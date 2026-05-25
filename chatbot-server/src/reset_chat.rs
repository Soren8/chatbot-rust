use axum::{
    body,
    body::Body,
    http::{Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{auth::Session as AuthSession, responses};

#[derive(Deserialize, Default)]
struct ResetChatRequest {
    #[serde(default)]
    set_name: Option<String>,
}

pub async fn handle_reset_chat(
    AuthSession(session_context): AuthSession,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
        error!(?err, "failed to read reset_chat body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: ResetChatRequest = if body_bytes.is_empty() {
        ResetChatRequest::default()
    } else {
        serde_json::from_slice(&body_bytes).map_err(|err| {
            error!(?err, "invalid reset_chat payload");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref()).map_err(
        |err| match err {
            PersistenceError::InvalidSetName => {
                (StatusCode::BAD_REQUEST, "invalid set name".to_string())
            }
            other => {
                error!(?other, "failed to normalise set name");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid request".to_string(),
                )
            }
        },
    )?;

    session::update_session_history(&session_context.session_id, &[]);

    if let Some(username) = session_context.username.as_deref() {
        let key = session_context
            .encryption_key
            .as_ref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "relogin required".to_string()))?;

        let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;

        persistence
            .store_history(
                username,
                &set_name,
                &[],
                EncryptionMode::Fernet(key.as_slice()),
            )
            .map_err(responses::persistence_error_to_http)?;
    }

    Ok(responses::json_response(
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Chat history has been reset.",
            "set_name": set_name
        }),
    ))
}
