use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize, Default)]
struct ResetChatRequest {
    #[serde(default)]
    set_name: Option<String>,
}

pub async fn handle_reset_chat(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

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

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let csrf_valid =
        session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token for reset_chat");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid or missing CSRF token".to_string()));
    }

    let session_context = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to resolve session context for reset_chat");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

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

        let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

        persistence
            .store_history(
                username,
                &set_name,
                &[],
                EncryptionMode::Fernet(key.as_slice()),
            )
            .map_err(persistence_error_to_http)?;
    }

    build_json_response(
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Chat history has been reset.",
            "set_name": set_name
        }),
    )
}

fn build_json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, (StatusCode, String)> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .map_err(|err| {
            error!(?err, "failed to build reset_chat response body");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}

fn persistence_error_to_http(err: PersistenceError) -> (StatusCode, String) {
    match err {
        PersistenceError::MissingEncryptionKey => {
            (StatusCode::UNAUTHORIZED, "relogin required".to_string())
        }
        PersistenceError::InvalidSetName => {
            (StatusCode::BAD_REQUEST, "invalid set name".to_string())
        }
        PersistenceError::InvalidUsername => {
            (StatusCode::BAD_REQUEST, "invalid session".to_string())
        }
        other => {
            error!(?other, "persistence error during reset_chat");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence error".to_string(),
            )
        }
    }
}
