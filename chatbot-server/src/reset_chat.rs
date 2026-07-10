use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    history::{HistoryError, HistoryService},
    persistence::{DataPersistence, PersistenceError},
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
        return Err((StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token".to_string()));
    }

    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

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

    if let Some(username) = session_context.username.as_deref() {
        if let Err(response) =
            session::validate_encryption_key_for_user(username, encryption_key.as_ref())
        {
            return build_service_response(response);
        }
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history = HistoryService::global().map_err(history_error_to_http)?;
        let snap = match history.find_by_display_name(username, &set_name, key) {
            Ok(Some(s)) => s,
            Ok(None) if set_name == "default" => history
                .ensure_default_set(username, key)
                .map_err(history_error_to_http)?,
            Ok(None) => {
                return Err((StatusCode::BAD_REQUEST, "set not found".to_string()));
            }
            Err(err) => return Err(history_error_to_http(err)),
        };
        let version = history
            .reset_history(username, snap.set_id, snap.version, key)
            .map_err(history_error_to_http)?;

        if let Err(response) = session::set_session_history_for_request(
            &session_context.session_id,
            Some(username),
            Some(snap.set_id),
            Vec::new(),
            encryption_key.as_ref(),
        ) {
            return build_service_response(response);
        }

        return build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Chat history has been reset.",
                "set_name": set_name,
                "set_id": snap.set_id.to_string(),
                "version": version.get(),
            }),
        );
    }

    session::update_session_history(&session_context.session_id, &[]);
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

fn build_service_response(
    response: session::ServiceResponse,
) -> Result<Response<Body>, (StatusCode, String)> {
    crate::build_response(response).map_err(|(status, message)| (status, message))
}

fn history_error_to_http(err: HistoryError) -> (StatusCode, String) {
    match err {
        HistoryError::MissingKey | HistoryError::DecryptFailed => (
            StatusCode::UNAUTHORIZED,
            "Encryption key required. Please unlock.".to_string(),
        ),
        HistoryError::NotFound => (StatusCode::NOT_FOUND, "set not found".to_string()),
        HistoryError::Conflict { current_version } => (
            StatusCode::CONFLICT,
            format!("version_conflict:{}", current_version.get()),
        ),
        HistoryError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.to_string()),
        HistoryError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
        HistoryError::Internal => {
            error!("internal history error during reset_chat");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "history store error".to_string(),
            )
        }
    }
}
