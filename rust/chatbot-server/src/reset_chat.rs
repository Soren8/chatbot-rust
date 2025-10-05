use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use chatbot_core::bridge::reset_chat as bridge_reset_chat;
use serde::Deserialize;
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

    let csrf_token =
        csrf_token.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing CSRF token".to_string()))?;

    let csrf_valid =
        bridge::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token for reset_chat");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    let py_response = bridge_reset_chat(cookie_header.as_deref(), payload.set_name.as_deref())
        .map_err(|err| {
            error!(?err, "reset_chat bridge error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    crate::build_response(py_response)
}
