use axum::{
    body::{self, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use tracing::{debug, error};

const MAX_BODY_BYTES: usize = 512 * 1024;

pub async fn handle_tts(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing CSRF token".to_string()))?;

    let csrf_valid =
        bridge::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token for /tts");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let body_bytes = body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|err| {
        error!(?err, "failed to read TTS request body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let body_slice = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.as_ref())
    };

    let py_response = bridge::generate_tts(
        cookie_header.as_deref(),
        csrf_token,
        content_type.as_deref(),
        body_slice,
    )
    .map_err(|err| {
        error!(?err, "python bridge error generating TTS audio");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    debug!("/tts request handled via Python bridge");
    crate::build_response(py_response)
}
