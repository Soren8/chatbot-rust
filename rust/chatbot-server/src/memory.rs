use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use serde::Deserialize;
use tracing::error;

#[derive(Deserialize, Default)]
struct UpdateMemoryRequest {
    #[serde(default)]
    memory: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
}

#[derive(Deserialize, Default)]
struct UpdateSystemPromptRequest {
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
}

#[derive(Deserialize, Default)]
struct DeleteMessageRequest {
    #[serde(default)]
    user_message: Option<String>,
    #[serde(default)]
    ai_message: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
}

pub async fn handle_update_memory(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /update_memory body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        UpdateMemoryRequest::default()
    } else {
        serde_json::from_slice::<UpdateMemoryRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /update_memory");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let py_response = bridge::update_memory(
        cookie_header.as_deref(),
        csrf_token,
        payload.memory.as_deref(),
        payload.set_name.as_deref(),
        payload.encrypted,
    )
    .map_err(|err| {
        error!(?err, "bridge error while updating memory");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    crate::build_response(py_response)
}

pub async fn handle_update_system_prompt(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /update_system_prompt body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        UpdateSystemPromptRequest::default()
    } else {
        serde_json::from_slice::<UpdateSystemPromptRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /update_system_prompt");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let py_response = bridge::update_system_prompt(
        cookie_header.as_deref(),
        csrf_token,
        payload.system_prompt.as_deref(),
        payload.set_name.as_deref(),
        payload.encrypted,
    )
    .map_err(|err| {
        error!(?err, "bridge error while updating system prompt");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    crate::build_response(py_response)
}

pub async fn handle_delete_message(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /delete_message body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        DeleteMessageRequest::default()
    } else {
        serde_json::from_slice::<DeleteMessageRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /delete_message");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let py_response = bridge::delete_message(
        cookie_header.as_deref(),
        csrf_token,
        payload.user_message.as_deref(),
        payload.ai_message.as_deref(),
        payload.set_name.as_deref(),
    )
    .map_err(|err| {
        error!(?err, "bridge error while deleting chat message");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    crate::build_response(py_response)
}

fn ensure_post(request: &Request<Body>) -> Result<(), (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }
    Ok(())
}

fn extract_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned())
}

fn extract_csrf(headers: &axum::http::HeaderMap) -> Result<&str, (StatusCode, String)> {
    headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing CSRF token".to_string()))
}

fn validate_csrf(
    cookie_header: Option<&str>,
    csrf_token: &str,
) -> Result<(), (StatusCode, String)> {
    let valid = bridge::validate_csrf_token(cookie_header, csrf_token).map_err(|err| {
        error!(?err, "failed to validate CSRF token for memory endpoint");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    if !valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    Ok(())
}
