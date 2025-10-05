use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use serde::Deserialize;
use tracing::error;

#[derive(Deserialize, Default)]
struct SetNameRequest {
    #[serde(default)]
    set_name: Option<String>,
}

pub async fn handle_get_sets(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::GET {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only GET allowed".into()));
    }

    let (parts, _) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let py_response = bridge::get_sets(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "bridge error while handling /get_sets");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    crate::build_response(py_response)
}

pub async fn handle_create_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    handle_set_mutation(request, MutationKind::Create).await
}

pub async fn handle_delete_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    handle_set_mutation(request, MutationKind::Delete).await
}

pub async fn handle_load_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    handle_set_mutation(request, MutationKind::Load).await
}

enum MutationKind {
    Create,
    Delete,
    Load,
}

async fn handle_set_mutation(
    request: Request<Body>,
    kind: MutationKind,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

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
            error!(?err, "failed to validate CSRF token for set mutation");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
        error!(?err, "failed to read request body for set mutation");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for set mutation");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name = payload.set_name.as_deref();

    let py_response = match kind {
        MutationKind::Create => bridge::create_set(cookie_header.as_deref(), csrf_token, set_name),
        MutationKind::Delete => bridge::delete_set(cookie_header.as_deref(), csrf_token, set_name),
        MutationKind::Load => bridge::load_set(cookie_header.as_deref(), csrf_token, set_name),
    }
    .map_err(|err| {
        error!(?err, "bridge error while handling set mutation");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    crate::build_response(py_response)
}
