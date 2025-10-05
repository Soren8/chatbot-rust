use std::collections::HashMap;

use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use serde_urlencoded::from_bytes;
use tracing::error;

use crate::user_store::{normalise_username, UserStore, UserStoreError};

const INVALID_CREDENTIALS: &str = "Invalid credentials";

pub async fn handle_login_post(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = body::to_bytes(body, 64 * 1024).await.map_err(|err| {
        error!(?err, "failed to read login body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse login form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");

    if username_raw.is_empty() || password.is_empty() {
        return invalid_credentials();
    }

    let csrf_valid =
        bridge::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token via python bridge");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(_) => return invalid_credentials(),
    };

    let store = UserStore::new().map_err(map_store_error)?;

    let valid = store
        .validate_user(&username, password)
        .map_err(map_store_error)?;

    if !valid {
        return invalid_credentials();
    }

    let encryption_key = store
        .derive_encryption_key(&username, password)
        .map_err(map_store_error)?;

    let py_response = bridge::finalize_login(cookie_header.as_deref(), &username, &encryption_key)
        .map_err(|err| {
            error!(?err, "failed to finalize login via python bridge");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    crate::build_response(py_response)
}

fn invalid_credentials() -> Result<Response<Body>, (StatusCode, String)> {
    Err((StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS.to_string()))
}

fn map_store_error(err: UserStoreError) -> (StatusCode, String) {
    error!(?err, "user store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to log in".to_string(),
    )
}
