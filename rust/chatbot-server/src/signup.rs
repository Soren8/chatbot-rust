use std::collections::HashMap;

use axum::{
    body::{self, Body},
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::bridge;
use serde_urlencoded::from_bytes;
use tracing::error;

use crate::user_store::{normalise_username, CreateOutcome, UserStore, UserStoreError};

pub async fn handle_signup_post(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = body::to_bytes(body, 64 * 1024).await.map_err(|err| {
        error!(?err, "failed to read signup body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse signup form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");

    if username_raw.is_empty() || password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username and password required.".to_string(),
        ));
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
        Err(message) => {
            return Err((StatusCode::BAD_REQUEST, message));
        }
    };

    let hashed = hash(password, DEFAULT_COST).map_err(|err| {
        error!(?err, "failed to hash password");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user".to_string(),
        )
    })?;

    let mut store = UserStore::new().map_err(map_store_error)?;

    match store.create_user(&username, &hashed) {
        Ok(CreateOutcome::Created) => {}
        Ok(CreateOutcome::AlreadyExists) => {
            return Err((StatusCode::BAD_REQUEST, "User already exists.".to_string()));
        }
        Err(err) => {
            error!(?err, "failed to persist new user");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            ));
        }
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/login"))
        .body(Body::empty())
        .map_err(|err| {
            error!(?err, "failed to build redirect response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            )
        })
}

fn map_store_error(err: UserStoreError) -> (StatusCode, String) {
    error!(?err, "user store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to create user".to_string(),
    )
}
