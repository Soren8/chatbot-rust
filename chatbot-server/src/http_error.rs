use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

/// Axum `IntoResponse` tuple for consistent JSON error bodies.
pub type HttpError = (StatusCode, Json<Value>);

pub fn api_error(status: StatusCode, message: impl Into<String>) -> HttpError {
    (status, Json(json!({ "error": message.into() })))
}

pub fn api_error_json(status: StatusCode, body: Value) -> HttpError {
    (status, Json(body))
}