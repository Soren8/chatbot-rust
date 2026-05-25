use axum::{
    body::Body,
    http::{Method, Response, StatusCode},
    response::IntoResponse,
    Json,
};
use chatbot_core::persistence::PersistenceError;
use serde_json::Value;
use tracing::error;

pub fn ensure_method(actual: &Method, expected: Method) -> Result<(), (StatusCode, String)> {
    if *actual != expected {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            format!("Only {expected} allowed"),
        ));
    }

    Ok(())
}

pub fn ensure_post(actual: &Method) -> Result<(), (StatusCode, String)> {
    ensure_method(actual, Method::POST)
}

pub fn ensure_get(actual: &Method) -> Result<(), (StatusCode, String)> {
    ensure_method(actual, Method::GET)
}

pub fn persistence_error_to_http(err: PersistenceError) -> (StatusCode, String) {
    match err {
        PersistenceError::InvalidUsername => {
            (StatusCode::BAD_REQUEST, "invalid session".to_string())
        }
        PersistenceError::InvalidSetName => {
            (StatusCode::BAD_REQUEST, "invalid set name".to_string())
        }
        PersistenceError::MissingEncryptionKey => {
            (StatusCode::UNAUTHORIZED, "relogin required".to_string())
        }
        other => {
            error!(?other, "persistence failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence error".to_string(),
            )
        }
    }
}

pub fn json_response(status: StatusCode, payload: Value) -> Response<Body> {
    (status, Json(payload)).into_response()
}
