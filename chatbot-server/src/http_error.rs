use axum::{http::StatusCode, Json};
use chatbot_core::{
    history::HistoryError,
    session::SessionError,
    user_store::UserStoreError,
};
use serde_json::{json, Value};
use tracing::{error, warn};

/// Axum `IntoResponse` tuple for consistent JSON error bodies.
pub type HttpError = (StatusCode, Json<Value>);

pub fn api_error(status: StatusCode, message: impl Into<String>) -> HttpError {
    (status, Json(json!({ "error": message.into() })))
}

pub fn api_error_json(status: StatusCode, body: Value) -> HttpError {
    (status, Json(body))
}

/// Log an unexpected failure with route context, then return a safe JSON error.
pub fn log_and_api_error(
    status: StatusCode,
    public_message: impl Into<String>,
    context: &'static str,
    err: impl std::fmt::Debug,
) -> HttpError {
    error!(?err, context, "request failed");
    api_error(status, public_message)
}

pub fn map_session_err(err: SessionError, context: &'static str) -> HttpError {
    match err {
        SessionError::InvalidSession => {
            warn!(context, "session invalid or expired");
            api_error(StatusCode::UNAUTHORIZED, "session expired")
        }
    }
}

pub fn map_user_store_err(
    err: UserStoreError,
    context: &'static str,
    public_message: &'static str,
) -> HttpError {
    error!(?err, context, "user store operation failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, public_message)
}

pub fn map_body_read_err(err: impl std::fmt::Debug, context: &'static str) -> HttpError {
    error!(?err, context, "failed to read request body");
    api_error(StatusCode::BAD_REQUEST, "Invalid request body")
}

pub fn map_json_parse_err(err: impl std::fmt::Debug, context: &'static str) -> HttpError {
    error!(?err, context, "invalid JSON payload");
    api_error(StatusCode::BAD_REQUEST, "Invalid JSON payload")
}

pub fn map_form_parse_err(err: impl std::fmt::Debug, context: &'static str) -> HttpError {
    error!(?err, context, "invalid form payload");
    api_error(StatusCode::BAD_REQUEST, "Invalid form payload")
}

pub fn map_response_build_err(err: impl std::fmt::Debug, context: &'static str) -> HttpError {
    error!(?err, context, "failed to build HTTP response");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "response build error")
}

pub fn map_serialization_err(err: impl std::fmt::Debug, context: &'static str) -> HttpError {
    error!(?err, context, "response serialization failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "response serialization failed")
}

pub fn map_history_err(err: HistoryError, context: &'static str) -> HttpError {
    match err {
        HistoryError::NotFound => api_error(StatusCode::NOT_FOUND, "set not found"),
        HistoryError::Conflict { current_version } => api_error_json(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "current_version": current_version.get(),
                "message": "Set was modified; reload and retry."
            }),
        ),
        HistoryError::Forbidden => api_error(StatusCode::FORBIDDEN, "forbidden"),
        HistoryError::DecryptFailed | HistoryError::MissingKey => {
            warn!(context, ?err, "encryption key required or invalid");
            api_error(
                StatusCode::UNAUTHORIZED,
                "Encryption key required or invalid. Please unlock.",
            )
        }
        HistoryError::InvalidInput(msg) => api_error(StatusCode::BAD_REQUEST, msg),
        HistoryError::Internal => {
            error!(context, ?err, "internal history error");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal history error")
        }
    }
}