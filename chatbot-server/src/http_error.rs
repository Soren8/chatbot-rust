use axum::{http::StatusCode, Json};
use chatbot_core::{
    history::HistoryError,
    session::{
        EncryptionKeyValidationError, PrepareHistoryError, PreparePolicyError,
        PrepareValidationError, SessionError, SessionOperationError,
    },
    user_store::UserStoreError,
};
use serde_json::{json, Value};
use tracing::{error, warn};

/// Axum `IntoResponse` tuple for consistent JSON error bodies.
pub type HttpError = (StatusCode, Json<Value>);

pub fn api_error(status: StatusCode, message: impl Into<String>) -> HttpError {
    let message = message.into();
    if status == StatusCode::BAD_REQUEST {
        warn!(status = 400, error = %message, "http 400");
    } else if status.is_server_error() {
        // 5xx api_error callers previously logged nothing (or debug-only),
        // leaving deterministic server failures invisible in production logs.
        error!(status = status.as_u16(), error = %message, "http 5xx");
    }
    (status, Json(json!({ "error": message })))
}

pub fn api_error_json(status: StatusCode, body: Value) -> HttpError {
    if status == StatusCode::BAD_REQUEST {
        warn!(status = 400, body = %body, "http 400");
    }
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

/// Map a typed encryption-key validation outcome to a JSON error.
///
/// The `UserStore` cause for `StoreUnavailable` is already logged at the
/// validation point in `chatbot_core::session`; this mapper adds no further
/// cause logging. The 500 branch records the error counter; response logging
/// belongs to the outer 5xx middleware.
pub fn map_encryption_key_validation_err(err: EncryptionKeyValidationError) -> HttpError {
    match err {
        EncryptionKeyValidationError::Missing => api_error(
            StatusCode::UNAUTHORIZED,
            "Encryption key required. Please unlock.",
        ),
        EncryptionKeyValidationError::Invalid => {
            api_error(StatusCode::UNAUTHORIZED, "Invalid encryption key.")
        }
        EncryptionKeyValidationError::StoreUnavailable => {
            crate::test_instrumentation::record_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal error while accessing user store" })),
            )
        }
    }
}

/// Map a pure prepare validation failure to a 400 JSON error.
///
/// The cause is already logged at the validation point in
/// `chatbot_core::session`; this mapper renders the response and logs the
/// raw 400 body. Handlers inspect `PrepareError` first: a validation failure
/// with a nonempty user message is saved as a 200 error turn instead, so
/// this mapper must not be invoked on that branch.
pub fn map_prepare_validation_err(err: &PrepareValidationError) -> HttpError {
    api_error_json(StatusCode::BAD_REQUEST, json!({ "error": err.message() }))
}

/// Map a prepare policy failure to its exact 429/403 JSON error.
///
/// This mapper adds no logging and records no error counter; policy
/// rejections are expected client-visible gates, not server failures.
pub fn map_prepare_policy_err(err: &PreparePolicyError) -> HttpError {
    match err {
        PreparePolicyError::Busy => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": err.message() })),
        ),
        PreparePolicyError::PremiumRequired => {
            (StatusCode::FORBIDDEN, Json(json!({ "error": err.message() })))
        }
    }
}

/// Map a typed prepare history failure to its exact JSON error.
///
/// Preserves the prepare-path bodies: `NotFound` stays a 400
/// "invalid set name" (unlike the general history 404), conflict carries
/// only `error` + `current_version`, and the 500 branch keeps the prepare
/// message with the error counter. The cause is already logged at the
/// prepare point in `chatbot_core::session`; 400s log the body here, and
/// 5xx response logging belongs to the outer middleware. Handlers inspect
/// `PrepareError` first: a 400 history failure with a nonempty user message
/// is saved as a 200 error turn instead, so this mapper must not be invoked
/// on that branch.
pub fn map_prepare_history_err(err: &PrepareHistoryError) -> HttpError {
    match err {
        PrepareHistoryError::Unauthorized => api_error(
            StatusCode::UNAUTHORIZED,
            "Encryption key required. Please unlock.",
        ),
        PrepareHistoryError::NotFound => api_error_json(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid set name" }),
        ),
        PrepareHistoryError::Conflict { current_version } => api_error_json(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "current_version": current_version.get(),
            }),
        ),
        PrepareHistoryError::InvalidInput(msg) => api_error_json(
            StatusCode::BAD_REQUEST,
            json!({ "error": msg }),
        ),
        PrepareHistoryError::Forbidden => api_error(StatusCode::FORBIDDEN, "forbidden"),
        PrepareHistoryError::Internal => {
            crate::test_instrumentation::record_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal error while accessing chat history" })),
            )
        }
    }
}

/// Map a typed session-operation failure to its exact JSON error.
///
/// 401s render their original strings with no logging or counter, the single
/// 400 renders via the raw-body 400 path (saved-turn handling stays in
/// chat/regenerate handlers), and 500s record the error counter once with
/// cause already logged in core. Response 5xx logging belongs to the outer
/// middleware.
pub fn map_session_operation_err(err: &SessionOperationError) -> HttpError {
    match err {
        SessionOperationError::MissingEncryptionKey => api_error(
            StatusCode::UNAUTHORIZED,
            "Encryption key required. Please unlock.",
        ),
        SessionOperationError::InvalidEncryptionKey => {
            api_error(StatusCode::UNAUTHORIZED, "Invalid encryption key.")
        }
        SessionOperationError::GuestCustomSetDenied => {
            api_error(StatusCode::UNAUTHORIZED, "Login required for custom sets")
        }
        SessionOperationError::AuthenticatedBootstrapMisuse => api_error_json(
            StatusCode::BAD_REQUEST,
            json!({ "error": err.message() }),
        ),
        SessionOperationError::UserStoreUnavailable => {
            crate::test_instrumentation::record_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal error while accessing user store" })),
            )
        }
        SessionOperationError::HistoryUnavailable => {
            crate::test_instrumentation::record_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal error while accessing chat history" })),
            )
        }
    }
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
                "message": "Set was modified; syncing latest version."
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
