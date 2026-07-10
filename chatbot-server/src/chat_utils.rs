use axum::{
    extract::ConnectInfo,
    http::{Extensions, HeaderMap, StatusCode},
};
use chatbot_core::{
    enc_key::EncryptionKey,
    history::{HistoryError, SetId, SetVersion},
    session,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

pub fn extract_enc_key(headers: &HeaderMap) -> Option<EncryptionKey> {
    headers
        .get("X-Enc-Key")
        .and_then(|value| value.to_str().ok())
        .and_then(EncryptionKey::from_header_value)
}

pub fn get_ip(headers: &HeaderMap, extensions: &Extensions) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

pub struct ChatLockGuard {
    session_id: String,
    released: bool,
}

impl ChatLockGuard {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            released: false,
        }
    }

    pub fn mark_released(&mut self) {
        self.released = true;
    }

    pub fn release_if_needed(&mut self) {
        if !self.released {
            session::release_session_lock(&self.session_id);
            self.released = true;
        }
    }
}

impl Drop for ChatLockGuard {
    fn drop(&mut self) {
        self.release_if_needed();
    }
}

/// Standard CAS conflict body for durable set mutations.
pub fn version_conflict_json(set_id: SetId, current_version: SetVersion) -> Value {
    json!({
        "error": "version_conflict",
        "set_id": set_id.to_string(),
        "current_version": current_version.get(),
        "message": "Set was modified; reload and retry."
    })
}

pub fn history_error_to_http(err: HistoryError) -> (StatusCode, String) {
    match err {
        HistoryError::NotFound => (StatusCode::NOT_FOUND, "set not found".into()),
        HistoryError::Conflict { current_version } => (
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "current_version": current_version.get(),
                "message": "Set was modified; reload and retry."
            })
            .to_string(),
        ),
        HistoryError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
        HistoryError::DecryptFailed | HistoryError::MissingKey => (
            StatusCode::UNAUTHORIZED,
            "Encryption key required or invalid. Please unlock.".into(),
        ),
        HistoryError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.into()),
        HistoryError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal history error".into(),
        ),
    }
}

/// Map history errors for JSON endpoints; CONFLICT returns structured body via the pair.
pub fn history_conflict_or_err(
    err: HistoryError,
    set_id: SetId,
) -> Result<(StatusCode, Value), (StatusCode, String)> {
    match err {
        HistoryError::Conflict { current_version } => Ok((
            StatusCode::CONFLICT,
            version_conflict_json(set_id, current_version),
        )),
        other => Err(history_error_to_http(other)),
    }
}
