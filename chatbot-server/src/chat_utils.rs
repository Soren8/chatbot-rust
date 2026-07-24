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
use std::sync::Arc;

use crate::http_error::HttpError;

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

/// Ensures session lock + history finalize run even when the client aborts
/// mid-stream (browser Stop button / dropped response body).
///
/// Without this, cancel leaves the generate-lock held and/or omits the chat
/// pair from durable history, so a subsequent edit/regenerate fails with 4xx.
pub struct StreamCompletionGuard {
    lock: Arc<std::sync::Mutex<ChatLockGuard>>,
    /// Set once lock is released and (if applicable) history is finalized.
    settled: bool,
    /// Provider stream error: unlock only, do not persist tainted text.
    skip_persist: bool,
    on_persist: Option<Box<dyn FnOnce(&str) -> Result<Vec<String>, ()> + Send>>,
    response_text: String,
    save_thoughts: bool,
}

impl StreamCompletionGuard {
    pub fn new(
        lock: Arc<std::sync::Mutex<ChatLockGuard>>,
        save_thoughts: bool,
        on_persist: impl FnOnce(&str) -> Result<Vec<String>, ()> + Send + 'static,
    ) -> Self {
        Self {
            lock,
            settled: false,
            skip_persist: false,
            on_persist: Some(Box::new(on_persist)),
            response_text: String::new(),
            save_thoughts,
        }
    }

    pub fn push_chunk(&mut self, chunk: &str) {
        self.response_text.push_str(chunk);
    }

    pub fn mark_provider_error(&mut self) {
        self.skip_persist = true;
    }

    fn final_text(&self) -> String {
        if self.save_thoughts {
            self.response_text.clone()
        } else {
            chatbot_core::chat::strip_think_tags(&self.response_text)
        }
    }

    /// Normal completion (stream finished without provider error).
    pub fn complete_success(&mut self) -> Vec<String> {
        if self.settled {
            return Vec::new();
        }
        self.settled = true;
        if self.skip_persist {
            self.lock.lock().unwrap().release_if_needed();
            return Vec::new();
        }
        let text = self.final_text();
        match self.on_persist.take() {
            Some(persist) => match persist(&text) {
                Ok(extras) => {
                    // finalize unlocks the session entry; prevent double-unlock on Drop.
                    self.lock.lock().unwrap().mark_released();
                    extras
                }
                Err(()) => {
                    self.lock.lock().unwrap().release_if_needed();
                    vec!["\n[Error] Failed to persist chat history".to_string()]
                }
            },
            None => {
                self.lock.lock().unwrap().release_if_needed();
                Vec::new()
            }
        }
    }

    /// Provider error path: unlock without writing history.
    pub fn complete_without_persist(&mut self) {
        if self.settled {
            return;
        }
        self.settled = true;
        self.skip_persist = true;
        self.on_persist.take();
        self.lock.lock().unwrap().release_if_needed();
    }
}

impl Drop for StreamCompletionGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Client cancelled / body dropped before the stream loop finished.
        // Persist whatever partial assistant text we have so Stop → Edit works
        // (pair exists for regenerate) and always release the generate-lock.
        if self.skip_persist {
            self.complete_without_persist();
        } else {
            let _ = self.complete_success();
        }
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

pub fn history_error_to_http(err: HistoryError) -> HttpError {
    crate::http_error::map_history_err(err, "history")
}

/// Map history errors for JSON endpoints; CONFLICT returns structured body via the pair.
pub fn history_conflict_or_err(
    err: HistoryError,
    set_id: SetId,
) -> Result<(StatusCode, Value), HttpError> {
    match err {
        HistoryError::Conflict { current_version } => Ok((
            StatusCode::CONFLICT,
            version_conflict_json(set_id, current_version),
        )),
        other => Err(history_error_to_http(other)),
    }
}
