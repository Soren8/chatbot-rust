use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Extensions, HeaderMap, Response, StatusCode},
};
use chatbot_core::{
    enc_key::EncryptionKey,
    history::{HistoryError, SetId, SetVersion},
    session,
};
use anyhow::Error;
use regex::Regex;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use crate::http_error::{map_response_build_err, HttpError};
use tracing::warn;

/// Appended to a root cause that does not already name the backend, so the
/// message says where the failure came from: "Connection refused by backend
/// LLM provider."
const BACKEND_CAUSE_SUFFIX: &str = " by backend LLM provider";

/// OS errno detail ("(os error 111)") never helps a user-facing message.
fn strip_os_error_detail(msg: &str) -> String {
    static OS_ERROR_NOISE: OnceLock<Regex> = OnceLock::new();
    let pattern = OS_ERROR_NOISE.get_or_init(|| Regex::new(r"\s*\(os error \d+\)").unwrap());
    pattern.replace_all(msg, "").into_owned()
}

/// Split a provider error into the parts the UI and the browser console need.
///
/// `visible` is one clean sentence: the specific root cause followed by the
/// backend name, always "backend LLM provider" — provider error causes must be
/// brand-free (OpenAI/xAI stay in server logs and the console detail only).
/// `detail` is the full anyhow chain for the browser console (surfaced via the
/// `[ConsoleError]` stream marker in `chat.js`).
pub fn provider_error_parts(err: &Error) -> (String, String) {
    let cause = strip_os_error_detail(&err.root_cause().to_string());
    let mut chars = cause.chars();
    let mut visible = match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => cause,
    };
    visible.push_str(BACKEND_CAUSE_SUFFIX);
    if !visible.ends_with('.') {
        visible.push('.');
    }
    let detail = format!("{err:#}").replace('\n', " ");
    (visible, detail)
}

/// Marker wrapping the full provider error detail on the SSE stream. `chat.js`
/// strips this from the visible text and sinks it to `console.error`.
pub const PROVIDER_ERROR_DETAIL_OPEN: &str = "[ConsoleError]";
pub const PROVIDER_ERROR_DETAIL_CLOSE: &str = "[/ConsoleError]";

pub const ENC_KEY_COOKIE_NAME: &str = "enc_key";

pub fn extract_enc_key(headers: &HeaderMap) -> Option<EncryptionKey> {
    headers
        .get("X-Enc-Key")
        .and_then(|value| value.to_str().ok())
        .and_then(EncryptionKey::from_header_value)
        .or_else(|| {
            extract_enc_key_cookie(
                headers
                    .get(header::COOKIE)
                    .and_then(|value| value.to_str().ok()),
            )
        })
}

pub fn extract_enc_key_cookie(cookie_header: Option<&str>) -> Option<EncryptionKey> {
    let header = cookie_header?;
    for part in header.split(';') {
        let part = part.trim();
        let Some(value) = part.strip_prefix(ENC_KEY_COOKIE_NAME) else {
            continue;
        };
        let Some(value) = value.strip_prefix('=') else {
            continue;
        };
        let decoded = urlencoding::decode(value).ok()?;
        return EncryptionKey::from_header_value(decoded.as_ref());
    }
    None
}

fn enc_cookie_secure_flag() -> &'static str {
    if chatbot_core::config::app_config().csrf {
        " Secure;"
    } else {
        ""
    }
}

pub fn build_enc_key_set_cookie(key: &str, max_age_secs: u64) -> String {
    let encoded = urlencoding::encode(key);
    format!(
        "{ENC_KEY_COOKIE_NAME}={encoded}; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age={max_age_secs}",
        secure = enc_cookie_secure_flag()
    )
}

pub fn build_enc_key_clear_cookie() -> String {
    format!(
        "{ENC_KEY_COOKIE_NAME}=; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age=0",
        secure = enc_cookie_secure_flag()
    )
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

pub fn service_error_message(resp: &session::ServiceResponse) -> String {
    serde_json::from_slice::<Value>(&resp.body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| String::from_utf8_lossy(&resp.body).into_owned())
}

/// Persist a /chat or /regenerate failure as a real history pair and return it
/// as a 200 text/plain assistant turn so the client can regenerate.
pub fn error_as_saved_chat_turn(
    session: &session::SessionContext,
    set_name: Option<&str>,
    user_message: &str,
    error_message: &str,
    encryption_key: Option<&EncryptionKey>,
    insertion_index: Option<usize>,
) -> Result<Response<Body>, HttpError> {
    let set = set_name.filter(|s| !s.trim().is_empty()).unwrap_or("default");
    let assistant = format!("[Error] {error_message}");
    warn!(
        error = error_message,
        user_chars = user_message.chars().count(),
        insertion_index,
        "saving /chat or /regenerate error as assistant turn"
    );
    if let Some(idx) = insertion_index {
        session::regenerate_finalize(
            session,
            set,
            user_message,
            &assistant,
            Some(idx),
            encryption_key,
        );
    } else {
        session::chat_finalize(session, set, user_message, &assistant, encryption_key);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Accel-Buffering", "no")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(assistant))
        .map_err(|err| map_response_build_err(err, "chat_utils::error_as_saved_chat_turn"))
}

/// Standard CAS conflict body for durable set mutations.
pub fn version_conflict_json(set_id: SetId, current_version: SetVersion) -> Value {
    json!({
        "error": "version_conflict",
        "set_id": set_id.to_string(),
        "current_version": current_version.get(),
        "message": "Set was modified; syncing latest version."
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

#[cfg(test)]
mod tests {
    use super::provider_error_parts;

    #[test]
    fn anonymous_cause_names_the_backend_without_errno_noise() {
        let err = anyhow::Error::from(std::io::Error::from_raw_os_error(111))
            .context("failed to send LLM request");
        let (visible, detail) = provider_error_parts(&err);
        assert_eq!(visible, "Connection refused by backend LLM provider.");
        assert!(
            detail.contains("failed to send LLM request") && detail.contains("os error 111"),
            "console detail keeps the full diagnostic chain: {detail}"
        );
    }

    #[test]
    fn http_status_cause_also_names_the_backend() {
        let err =
            anyhow::anyhow!("HTTP 429 Too Many Requests - Rate limit exceeded, quota reached");
        let (visible, _) = provider_error_parts(&err);
        assert_eq!(
            visible,
            "HTTP 429 Too Many Requests - Rate limit exceeded, quota reached by backend LLM provider."
        );
    }
}
