use std::convert::Infallible;

use anyhow::Result;
use async_stream::stream;
use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use bytes::Bytes;
use chatbot_core::bridge::{
    self, chat_finalize, chat_prepare, chat_release_lock, get_provider_config, ChatRequestData,
};
use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, error, info};

use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::OpenAiProvider;

const SYSTEM_PROMPT_BUFFER: f64 = 0.2;
const DEFAULT_CONTEXT_SIZE: usize = 8_192;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<think>.*?</think>").expect("valid think regex"));

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
}

struct ChatLockGuard {
    session_id: String,
    released: bool,
}

impl ChatLockGuard {
    fn new(session_id: String) -> Self {
        Self {
            session_id,
            released: false,
        }
    }

    fn mark_released(&mut self) {
        self.released = true;
    }

    fn release_if_needed(&mut self) {
        if !self.released {
            if let Err(err) = chat_release_lock(&self.session_id) {
                error!(?err, "failed to release chat lock");
            }
            self.released = true;
        }
    }
}

impl Drop for ChatLockGuard {
    fn drop(&mut self) {
        self.release_if_needed();
    }
}

pub async fn handle_chat(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let uri = parts.uri;
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 2 * 1024 * 1024).await.map_err(|err| {
        error!(?err, "failed to read chat request body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: ChatRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid chat request payload");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

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
            error!(?err, "failed to validate CSRF token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
    }

    let mut selected_model = payload.model_name.clone().unwrap_or_default();

    let provider_config = get_provider_config(if selected_model.is_empty() {
        None
    } else {
        Some(selected_model.as_str())
    })
    .map_err(|err| {
        error!(?err, "failed to load provider config");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "requested model not found".to_string(),
        )
    })?;

    if selected_model.is_empty() {
        selected_model = provider_config.provider_name.clone();
    }

    if provider_config.provider_type.to_lowercase() != "openai" {
        info!(model = %selected_model, "deferring chat request to python bridge");
        let header_pairs = headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_owned()))
            })
            .collect::<Vec<_>>();
        let py_response = bridge::proxy_request(
            "POST",
            "/chat",
            uri.query(),
            &header_pairs,
            cookie_header.as_deref(),
            Some(&body_bytes),
        )
        .map_err(|err| {
            error!(?err, "python bridge error for /chat fallback");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;
        return crate::build_response(py_response);
    }

    let request_data = ChatRequestData {
        message: payload.message.as_str(),
        system_prompt: payload.system_prompt.as_deref(),
        set_name: payload.set_name.as_deref(),
        model_name: Some(selected_model.as_str()),
        encrypted: payload.encrypted.unwrap_or(false),
    };

    let prepare = chat_prepare(cookie_header.as_deref(), &request_data).map_err(|err| {
        error!(?err, "chat_prepare bridge call failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    if let Some(py_response) = prepare.error {
        return crate::build_response(py_response);
    }

    let mut context = prepare.context.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing chat context".to_string(),
        )
    })?;

    let lock_guard = Arc::new(Mutex::new(ChatLockGuard::new(
        context.session_id.clone(),
    )));

    let provider = OpenAiProvider::new(&context.provider).map_err(|err| {
        error!(?err, "failed to construct OpenAI provider");
        lock_guard.lock().unwrap().release_if_needed();
        (StatusCode::BAD_GATEWAY, "provider setup failed".to_string())
    })?;

    let context_size = context
        .provider
        .context_size
        .unwrap_or(DEFAULT_CONTEXT_SIZE as u32) as usize;
    let available_tokens = calculate_available_history_tokens(
        context_size,
        &context.system_prompt,
        &context.memory_text,
    );
    let truncated_history = truncate_history(&context.history, available_tokens);

    let mut messages = Vec::new();
    messages.push(ChatMessagePayload::system(context.system_prompt.clone()));

    if !context.memory_text.trim().is_empty() {
        let snippet = if context.memory_text.len() > 2000 {
            context.memory_text[..2000].to_string()
        } else {
            context.memory_text.clone()
        };
        messages.push(ChatMessagePayload::system(format!("Memory:\n{}", snippet)));
    }

    for (user, assistant) in truncated_history.iter() {
        messages.push(ChatMessagePayload::user(user.clone()));
        if !assistant.is_empty() {
            messages.push(ChatMessagePayload::assistant(assistant.clone()));
        }
    }

    messages.push(ChatMessagePayload::user(payload.message.clone()));

    let cookie_for_finalize = cookie_header.clone();
    let session_id = context.session_id.clone();
    let set_name = context.set_name.clone();
    let user_message = payload.message.clone();
    let encryption_key = context
        .encryption_key
        .as_ref()
        .map(|bytes| bytes.as_slice())
        .map(|slice| slice.to_vec());

    let mut provider_stream = match provider.stream_chat(messages) {
        Ok(stream) => stream,
        Err(err) => {
            error!(?err, "provider stream setup failed");
            lock_guard.lock().unwrap().release_if_needed();
            return Err((
                StatusCode::BAD_GATEWAY,
                "provider request failed".to_string(),
            ));
        }
    };

    let stream_lock = lock_guard.clone();

    let stream = stream! {
        let mut response_text = String::new();
        let mut encountered_error = false;

        while let Some(item) = provider_stream.next().await {
            match item {
                Ok(chunk) => {
                    response_text.push_str(&chunk);
                    yield Bytes::from(chunk.into_bytes());
                }
                Err(err) => {
                    encountered_error = true;
                    error!(?err, "error while reading provider stream");
                    let msg = format!("\n[Error] {err}\n");
                    response_text.push_str(&msg);
                    yield Bytes::from(msg.into_bytes());
                    break;
                }
            }
        }

        let clean_response = strip_think_tags(&response_text);
        match finalize_chat(
            cookie_for_finalize.as_deref(),
            &session_id,
            &set_name,
            &user_message,
            &clean_response,
            encryption_key.as_deref(),
        ) {
            Ok(extra_chunks) => {
                stream_lock.lock().unwrap().mark_released();
                for chunk in extra_chunks {
                    yield Bytes::from(chunk.into_bytes());
                }
            }
            Err(err) => {
                error!(?err, "chat_finalize failed");
                stream_lock.lock().unwrap().release_if_needed();
                if !encountered_error {
                    let msg = "\n[Error] Failed to persist chat history".to_string();
                    yield Bytes::from(msg.into_bytes());
                }
            }
        }
    };

    let body_stream = stream.map(|bytes| Ok::<Bytes, Infallible>(bytes));

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Accel-Buffering", "no")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(body_stream))
        .map_err(|err| {
            error!(?err, "failed to build chat response");
            lock_guard.lock().unwrap().release_if_needed();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })?;

    debug!("/chat request handled via Rust path");
    Ok(response)
}

fn finalize_chat(
    cookie_header: Option<&str>,
    session_id: &str,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&[u8]>,
) -> Result<Vec<String>> {
    chat_finalize(
        cookie_header,
        session_id,
        set_name,
        user_message,
        assistant_response,
        encryption_key,
    )
    .map_err(|err| err.into())
}

fn calculate_available_history_tokens(
    context_size: usize,
    system_prompt: &str,
    memory_text: &str,
) -> usize {
    let system_tokens = system_prompt.len() / 4;
    let memory_tokens = memory_text.len() / 4;
    let reserved =
        system_tokens + memory_tokens + ((context_size as f64 * SYSTEM_PROMPT_BUFFER) as usize);
    context_size.saturating_sub(reserved)
}

fn truncate_history(
    history: &[(String, String)],
    available_tokens: usize,
) -> Vec<(String, String)> {
    let mut truncated = Vec::new();
    let mut total_tokens = 0usize;

    for (user, assistant) in history.iter().rev() {
        let user_tokens = user.len() / 4;
        let assistant_tokens = assistant.len() / 4;
        let combined = user_tokens + assistant_tokens;

        if total_tokens + combined > available_tokens {
            let remaining = available_tokens.saturating_sub(total_tokens);
            if remaining > 100 {
                let limit = remaining * 2;
                let user_part = user.chars().take(limit).collect::<String>();
                let assistant_part = assistant.chars().take(limit).collect::<String>();
                truncated.push((user_part, assistant_part));
            }
            break;
        }

        truncated.push((user.clone(), assistant.clone()));
        total_tokens += combined;
    }

    truncated.reverse();
    truncated
}

fn strip_think_tags(content: &str) -> String {
    THINK_REGEX.replace_all(content, "").into_owned()
}
