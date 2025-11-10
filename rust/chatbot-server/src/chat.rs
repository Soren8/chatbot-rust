use std::convert::Infallible;

use anyhow::Result;
use async_stream::stream;
use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use bytes::Bytes;
use chatbot_core::{
    bridge::{self, chat_finalize, chat_prepare, ChatRequestData},
    chat::{self, ChatMessageRole, strip_think_tags},
    config::get_provider_config,
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};

use crate::chat_utils::ChatLockGuard;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::OpenAiProvider;

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

    let provider_config = match get_provider_config(if selected_model.is_empty() {
        None
    } else {
        Some(selected_model.as_str())
    }) {
        Some(config) => config,
        None => {
            let model = if selected_model.is_empty() {
                "<default>"
            } else {
                selected_model.as_str()
            };
            error!(model = %model, "requested model not found");
            return Err((
                StatusCode::BAD_REQUEST,
                "requested model not found".to_string(),
            ));
        }
    };

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

    let context = prepare.context.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing chat context".to_string(),
        )
    })?;

    let lock_guard = Arc::new(Mutex::new(ChatLockGuard::new(context.session_id.clone())));

    let provider = OpenAiProvider::new(&context.provider).map_err(|err| {
        error!(?err, "failed to construct OpenAI provider");
        lock_guard.lock().unwrap().release_if_needed();
        (StatusCode::BAD_GATEWAY, "provider setup failed".to_string())
    })?;

    let prepared = chat::prepare_chat_messages(&context, payload.message.as_str());

    if prepared.was_truncated() {
        debug!(
            original_history_tokens = prepared.original_history_tokens,
            truncated_history_tokens = prepared.truncated_history_tokens,
            "chat history token metrics"
        );
    }

    let messages = prepared
        .messages
        .iter()
        .map(|message| match message.role {
            ChatMessageRole::System => {
                ChatMessagePayload::system(message.content.clone())
            }
            ChatMessageRole::User => ChatMessagePayload::user(message.content.clone()),
            ChatMessageRole::Assistant => {
                ChatMessagePayload::assistant(message.content.clone())
            }
        })
        .collect::<Vec<_>>();

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

    let response = Response::builder()
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
