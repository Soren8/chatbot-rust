use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_stream::stream;
use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use bytes::Bytes;
use chatbot_core::{
    chat::{self, strip_think_tags, ChatMessageRole},
    config::{app_config, get_provider_config},
    session::{self, RegenerateRequestData, SessionContext},
};
use futures_util::StreamExt;
use serde::Deserialize;
use tracing::{debug, error};

use crate::chat_utils::ChatLockGuard;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::OpenAiProvider;
use crate::providers::xai::XaiProvider;

#[derive(Deserialize)]
struct RegenerateRequest {
    message: String,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    pair_index: Option<i32>,
    #[serde(default)]
    save_thoughts: Option<bool>,
    #[serde(default)]
    send_thoughts: Option<bool>,
}

pub async fn handle_regenerate(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 2 * 1024 * 1024).await.map_err(|err| {
        error!(?err, "failed to read regenerate request body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: RegenerateRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid regenerate request payload");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let csrf_valid =
        session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token".to_string()));
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

    let provider_type = provider_config.provider_type.to_lowercase();
    if provider_type != "openai" && provider_type != "ollama" && provider_type != "xai" {
        error!(
            model = %selected_model,
            provider_type = %provider_type,
            "unsupported provider type for regenerate"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported provider type".to_string(),
        ));
    }

    let session_context = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to resolve session context");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let app_config = app_config();
    let save_thoughts = payload.save_thoughts.unwrap_or(app_config.save_thoughts);
    let send_thoughts = payload.send_thoughts.unwrap_or(app_config.send_thoughts);

    let request_data = RegenerateRequestData {
        message: payload.message.as_str(),
        system_prompt: payload.system_prompt.as_deref(),
        set_name: payload.set_name.as_deref(),
        model_name: Some(selected_model.as_str()),
        encrypted: payload.encrypted.unwrap_or(false),
        pair_index: payload.pair_index,
        send_thoughts,
    };

    let prepare = session::regenerate_prepare(&session_context, &request_data, &provider_config);

    if let Some(py_response) = prepare.error {
        return crate::build_response(py_response);
    }

    let context = prepare.context.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing chat context".to_string(),
        )
    })?;

    let insertion_index = prepare.insertion_index;

    let lock_guard = Arc::new(Mutex::new(ChatLockGuard::new(context.session_id.clone())));

    enum ProviderKind {
        OpenAi(OpenAiProvider),
        Ollama(OllamaProvider),
        Xai(XaiProvider),
    }

    let provider_kind = match provider_type.as_str() {
        "openai" => OpenAiProvider::new(&context.provider)
            .map(ProviderKind::OpenAi)
            .map_err(|err| {
                error!(?err, "failed to construct OpenAI provider");
                lock_guard.lock().unwrap().release_if_needed();
                (StatusCode::BAD_GATEWAY, "provider setup failed".to_string())
            })?,
        "ollama" => OllamaProvider::new(&context.provider)
            .map(ProviderKind::Ollama)
            .map_err(|err| {
                error!(?err, "failed to construct Ollama provider");
                lock_guard.lock().unwrap().release_if_needed();
                (StatusCode::BAD_GATEWAY, "provider setup failed".to_string())
            })?,
        "xai" => XaiProvider::new(&context.provider)
            .map(ProviderKind::Xai)
            .map_err(|err| {
                error!(?err, "failed to construct XAI provider");
                lock_guard.lock().unwrap().release_if_needed();
                (StatusCode::BAD_GATEWAY, "provider setup failed".to_string())
            })?,
        _ => unreachable!("provider_type should be filtered earlier"),
    };

    let prepared = chat::prepare_chat_messages(&context, payload.message.as_str());

    if prepared.was_truncated() {
        debug!(
            original_history_tokens = prepared.original_history_tokens,
            truncated_history_tokens = prepared.truncated_history_tokens,
            "regenerate history token metrics"
        );
    }

    let messages = prepared
        .messages
        .iter()
        .map(|message| match message.role {
            ChatMessageRole::System => ChatMessagePayload::system(message.content.clone()),
            ChatMessageRole::User => ChatMessagePayload::user(message.content.clone()),
            ChatMessageRole::Assistant => ChatMessagePayload::assistant(message.content.clone()),
        })
        .collect::<Vec<_>>();

    let session_context_for_finalize = session_context.clone();
    let set_name = context.set_name.clone();
    let user_message = payload.message.clone();

    let mut provider_stream = match provider_kind {
        ProviderKind::OpenAi(provider) => match provider.stream_chat(messages.clone()) {
            Ok(stream) => stream,
            Err(err) => {
                error!(?err, "provider stream setup failed");
                lock_guard.lock().unwrap().release_if_needed();
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "provider request failed".to_string(),
                ));
            }
        },
        ProviderKind::Ollama(provider) => {
            let request = provider.build_request(&context, &prepared, payload.message.as_str());
            match provider.stream_chat(request) {
                Ok(stream) => stream,
                Err(err) => {
                    error!(?err, "provider stream setup failed");
                    lock_guard.lock().unwrap().release_if_needed();
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        "provider request failed".to_string(),
                    ));
                }
            }
        },
        ProviderKind::Xai(provider) => match provider.stream_chat(messages.clone()) {
            Ok(stream) => stream,
            Err(err) => {
                error!(?err, "provider stream setup failed");
                lock_guard.lock().unwrap().release_if_needed();
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "provider request failed".to_string(),
                ));
            }
        },
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
                    error!(?err, "error while reading provider stream (regenerate)");
                    let msg = format!("\n[Error] {err}\n");
                    response_text.push_str(&msg);
                    yield Bytes::from(msg.into_bytes());
                    break;
                }
            }
        }

        let clean_response = strip_think_tags(&response_text);
        let final_response = if save_thoughts {
            &response_text
        } else {
            &clean_response
        };

        match regenerate_finalize(
            &session_context_for_finalize,
            &set_name,
            &user_message,
            final_response,
            insertion_index,
        ) {
            Ok(extra_chunks) => {
                stream_lock.lock().unwrap().mark_released();
                for chunk in extra_chunks {
                    yield Bytes::from(chunk.into_bytes());
                }
            }
            Err(err) => {
                error!(?err, "regenerate_finalize failed");
                stream_lock.lock().unwrap().release_if_needed();
                if !encountered_error {
                    let msg = "\n[Error] Failed to persist regenerated chat history".to_string();
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
            error!(?err, "failed to build regenerate response");
            lock_guard.lock().unwrap().release_if_needed();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })?;

    debug!("/regenerate request handled via Rust path");
    Ok(response)
}

fn regenerate_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
) -> Result<Vec<String>> {
    Ok(session::regenerate_finalize(
        session,
        set_name,
        user_message,
        assistant_response,
        insertion_index,
    ))
}
