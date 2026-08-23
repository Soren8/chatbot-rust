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
    chat::{self, ChatMessageRole},
    config::{app_config, get_provider_config},
    session::{self, ChatRequestData, SessionContext},
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, warn};

use crate::chat_utils::{
    error_as_saved_chat_turn, service_error_message, ChatLockGuard, StreamCompletionGuard,
};
use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_response_build_err, map_session_err,
    HttpError,
};
use crate::providers::message_utils::parse_message_content;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::OpenAiProvider;
use crate::providers::xai::XaiProvider;

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    web_search: Option<bool>,
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    save_thoughts: Option<bool>,
    #[serde(default)]
    send_thoughts: Option<bool>,
}

pub async fn handle_chat(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "chat::post"))?;

    let payload: ChatRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "chat::post"))?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "chat::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session_context = session::session_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "chat::post::session"))?;

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
            if !payload.message.trim().is_empty() {
                return error_as_saved_chat_turn(
                    &session_context,
                    payload.set_name.as_deref(),
                    &payload.message,
                    "requested model not found",
                    encryption_key.as_ref(),
                    None,
                );
            }
            return Err(api_error(StatusCode::BAD_REQUEST, "requested model not found"));
        }
    };

    if selected_model.is_empty() {
        selected_model = provider_config.provider_name.clone();
    }

    let provider_type = provider_config.provider_type.to_lowercase();
    debug!(
        model = %selected_model,
        provider_type = %provider_type,
        "resolved provider configuration for chat"
    );
    if provider_type != "openai" && provider_type != "xai" {
        error!(
            model = %selected_model,
            provider_type = %provider_type,
            "unsupported provider type for chat"
        );
        if !payload.message.trim().is_empty() {
            return error_as_saved_chat_turn(
                &session_context,
                payload.set_name.as_deref(),
                &payload.message,
                "unsupported provider type",
                encryption_key.as_ref(),
                None,
            );
        }
        return Err(api_error(StatusCode::BAD_REQUEST, "unsupported provider type"));
    }

    let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
    let username = session_context.username.as_deref().unwrap_or("guest");
    // Prefer non-sensitive set_id in logs; display names are privacy-sensitive.
    let set_log = payload
        .set_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("name-fallback");

    tracing::info!(
        username = %username,
        ip = %ip,
        model = %selected_model,
        set_id = %set_log,
        "Chat request received"
    );

    let app_config = app_config();
    let save_thoughts = payload.save_thoughts.unwrap_or(app_config.save_thoughts);
    let send_thoughts = payload.send_thoughts.unwrap_or(app_config.send_thoughts);

    let request_data = ChatRequestData {
        message: payload.message.as_str(),
        system_prompt: payload.system_prompt.as_deref(),
        set_name: payload.set_name.as_deref(),
        set_id: payload.set_id.as_deref(),
        model_name: Some(selected_model.as_str()),
        encrypted: payload.encrypted.unwrap_or(false),
        send_thoughts,
    };

    let prepare = session::chat_prepare(
        &session_context,
        &request_data,
        &provider_config,
        encryption_key.as_ref(),
    );

    if let Some(py_response) = prepare.error {
        if py_response.status == 400 && !payload.message.trim().is_empty() {
            let msg = service_error_message(&py_response);
            return error_as_saved_chat_turn(
                &session_context,
                payload.set_name.as_deref(),
                &payload.message,
                &msg,
                encryption_key.as_ref(),
                None,
            );
        }
        return crate::build_response(py_response);
    }

    let context = prepare.context.ok_or_else(|| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "missing chat context")
    })?;

    let lock_guard = Arc::new(Mutex::new(ChatLockGuard::new(context.session_id.clone())));

    enum ProviderKind {
        OpenAi(OpenAiProvider),
        Xai(XaiProvider),
    }

    let provider_kind = match provider_type.as_str() {
        "openai" => match OpenAiProvider::new(&context.provider) {
            Ok(p) => ProviderKind::OpenAi(p),
            Err(err) => {
                error!(?err, "failed to construct OpenAI provider");
                lock_guard.lock().unwrap().release_if_needed();
                return error_as_saved_chat_turn(
                    &session_context,
                    Some(context.set_name.as_str()),
                    payload.message.as_str(),
                    "provider setup failed",
                    encryption_key.as_ref(),
                    None,
                );
            }
        },
        "xai" => match XaiProvider::new(&context.provider) {
            Ok(p) => ProviderKind::Xai(p),
            Err(err) => {
                error!(?err, "failed to construct XAI provider");
                lock_guard.lock().unwrap().release_if_needed();
                return error_as_saved_chat_turn(
                    &session_context,
                    Some(context.set_name.as_str()),
                    payload.message.as_str(),
                    "provider setup failed",
                    encryption_key.as_ref(),
                    None,
                );
            }
        },
        _ => unreachable!("provider_type should be filtered earlier"),
    };

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
            ChatMessageRole::System => ChatMessagePayload::system(message.content.clone()),
            ChatMessageRole::User => {
                let content = parse_message_content(&message.content);
                ChatMessagePayload::user_with_content(content)
            }
            ChatMessageRole::Assistant => ChatMessagePayload::assistant(message.content.clone()),
        })
        .collect::<Vec<_>>();

    let session_context_for_finalize = session_context.clone();
    let set_name = context.set_name.clone();
    let prepare_capture = context.prepare_capture.clone();
    let user_message = payload.message.clone();
    let encryption_key_for_finalize = encryption_key.clone();

    let mut provider_stream = match provider_kind {
        ProviderKind::OpenAi(provider) => {
            let use_search = payload.web_search.unwrap_or(false);
            let brave = if use_search { crate::brave::brave_client() } else { None };

            let stream_result = if let Some(ref brave) = brave {
                let tools = vec![crate::tools::brave_web_search_tool()];
                match crate::search::search_augmented_stream(&provider, messages.clone(), brave, &tools).await {
                    Ok(s) => Ok(s),
                    Err(err) => {
                        warn!(?err, "search augmentation failed, falling back to regular streaming");
                        provider.stream_chat(messages.clone())
                    }
                }
            } else {
                provider.stream_chat(messages.clone())
            };

            match stream_result {
                Ok(stream) => stream,
                Err(err) => {
                    error!(?err, "provider stream setup failed");
                    lock_guard.lock().unwrap().release_if_needed();
                    return error_as_saved_chat_turn(
                        &session_context,
                        Some(set_name.as_str()),
                        user_message.as_str(),
                        "provider request failed",
                        encryption_key.as_ref(),
                        None,
                    );
                }
            }
        },
        ProviderKind::Xai(xai_provider) => {
            let web_search = payload.web_search.unwrap_or(false);
            let use_brave = web_search && !context.provider.xai_search;
            let brave = if use_brave { crate::brave::brave_client() } else { None };

            let stream_result = if let Some(ref brave) = brave {
                // Use Brave search via XAI's OpenAI-compatible /chat/completions endpoint
                match OpenAiProvider::new(&context.provider) {
                    Ok(openai_provider) => {
                        let tools = vec![crate::tools::brave_web_search_tool()];
                        match crate::search::search_augmented_stream(&openai_provider, messages.clone(), brave, &tools).await {
                            Ok(s) => Ok(s),
                            Err(err) => {
                                warn!(?err, "XAI Brave search failed, falling back to native");
                                xai_provider.stream_chat(messages.clone(), web_search)
                            }
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to build OpenAI provider for XAI Brave search, using native");
                        xai_provider.stream_chat(messages.clone(), web_search)
                    }
                }
            } else {
                xai_provider.stream_chat(messages.clone(), web_search)
            };

            match stream_result {
                Ok(stream) => stream,
                Err(err) => {
                    error!(?err, "provider stream setup failed");
                    lock_guard.lock().unwrap().release_if_needed();
                    return error_as_saved_chat_turn(
                        &session_context,
                        Some(set_name.as_str()),
                        user_message.as_str(),
                        "provider request failed",
                        encryption_key.as_ref(),
                        None,
                    );
                }
            }
        },
    };

    let stream_lock = lock_guard.clone();
    let session_for_guard = session_context_for_finalize.clone();
    let set_name_for_guard = set_name.clone();
    let user_message_for_guard = user_message.clone();
    let enc_for_guard = encryption_key_for_finalize.clone();
    let capture_for_guard = prepare_capture.clone();

    let stream = stream! {
        let mut guard = StreamCompletionGuard::new(
            stream_lock,
            save_thoughts,
            move |final_response| {
                finalize_chat(
                    &session_for_guard,
                    &set_name_for_guard,
                    &user_message_for_guard,
                    final_response,
                    enc_for_guard.as_ref(),
                    capture_for_guard.clone(),
                )
                .map_err(|err| {
                    error!(?err, "chat_finalize failed");
                })
            },
        );

        while let Some(item) = provider_stream.next().await {
            match item {
                Ok(chunk) => {
                    guard.push_chunk(&chunk);
                    yield Bytes::from(chunk.into_bytes());
                }
                Err(err) => {
                    error!(?err, "error while reading provider stream");
                    // Do not persist partial/error-tainted assistant text.
                    guard.mark_provider_error();
                    let msg = format!("\n[Error] {err}\n");
                    yield Bytes::from(msg.into_bytes());
                    guard.complete_without_persist();
                    break;
                }
            }
        }

        // Full stream consumed: persist + unlock. If the client aborted earlier,
        // this generator was dropped and StreamCompletionGuard::drop already
        // finalized whatever partial text we had (so Stop → Edit can regenerate).
        let extras = guard.complete_success();
        for chunk in extras {
            yield Bytes::from(chunk.into_bytes());
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
            lock_guard.lock().unwrap().release_if_needed();
            map_response_build_err(err, "chat::post::response")
        })?;

    debug!("/chat request handled via Rust path");
    Ok(response)
}

fn finalize_chat(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&chatbot_core::enc_key::EncryptionKey>,
    prepare_capture: Option<chatbot_core::history::PrepareCapture>,
) -> Result<Vec<String>> {
    Ok(session::chat_finalize_with_capture(
        session,
        set_name,
        user_message,
        assistant_response,
        encryption_key,
        prepare_capture,
    ))
}
