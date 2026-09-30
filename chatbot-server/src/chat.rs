use std::convert::Infallible;
use std::pin::Pin;

use anyhow::Result;
use async_stream::stream;
use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use bytes::Bytes;
use chatbot_core::{
    chat,
    session::ChatRequestData,
};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use tracing::{debug, error, warn};

use crate::chat_utils::{
    error_as_saved_chat_turn_with_service, map_prepare_error, provider_error_parts,
    render_finalize_outcome, StreamCompletionGuard,
};
use crate::http_error::{
    api_error, api_error_json, map_body_read_err, map_json_parse_err, map_response_build_err,
    map_session_err, HttpError,
};
use crate::providers::generation::{
    build_provider_with_generation, dispatch_stream, map_core_messages,
};
use crate::services::AppServices;

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

pub(crate) fn persist_setup_error(
    feedback: Option<&crate::generations::GenerationFeedback>,
    persist: impl FnOnce() -> chatbot_core::session::FinalizeOutcome,
) {
    let outcome = persist();
    if let Some(feedback) = feedback { feedback.finalized(&outcome); }
}

#[cfg(test)]
mod setup_error_tests {
    #[test]
    fn saved_setup_error_reports_finalize_outcome() {
        use std::sync::{Arc, Mutex};
        use chatbot_core::session::FinalizeOutcome;
        let feedback = crate::generations::GenerationFeedback {
            expected_version: 4,
            base_version: Arc::new(Mutex::new(4)),
            outcome: Arc::new(Mutex::new(None)),
            provider_failed: Arc::new(Mutex::new(false)),
        };
        super::persist_setup_error(Some(&feedback), || FinalizeOutcome::DurableCommitted);
        assert_eq!(*feedback.outcome.lock().unwrap(), Some(FinalizeOutcome::DurableCommitted));
    }
}

pub(crate) fn saved_provider_error_response(
    err: &anyhow::Error,
    user_chars: usize,
    insertion_index: Option<usize>,
    location: &'static str,
    persist: impl FnOnce(&str),
) -> Result<Response<Body>, HttpError> {
    let (message, _) = provider_error_parts(err);
    let assistant = format!("[Error] {message}");
    warn!(
        error = %message,
        user_chars,
        insertion_index,
        "saving /chat or /regenerate error as assistant turn"
    );
    persist(&assistant);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Accel-Buffering", "no")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(assistant))
        .map_err(|err| map_response_build_err(err, location))
}

pub(crate) fn forward_provider_stream(
    mut provider_stream: Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>,
    mut guard: StreamCompletionGuard,
    regenerate: bool,
    feedback: Option<crate::generations::GenerationFeedback>,
) -> impl Stream<Item = Bytes> {
    stream! {
        while let Some(item) = provider_stream.next().await {
            match item {
                Ok(chunk) => {
                    guard.push_chunk(&chunk);
                    yield Bytes::from(chunk.into_bytes());
                }
                Err(err) => {
                    if regenerate {
                        error!(?err, "error while reading provider stream (regenerate)");
                    } else {
                        error!(?err, "error while reading provider stream");
                    }
                    guard.mark_provider_error();
                    if let Some(feedback) = &feedback { feedback.failed(); }
                    let (visible, detail) = provider_error_parts(&err);
                    let msg = format!(
                        "\n[Error] {visible}\n{open}{detail}{close}\n",
                        open = crate::chat_utils::PROVIDER_ERROR_DETAIL_OPEN,
                        close = crate::chat_utils::PROVIDER_ERROR_DETAIL_CLOSE,
                    );
                    yield Bytes::from(msg.into_bytes());
                    guard.complete_without_persist();
                    break;
                }
            }
        }

        let extras = guard.complete_success();
        for chunk in extras {
            yield Bytes::from(chunk.into_bytes());
        }
    }
}

pub(crate) async fn generation_stream(
    provider: crate::providers::generation::GenerationProvider,
    config: chatbot_core::config::ProviderConfig,
    messages: Vec<crate::providers::messages::ChatMessagePayload>,
    web_search: bool,
    fallback: bool,
    generation: crate::generation_deps::GenerationDeps,
    owned: bool,
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    if !owned {
        return dispatch_stream(&provider, &config, messages, web_search, fallback, &generation).await;
    }
    Ok(Box::pin(stream! {
        match dispatch_stream(&provider, &config, messages, web_search, fallback, &generation).await {
            Ok(mut source) => while let Some(item) = source.next().await { yield item; },
            Err(error) => yield Err(error),
        }
    }))
}

pub async fn handle_chat(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.headers().get("X-Generation-Mode").is_some_and(|v| v == "durable") {
        return crate::generations::admit(request, "chat").await;
    }
    handle_chat_legacy(request).await
}

pub(crate) async fn handle_chat_legacy(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let feedback = parts.extensions.get::<crate::generations::GenerationFeedback>().cloned();
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let generation = services.generation_deps();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "chat::post"))?;

    let payload: ChatRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "chat::post"))?;

    let cookie_header = crate::request_context::extract_cookie(&headers);
    let csrf_token = crate::request_context::extract_csrf(&headers);

    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "chat::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "chat::post::session",
    )?;
    // Still unverified: core prepare owns key validation.
    let (session_context, encryption_key) = data_context.into_unverified_parts();

    let mut selected_model = payload.model_name.clone().unwrap_or_default();

    let provider_config = match generation.get_provider_config(if selected_model.is_empty() {
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
            if feedback.is_some() {
                return Err(api_error(StatusCode::BAD_REQUEST, "requested model not found"));
            }
            if !payload.message.trim().is_empty() {
                return error_as_saved_chat_turn_with_service(&chat,
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
        if feedback.is_some() { return Err(api_error(StatusCode::BAD_REQUEST, "unsupported provider type")); }
        if !payload.message.trim().is_empty() {
            return error_as_saved_chat_turn_with_service(&chat,
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

    let privacy_binding = if let Some(user) = session_context.username.as_deref() {
        chat.validate_encryption_key_for_user(user, encryption_key.as_ref())
            .map_err(crate::http_error::map_encryption_key_validation_err)?;
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history = chat.history().map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "history unavailable"))?;
        // A missing set must follow the same saved-turn contract as other
        // prepare failures: with a nonempty message the error is returned as
        // a 200 assistant turn instead of a raw 400.
        let set_id = match crate::set_privacy_coordinator::resolve_content_set(&history, user, payload.set_id.as_deref(), payload.set_name.as_deref(), key) {
            Ok(id) => id,
            Err(chatbot_core::history::HistoryError::NotFound) if feedback.is_none() && !payload.message.trim().is_empty() => {
                return error_as_saved_chat_turn_with_service(&chat,
                    &session_context,
                    payload.set_name.as_deref(),
                    &payload.message,
                    "invalid set name",
                    encryption_key.as_ref(),
                    None,
                );
            }
            Err(err) => return Err(crate::set_privacy_coordinator::map_resolution_error(err)),
        };
        let permit = services.set_privacy().content(user, set_id).await;
        let snapshot = history.load(user, set_id, key).map_err(crate::set_privacy_coordinator::map_resolution_error)?;
        Some((permit, set_id, snapshot.privacy_level))
    } else { None };

    let ip = crate::request_context::get_ip(&headers, &parts.extensions);
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

    let (default_save_thoughts, default_send_thoughts) = generation.thoughts_defaults();
    let save_thoughts = payload.save_thoughts.unwrap_or(default_save_thoughts);
    let send_thoughts = payload.send_thoughts.unwrap_or(default_send_thoughts);

    let request_data = ChatRequestData {
        message: payload.message.as_str(),
        system_prompt: payload.system_prompt.as_deref(),
        set_name: payload.set_name.as_deref(),
        set_id: payload.set_id.as_deref(),
        model_name: Some(selected_model.as_str()),
        encrypted: payload.encrypted.unwrap_or(false),
        send_thoughts,
    };

    let prepare = chat.chat_prepare_leased(
        &session_context,
        &request_data,
        &provider_config,
        encryption_key.as_ref(),
    );

    if let Some((_, set_id, captured_level)) = &privacy_binding {
        if prepare.context.as_ref().and_then(|ctx| ctx.prepare_capture.as_ref())
            .is_some_and(|capture| capture.set_id != *set_id || capture.privacy_level != *captured_level)
        {
            return Err(api_error_json(StatusCode::CONFLICT, serde_json::json!({"error":"version_conflict"})));
        }
    }

    if let Some(err) = prepare.error {
        if feedback.is_some() { return Err(crate::chat_utils::prepare_rejection(err)); }
        return map_prepare_error(
            err,
            &chat,
            &session_context,
            payload.set_name.as_deref(),
            &payload.message,
            encryption_key.as_ref(),
        );
    }

    let context = prepare.context.ok_or_else(|| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "missing chat context")
    })?;
    if privacy_binding.is_some() && context.prepare_capture.is_none() {
        return Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "missing set privacy capture"));
    }
    if let Some(feedback) = &feedback {
        feedback.capture(context.prepare_capture.as_ref())?;
    }
    let mut allow_native_search_fallback = true;
    if let Some((_, _, level)) = privacy_binding.as_ref() {
        allow_native_search_fallback = crate::set_privacy_coordinator::check_destination_eligibility(
            *level,
            services.config_source().destination_policy().as_deref(),
            &selected_model,
            provider_type.as_str(),
            provider_config.xai_search,
            payload.web_search.unwrap_or(false),
        )?;
    }
    let privacy_permit = privacy_binding.map(|(permit, _, _)| permit);
    // The lease settles this generation.
    let lease = prepare.lease.ok_or_else(|| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing generation lease",
        )
    })?;

    let provider = match build_provider_with_generation(
        provider_type.as_str(),
        &context.provider,
        &generation,
    ) {
        Ok(provider) => provider,
        Err(err) => {
            return saved_provider_error_response(&err, payload.message.chars().count(), None, "chat::setup_error", |assistant| {
                persist_setup_error(feedback.as_ref(), || lease.complete_chat_outcome(
                    context.set_name.as_str(), payload.message.as_str(), assistant,
                    encryption_key.as_ref(), context.prepare_capture.clone(),
                ));
            });
        }
    };

    let prepared = chat::prepare_chat_messages(&context, payload.message.as_str());

    if prepared.was_truncated() {
        debug!(
            original_history_tokens = prepared.original_history_tokens,
            truncated_history_tokens = prepared.truncated_history_tokens,
            "chat history token metrics"
        );
    }

    let messages = map_core_messages(&prepared.messages);

    let provider_stream = match generation_stream(
        provider,
        context.provider.clone(),
        messages,
        payload.web_search.unwrap_or(false),
        allow_native_search_fallback,
        generation,
        feedback.is_some(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(err) => {
            if err.downcast_ref::<crate::providers::generation::PrivacyRestrictedFallback>().is_some() {
                return Err(api_error_json(StatusCode::FORBIDDEN, serde_json::json!({"error":"privacy_restricted","destination":"native_search"})));
            }
            error!(?err, "provider stream setup failed");
            return saved_provider_error_response(&err, payload.message.chars().count(), None, "chat::setup_error", |assistant| {
                persist_setup_error(feedback.as_ref(), || lease.complete_chat_outcome(
                    context.set_name.as_str(), payload.message.as_str(), assistant,
                    encryption_key.as_ref(), context.prepare_capture.clone(),
                ));
            });
        }
    };

    let set_name_for_guard = context.set_name.clone();
    let user_message_for_guard = payload.message.clone();
    let enc_for_guard = encryption_key.clone();
    let capture_for_guard = context.prepare_capture.clone();

    let feedback_for_guard = feedback.clone();
    let persist = move |final_response: &str| -> Result<Vec<String>, ()> {
        let outcome = lease.complete_chat_outcome(
            &set_name_for_guard, &user_message_for_guard, final_response,
            enc_for_guard.as_ref(), capture_for_guard.clone(),
        );
        if let Some(feedback) = &feedback_for_guard { feedback.finalized(&outcome); }
        Ok(render_finalize_outcome(&outcome))
    };
    let mut persist = Some(persist);
    let owned_guard = feedback.as_ref().map(|_| StreamCompletionGuard::new(save_thoughts, persist.take().expect("persist")));
    let stream = stream! {
        let _privacy_permit = privacy_permit;
        let guard = owned_guard.unwrap_or_else(|| StreamCompletionGuard::new(save_thoughts, persist.take().expect("persist")));

        // Full stream consumed: persist + unlock. If the client aborted earlier,
        // this generator was dropped and StreamCompletionGuard::drop already
        // finalized whatever partial text we had (so Stop → Edit can regenerate).
        let forwarded = forward_provider_stream(provider_stream, guard, false, feedback);
        futures_util::pin_mut!(forwarded);
        while let Some(chunk) = forwarded.next().await {
            yield chunk;
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
        // The lease moved into the stream; dropping the body releases it
        // without persisting.
        .map_err(|err| map_response_build_err(err, "chat::post::response"))?;

    debug!("/chat request handled via Rust path");
    Ok(response)
}
