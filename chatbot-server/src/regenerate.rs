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
    chat,
    config::{app_config, get_provider_config},
    session::{self, RegenerateRequestData},
};
use futures_util::StreamExt;
use serde::Deserialize;
use tracing::{debug, error};

use crate::chat_utils::{
    error_as_saved_chat_turn_with_service, provider_error_parts, render_finalize_outcome,
    StreamCompletionGuard,
};
use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_prepare_history_err,
    map_prepare_policy_err, map_prepare_validation_err, map_response_build_err, map_session_err,
    map_session_operation_err, HttpError,
};
use crate::providers::generation::{build_provider, dispatch_stream, map_core_messages};
use crate::services::AppServices;

#[derive(Deserialize)]
struct RegenerateRequest {
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
    encrypted: Option<bool>,
    #[serde(default)]
    pair_index: Option<i32>,
    #[serde(default)]
    web_search: Option<bool>,
    #[serde(default)]
    save_thoughts: Option<bool>,
    #[serde(default)]
    send_thoughts: Option<bool>,
}

pub async fn handle_regenerate(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "regenerate::post"))?;

    let payload: RegenerateRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "regenerate::post"))?;

    let cookie_header = crate::request_context::extract_cookie(&headers);
    let csrf_token = crate::request_context::extract_csrf(&headers);

    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "regenerate::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "regenerate::post::session",
    )?;
    // Still unverified: core prepare owns key validation.
    let (session_context, encryption_key) = data_context.into_unverified_parts();

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
    if provider_type != "openai" && provider_type != "xai" {
        error!(
            model = %selected_model,
            provider_type = %provider_type,
            "unsupported provider type for regenerate"
        );
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

    let app_config = app_config();
    let save_thoughts = payload.save_thoughts.unwrap_or(app_config.save_thoughts);
    let send_thoughts = payload.send_thoughts.unwrap_or(app_config.send_thoughts);

    let request_data = RegenerateRequestData {
        message: payload.message.as_str(),
        system_prompt: payload.system_prompt.as_deref(),
        set_name: payload.set_name.as_deref(),
        set_id: payload.set_id.as_deref(),
        model_name: Some(selected_model.as_str()),
        encrypted: payload.encrypted.unwrap_or(false),
        pair_index: payload.pair_index,
        send_thoughts,
    };

    let prepare = chat.regenerate_prepare_leased(
        &session_context,
        &request_data,
        &provider_config,
        encryption_key.as_ref(),
    );

    if let Some(err) = prepare.error {
        match err {
            session::PrepareError::Validation(validation) => {
                if !payload.message.trim().is_empty() {
                    return error_as_saved_chat_turn_with_service(&chat,
                        &session_context,
                        payload.set_name.as_deref(),
                        &payload.message,
                        validation.message(),
                        encryption_key.as_ref(),
                        None,
                    );
                }
                return Err(map_prepare_validation_err(&validation));
            }
            session::PrepareError::Policy(policy) => {
                return Err(map_prepare_policy_err(&policy));
            }
            session::PrepareError::History(history) => {
                if !payload.message.trim().is_empty() {
                    if let Some(msg) = history.saved_error_message() {
                        return error_as_saved_chat_turn_with_service(&chat,
                            &session_context,
                            payload.set_name.as_deref(),
                            &payload.message,
                            msg,
                            encryption_key.as_ref(),
                            None,
                        );
                    }
                }
                return Err(map_prepare_history_err(&history));
            }
            session::PrepareError::Session(op) => {
                if op == session::SessionOperationError::AuthenticatedBootstrapMisuse
                    && !payload.message.trim().is_empty()
                {
                    return error_as_saved_chat_turn_with_service(&chat,
                        &session_context,
                        payload.set_name.as_deref(),
                        &payload.message,
                        op.message(),
                        encryption_key.as_ref(),
                        None,
                    );
                }
                return Err(map_session_operation_err(&op));
            }
        }
    }

    let context = prepare.context.ok_or_else(|| {
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "missing chat context")
    })?;

    let insertion_index = prepare.insertion_index;

    // The lease settles this generation.
    let lease = prepare.lease.ok_or_else(|| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing generation lease",
        )
    })?;

    let provider = match build_provider(provider_type.as_str(), &context.provider) {
        Ok(provider) => provider,
        Err(err) => {
            lease.release_without_persist();
            let (setup_msg, _) = provider_error_parts(&err);
            return error_as_saved_chat_turn_with_service(&chat,
                &session_context,
                Some(context.set_name.as_str()),
                payload.message.as_str(),
                &setup_msg,
                encryption_key.as_ref(),
                insertion_index,
            );
        }
    };

    // Prefer the capture's coalesced user text so a UI thumbnail is not
    // persisted (or sent to the model) in place of the stored full image.
    let user_message = context
        .prepare_capture
        .as_ref()
        .and_then(|c| c.replace_user_message.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| payload.message.clone());

    let prepared = chat::prepare_chat_messages(&context, user_message.as_str());

    if prepared.was_truncated() {
        debug!(
            original_history_tokens = prepared.original_history_tokens,
            truncated_history_tokens = prepared.truncated_history_tokens,
            "regenerate history token metrics"
        );
    }

    let messages = map_core_messages(&prepared.messages);

    let set_name = context.set_name.clone();
    let prepare_capture = context.prepare_capture.clone();
    let encryption_key_for_finalize = encryption_key.clone();

    let mut provider_stream = match dispatch_stream(
        &provider,
        &context.provider,
        messages,
        payload.web_search.unwrap_or(false),
    )
    .await
    {
        Ok(stream) => stream,
        Err(err) => {
            error!(?err, "provider stream setup failed");
            lease.release_without_persist();
            let (req_msg, _) = provider_error_parts(&err);
            return error_as_saved_chat_turn_with_service(&chat,
                &session_context,
                Some(set_name.as_str()),
                user_message.as_str(),
                &req_msg,
                encryption_key.as_ref(),
                insertion_index,
            );
        }
    };

    let set_name_for_guard = set_name.clone();
    let user_message_for_guard = user_message.clone();
    let enc_for_guard = encryption_key_for_finalize.clone();
    let capture_for_guard = prepare_capture.clone();

    let stream = stream! {
        // The persist closure owns the lease. Dropping an unpolled stream
        // releases it without persisting.
        let mut guard = StreamCompletionGuard::new(
            save_thoughts,
            move |final_response: &str| -> Result<Vec<String>, ()> {
                let outcome = lease.complete_regenerate_outcome(
                    &set_name_for_guard,
                    &user_message_for_guard,
                    final_response,
                    insertion_index,
                    enc_for_guard.as_ref(),
                    capture_for_guard.clone(),
                );
                Ok(render_finalize_outcome(&outcome))
            },
        );

        while let Some(item) = provider_stream.next().await {
            match item {
                Ok(chunk) => {
                    guard.push_chunk(&chunk);
                    yield Bytes::from(chunk.into_bytes());
                }
                Err(err) => {
                    error!(?err, "error while reading provider stream (regenerate)");
                    // Do not persist partial/error-tainted assistant text.
                    guard.mark_provider_error();
                    // Keep the on-screen message short; the full anyhow chain is
                    // sent via the `[ConsoleError]` marker for the browser console.
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
        .map_err(|err| map_response_build_err(err, "regenerate::post::response"))?;

    debug!("/regenerate request handled via Rust path");
    Ok(response)
}
