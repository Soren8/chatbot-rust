use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::history::{self, HistoryError, SetVersion};
use chatbot_core::session::MutationMirrorError;
use serde::Deserialize;
use serde_json::json;
use crate::http_error::{
    api_error, map_body_read_err, map_encryption_key_validation_err, map_json_parse_err,
    map_response_build_err, map_serialization_err, map_session_err, map_session_operation_err,
    HttpError,
};
use crate::request_context::{extract_cookie, extract_csrf};
use crate::services::AppServices;
use crate::identity::RequestIdentity;

/// Memory / system-prompt updates (no image payloads).
const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB
/// Delete must echo `user_message` for content match, including base64 `[IMAGE:...]`
/// attachments up to the chat body / history message cap (~5 MiB).
const MAX_DELETE_BODY_SIZE: usize = 5 * 1024 * 1024 + 64 * 1024;

#[derive(Deserialize, Default)]
struct UpdateMemoryRequest {
    #[serde(default)]
    memory: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
    #[serde(default)]
    _encrypted: Option<bool>,
    #[serde(default)]
    logged_in: Option<bool>,
}

#[derive(Deserialize, Default)]
struct UpdateSystemPromptRequest {
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
    #[serde(default)]
    _encrypted: Option<bool>,
    #[serde(default)]
    logged_in: Option<bool>,
}

#[derive(Deserialize, Default)]
struct DeleteMessageRequest {
    #[serde(default)]
    pair_index: Option<i32>,
    #[serde(default)]
    user_message: Option<String>,
    /// Older clients may still send this; verification uses `user_message` only.
    #[serde(default)]
    #[allow(dead_code)]
    ai_message: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
}

pub async fn handle_update_memory(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|err| map_body_read_err(err, "memory::update_memory"))?;

    let payload = if body_bytes.is_empty() {
        UpdateMemoryRequest::default()
    } else {
        serde_json::from_slice::<UpdateMemoryRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "memory::update_memory"))?
    };

    let memory_text = payload.memory.unwrap_or_default();

    let set_name = history::normalise_set_name(payload.set_name.as_deref())
        .map_err(|e| map_name_err(e))?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "memory::update_memory::session",
    )?;

    if payload.logged_in.unwrap_or(false) && data_context.session().username.is_none() {
        return build_json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        );
    }

    if data_context.session().username.as_deref().is_some() {
        let session = data_context.session();
        let key = data_context.unverified_encryption_key();
        match chat.apply_memory_update(
            session,
            key,
            &set_name,
            payload.set_id.as_deref(),
            payload.expected_version.map(SetVersion),
            &memory_text,
        ) {
            Ok(applied) => build_json_response(
                StatusCode::OK,
                json!({
                    "status": "success",
                    "message": "Memory saved to disk",
                    "storage": "disk",
                    "version": applied.version.get(),
                    "set_id": applied.set_id.to_string(),
                }),
            ),
            Err(MutationMirrorError::Key(err)) => {
                Err(map_encryption_key_validation_err(err))
            }
            Err(MutationMirrorError::InvalidSetId) => {
                Err(api_error(StatusCode::BAD_REQUEST, "invalid set_id"))
            }
            Err(MutationMirrorError::SetNotFound) => {
                Err(api_error(StatusCode::BAD_REQUEST, "set not found"))
            }
            Err(MutationMirrorError::Conflict {
                set_id,
                current_version,
            }) => build_json_response(
                StatusCode::CONFLICT,
                crate::chat_utils::version_conflict_json(set_id, current_version),
            ),
            Err(MutationMirrorError::History(err)) => Err(history_error_to_tuple(err)),
            Err(MutationMirrorError::Mirror(err)) => Err(map_session_operation_err(&err)),
        }
    } else {
        chat.update_session_memory(&data_context.session().session_id, &memory_text);

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to session memory",
                "storage": "session"
            }),
        )
    }
}

pub async fn handle_update_system_prompt(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|err| map_body_read_err(err, "memory::update_system_prompt"))?;

    let payload = if body_bytes.is_empty() {
        UpdateSystemPromptRequest::default()
    } else {
        serde_json::from_slice::<UpdateSystemPromptRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "memory::update_system_prompt"))?
    };

    let system_prompt = payload.system_prompt.unwrap_or_default();
    if system_prompt.trim().is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "System prompt is required"}),
        );
    }

    let set_name = history::normalise_set_name(payload.set_name.as_deref()).map_err(map_name_err)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "memory::update_system_prompt::session",
    )?;

    if payload.logged_in.unwrap_or(false) && data_context.session().username.is_none() {
        return build_json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        );
    }

    if data_context.session().username.as_deref().is_some() {
        let session = data_context.session();
        let key = data_context.unverified_encryption_key();
        match chat.apply_system_prompt_update(
            session,
            key,
            &set_name,
            payload.set_id.as_deref(),
            payload.expected_version.map(SetVersion),
            &system_prompt,
        ) {
            Ok(applied) => build_json_response(
                StatusCode::OK,
                json!({
                    "status": "success",
                    "message": "System prompt saved to disk",
                    "storage": "disk",
                    "version": applied.version.get(),
                    "set_id": applied.set_id.to_string(),
                }),
            ),
            Err(MutationMirrorError::Key(err)) => {
                Err(map_encryption_key_validation_err(err))
            }
            Err(MutationMirrorError::InvalidSetId) => {
                Err(api_error(StatusCode::BAD_REQUEST, "invalid set_id"))
            }
            Err(MutationMirrorError::SetNotFound) => {
                Err(api_error(StatusCode::BAD_REQUEST, "set not found"))
            }
            Err(MutationMirrorError::Conflict {
                set_id,
                current_version,
            }) => build_json_response(
                StatusCode::CONFLICT,
                crate::chat_utils::version_conflict_json(set_id, current_version),
            ),
            Err(MutationMirrorError::History(err)) => Err(history_error_to_tuple(err)),
            Err(MutationMirrorError::Mirror(err)) => Err(map_session_operation_err(&err)),
        }
    } else {
        chat.update_session_system_prompt(&data_context.session().session_id, &system_prompt);

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to session memory",
                "storage": "session"
            }),
        )
    }
}

pub async fn handle_delete_message(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_DELETE_BODY_SIZE)
        .await
        .map_err(|err| map_body_read_err(err, "memory::delete_message"))?;

    let payload = if body_bytes.is_empty() {
        DeleteMessageRequest::default()
    } else {
        serde_json::from_slice::<DeleteMessageRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "memory::delete_message"))?
    };

    let user_message = payload.user_message.unwrap_or_default();
    let trimmed = user_message.trim();
    if trimmed.is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "user_message is required"}),
        );
    }
    // AI text is no longer required for the check (allows deleting mid-generation or failed responses).
    // Only user text + pair_index is used for verification.
    let pair_index = match payload.pair_index {
        Some(index) if index >= 0 => index as usize,
        _ => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"status": "error", "error": "pair_index is required"}),
            );
        }
    };

    let set_name = history::normalise_set_name(payload.set_name.as_deref()).map_err(map_name_err)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "memory::delete_message::session",
    )?;

    if data_context.session().username.as_deref().is_some() {
        // Prefer set_id + expected_version from the client so we do not decrypt the full
        // multi-MB set twice (once to resolve, once inside delete_pair).
        let set_id_raw = payload
            .set_id
            .as_deref()
            .filter(|s| !s.trim().is_empty());
        let session = data_context.session();
        let key = data_context.unverified_encryption_key();
        match chat.apply_delete_pair(
            session,
            key,
            &set_name,
            set_id_raw,
            payload.expected_version.map(SetVersion),
            pair_index,
            trimmed,
        ) {
            Ok(applied) => {
                return build_json_response(
                    StatusCode::OK,
                    json!({
                        "status": "success",
                        "version": applied.version.get(),
                        "set_id": applied.set_id.to_string(),
                    }),
                );
            }
            Err(MutationMirrorError::Key(err)) => {
                return Err(map_encryption_key_validation_err(err));
            }
            Err(MutationMirrorError::InvalidSetId) => {
                return Err(api_error(StatusCode::BAD_REQUEST, "invalid set_id"));
            }
            Err(MutationMirrorError::SetNotFound) => {
                return Err(api_error(StatusCode::BAD_REQUEST, "set not found"));
            }
            Err(MutationMirrorError::Conflict {
                set_id,
                current_version,
            }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(set_id, current_version),
                );
            }
            Err(MutationMirrorError::History(HistoryError::InvalidInput(
                "content mismatch at pair_index",
            ))) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    json!({"status": "error", "error": "content mismatch at pair_index"}),
                );
            }
            Err(MutationMirrorError::History(HistoryError::InvalidInput(
                "pair_index out of range",
            ))) => {
                return build_json_response(
                    StatusCode::NOT_FOUND,
                    json!({"status": "error", "error": "pair_index out of range"}),
                );
            }
            Err(MutationMirrorError::History(err)) => {
                return Err(history_error_to_tuple(err));
            }
            Err(MutationMirrorError::Mirror(err)) => {
                return Err(map_session_operation_err(&err));
            }
        }
    }

    let session_id = data_context.session().session_id.clone();
    let mut history = chat.session_history(&session_id);
    if pair_index >= history.len() {
        return build_json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "pair_index out of range"}),
        );
    }
    let (stored_user, _stored_assistant) = &history[pair_index];
    if !chatbot_core::chat_images::user_messages_match(stored_user, trimmed) {
        return build_json_response(
            StatusCode::CONFLICT,
            json!({"status": "error", "error": "content mismatch at pair_index"}),
        );
    }
    history.remove(pair_index);
    chat.update_session_history(&session_id, &history);
    build_json_response(StatusCode::OK, json!({"status": "success"}))
}

fn ensure_post(request: &Request<Body>) -> Result<(), HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }
    Ok(())
}

fn validate_csrf(
    identity: &RequestIdentity,
    cookie_header: Option<&str>,
    csrf_token: Option<&str>,
) -> Result<(), HttpError> {
    let valid = identity
        .validate_csrf_token(cookie_header, csrf_token)
        .map_err(|err| map_session_err(err, "memory::csrf"))?;

    if !valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    Ok(())
}

fn history_error_to_tuple(err: HistoryError) -> HttpError {
    crate::chat_utils::history_error_to_http(err)
}

fn map_name_err(err: chatbot_core::history::SetNameError) -> HttpError {
    match err {
        chatbot_core::history::SetNameError::Invalid => {
            api_error(StatusCode::BAD_REQUEST, "invalid set name")
        }
    }
}

fn build_json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, HttpError> {
    if status == StatusCode::BAD_REQUEST {
        tracing::warn!(status = 400, body = %payload, "http 400");
    }
    let body = serde_json::to_vec(&payload)
        .map_err(|err| map_serialization_err(err, "memory::json_response"))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|err| map_response_build_err(err, "memory::json_response"))
}
