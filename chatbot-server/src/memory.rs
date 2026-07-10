use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    history::{self, HistoryError, HistoryService, SetId, SetVersion},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB

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
    #[serde(default)]
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
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_BODY_SIZE).await.map_err(|err| {
        error!(?err, "failed to read /update_memory body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        UpdateMemoryRequest::default()
    } else {
        serde_json::from_slice::<UpdateMemoryRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /update_memory");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let memory_text = payload.memory.unwrap_or_default();
    if memory_text.trim().is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "Memory content is required"}),
        );
    }

    let set_name = history::normalise_set_name(payload.set_name.as_deref())
        .map_err(|e| map_name_err(e))?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for update_memory");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    if payload.logged_in.unwrap_or(false) && session.username.is_none() {
        return build_json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        );
    }

    if let Some(username) = session.username.as_deref() {
        if let Err(response) =
            session::validate_encryption_key_for_user(username, encryption_key.as_ref())
        {
            return build_service_response(response);
        }
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history = HistoryService::global().map_err(history_error_to_tuple)?;
        let snap = resolve_set(
            &history,
            username,
            payload.set_id.as_deref(),
            Some(&set_name),
            key,
        )?;
        let expected = payload
            .expected_version
            .map(SetVersion)
            .unwrap_or(snap.version);
        let version = match history.update_memory(username, snap.set_id, expected, &memory_text, key)
        {
            Ok(v) => v,
            Err(HistoryError::Conflict { current_version }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(snap.set_id, current_version),
                );
            }
            Err(err) => return Err(history_error_to_tuple(err)),
        };

        if let Err(response) = session::update_session_memory_for_request(
            &session.session_id,
            username,
            snap.set_id,
            &memory_text,
            key,
        ) {
            return build_service_response(response);
        }

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to disk",
                "storage": "disk",
                "version": version.get(),
                "set_id": snap.set_id.to_string(),
            }),
        )
    } else {
        session::update_session_memory(&session.session_id, &memory_text);

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
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_BODY_SIZE).await.map_err(|err| {
        error!(?err, "failed to read /update_system_prompt body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        UpdateSystemPromptRequest::default()
    } else {
        serde_json::from_slice::<UpdateSystemPromptRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /update_system_prompt");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
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

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(
            ?err,
            "failed to obtain session context for update_system_prompt"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    if payload.logged_in.unwrap_or(false) && session.username.is_none() {
        return build_json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        );
    }

    if let Some(username) = session.username.as_deref() {
        if let Err(response) =
            session::validate_encryption_key_for_user(username, encryption_key.as_ref())
        {
            return build_service_response(response);
        }
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history = HistoryService::global().map_err(history_error_to_tuple)?;
        let snap = resolve_set(
            &history,
            username,
            payload.set_id.as_deref(),
            Some(&set_name),
            key,
        )?;
        let expected = payload
            .expected_version
            .map(SetVersion)
            .unwrap_or(snap.version);
        let version = match history.update_system_prompt(
            username,
            snap.set_id,
            expected,
            &system_prompt,
            key,
        ) {
            Ok(v) => v,
            Err(HistoryError::Conflict { current_version }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(snap.set_id, current_version),
                );
            }
            Err(err) => return Err(history_error_to_tuple(err)),
        };

        if let Err(response) = session::update_session_system_prompt_for_request(
            &session.session_id,
            username,
            snap.set_id,
            &system_prompt,
            key,
        ) {
            return build_service_response(response);
        }

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to disk",
                "storage": "disk",
                "version": version.get(),
                "set_id": snap.set_id.to_string(),
            }),
        )
    } else {
        session::update_session_system_prompt(&session.session_id, &system_prompt);

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
) -> Result<Response<Body>, (StatusCode, String)> {
    ensure_post(&request)?;
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, MAX_BODY_SIZE).await.map_err(|err| {
        error!(?err, "failed to read /delete_message body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        DeleteMessageRequest::default()
    } else {
        serde_json::from_slice::<DeleteMessageRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /delete_message");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
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

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for delete_message");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    if let Some(username) = session.username.as_deref() {
        if let Err(response) =
            session::validate_encryption_key_for_user(username, encryption_key.as_ref())
        {
            return build_service_response(response);
        }
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history_svc = HistoryService::global().map_err(history_error_to_tuple)?;
        let snap = resolve_set(
            &history_svc,
            username,
            payload.set_id.as_deref(),
            Some(&set_name),
            key,
        )?;
        if pair_index >= snap.history.len() {
            return build_json_response(
                StatusCode::NOT_FOUND,
                json!({"status": "error", "error": "pair_index out of range"}),
            );
        }
        let expected = payload
            .expected_version
            .map(SetVersion)
            .unwrap_or(snap.version);
        match history_svc.delete_pair(
            username,
            snap.set_id,
            expected,
            pair_index,
            trimmed,
            key,
        ) {
            Ok(version) => {
                let mut remaining = snap.history;
                remaining.remove(pair_index);
                if let Err(response) = session::set_session_history_for_request(
                    &session.session_id,
                    Some(username),
                    Some(snap.set_id),
                    remaining,
                    encryption_key.as_ref(),
                ) {
                    return build_service_response(response);
                }
                return build_json_response(
                    StatusCode::OK,
                    json!({
                        "status": "success",
                        "version": version.get(),
                        "set_id": snap.set_id.to_string(),
                    }),
                );
            }
            Err(HistoryError::Conflict { current_version }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(snap.set_id, current_version),
                );
            }
            Err(HistoryError::InvalidInput("content mismatch at pair_index")) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    json!({"status": "error", "error": "content mismatch at pair_index"}),
                );
            }
            Err(HistoryError::InvalidInput("pair_index out of range")) => {
                return build_json_response(
                    StatusCode::NOT_FOUND,
                    json!({"status": "error", "error": "pair_index out of range"}),
                );
            }
            Err(err) => return Err(history_error_to_tuple(err)),
        }
    }

    let mut history = session::session_history(&session.session_id);
    if pair_index >= history.len() {
        return build_json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "pair_index out of range"}),
        );
    }
    let (stored_user, _stored_assistant) = &history[pair_index];
    if stored_user.trim() != trimmed {
        return build_json_response(
            StatusCode::CONFLICT,
            json!({"status": "error", "error": "content mismatch at pair_index"}),
        );
    }
    history.remove(pair_index);
    session::update_session_history(&session.session_id, &history);
    build_json_response(StatusCode::OK, json!({"status": "success"}))
}

fn build_service_response(
    response: session::ServiceResponse,
) -> Result<Response<Body>, (StatusCode, String)> {
    crate::build_response(response).map_err(|(status, message)| (status, message))
}

fn ensure_post(request: &Request<Body>) -> Result<(), (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }
    Ok(())
}

fn extract_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned())
}

fn extract_csrf(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
}

fn validate_csrf(
    cookie_header: Option<&str>,
    csrf_token: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let valid = session::validate_csrf_token(cookie_header, csrf_token).map_err(|err| {
        error!(?err, "failed to validate CSRF token for memory endpoint");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token".to_string()));
    }

    Ok(())
}

fn history_error_to_tuple(err: HistoryError) -> (StatusCode, String) {
    crate::chat_utils::history_error_to_http(err)
}

fn map_name_err(err: chatbot_core::persistence::PersistenceError) -> (StatusCode, String) {
    match err {
        chatbot_core::persistence::PersistenceError::InvalidSetName => {
            (StatusCode::BAD_REQUEST, "invalid set name".into())
        }
        other => {
            error!(?other, "set name normalisation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid request".into())
        }
    }
}

fn resolve_set(
    history: &HistoryService,
    username: &str,
    set_id: Option<&str>,
    set_name: Option<&str>,
    key: &chatbot_core::enc_key::EncryptionKey,
) -> Result<chatbot_core::history::SetSnapshot, (StatusCode, String)> {
    if let Some(raw) = set_id {
        let id = SetId::parse(raw).map_err(|_| {
            (StatusCode::BAD_REQUEST, "invalid set_id".to_string())
        })?;
        return history.load(username, id, key).map_err(history_error_to_tuple);
    }
    let name = set_name.unwrap_or("default");
    match history.find_by_display_name(username, name, key) {
        Ok(Some(snap)) => Ok(snap),
        Ok(None) if name == "default" => history
            .ensure_default_set(username, key)
            .map_err(history_error_to_tuple),
        Ok(None) => Err((StatusCode::BAD_REQUEST, "set not found".to_string())),
        Err(err) => Err(history_error_to_tuple(err)),
    }
}

fn build_json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, (StatusCode, String)> {
    let body = serde_json::to_vec(&payload).map_err(|err| {
        error!(?err, "failed to serialize JSON response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response serialization failed".to_string(),
        )
    })?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|err| {
            error!(?err, "failed to build HTTP response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}
