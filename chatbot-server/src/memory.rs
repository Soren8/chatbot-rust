use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
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

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(persistence_error_to_http)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

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
        let key = encryption_key
            .as_ref()
            .expect("validated encryption key")
            .as_bytes();

        persistence
            .store_memory(
                username,
                &set_name,
                &memory_text,
                EncryptionMode::Fernet(key),
            )
            .map_err(persistence_error_to_http)?;

        if let Err(response) = session::update_session_memory_for_request(
            &session.session_id,
            username,
            &memory_text,
            encryption_key.as_ref().expect("validated encryption key"),
        ) {
            return build_service_response(response);
        }

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to disk",
                "storage": "disk"
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

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(persistence_error_to_http)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

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
        let key = encryption_key
            .as_ref()
            .expect("validated encryption key")
            .as_bytes();

        persistence
            .store_system_prompt(
                username,
                &set_name,
                &system_prompt,
                EncryptionMode::Fernet(key),
            )
            .map_err(persistence_error_to_http)?;

        if let Err(response) = session::update_session_system_prompt_for_request(
            &session.session_id,
            username,
            &system_prompt,
            encryption_key.as_ref().expect("validated encryption key"),
        ) {
            return build_service_response(response);
        }

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to disk",
                "storage": "disk"
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
    let ai_message = payload.ai_message.unwrap_or_default();
    let ai_trimmed = ai_message.trim();
    if trimmed.is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "user_message is required"}),
        );
    }
    if ai_trimmed.is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "ai_message is required"}),
        );
    }
    let pair_index = match payload.pair_index {
        Some(index) if index >= 0 => index as usize,
        _ => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"status": "error", "error": "pair_index is required"}),
            );
        }
    };

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(persistence_error_to_http)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);

    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for delete_message");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let mut history = if let Some(username) = session.username.as_deref() {
        match session::session_history_for_request(
            &session.session_id,
            Some(username),
            encryption_key.as_ref(),
        ) {
            Ok(value) => value,
            Err(response) => return build_service_response(response),
        }
    } else {
        session::session_history(&session.session_id)
    };

    if pair_index >= history.len() {
        return build_json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "pair_index out of range"}),
        );
    }

    let (stored_user, stored_assistant) = &history[pair_index];
    if stored_user.trim() != trimmed || stored_assistant.trim() != ai_trimmed {
        return build_json_response(
            StatusCode::CONFLICT,
            json!({"status": "error", "error": "content mismatch at pair_index"}),
        );
    }

    history.remove(pair_index);

    if let Some(username) = session.username.as_deref() {
        if let Err(response) = session::set_session_history_for_request(
            &session.session_id,
            Some(username),
            history.clone(),
            encryption_key.as_ref(),
        ) {
            return build_service_response(response);
        }

        let key = encryption_key
            .as_ref()
            .expect("validated encryption key")
            .as_bytes();

        persistence
            .store_history(
                username,
                &set_name,
                &history,
                EncryptionMode::Fernet(key),
            )
            .map_err(persistence_error_to_http)?;
    } else {
        session::update_session_history(&session.session_id, &history);
    }

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

fn persistence_error_to_http(err: PersistenceError) -> (StatusCode, String) {
    match err {
        PersistenceError::InvalidUsername => {
            (StatusCode::BAD_REQUEST, "invalid session".to_string())
        }
        PersistenceError::InvalidSetName => {
            (StatusCode::BAD_REQUEST, "invalid set name".to_string())
        }
        PersistenceError::MissingEncryptionKey => {
            (StatusCode::UNAUTHORIZED, "relogin required".to_string())
        }
        other => {
            error!(?other, "persistence failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence error".to_string(),
            )
        }
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
