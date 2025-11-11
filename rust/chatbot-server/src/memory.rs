use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use chatbot_core::persistence::{DataPersistence, EncryptionMode, PersistenceError};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize, Default)]
struct UpdateMemoryRequest {
    #[serde(default)]
    memory: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    _encrypted: Option<bool>,
}

#[derive(Deserialize, Default)]
struct UpdateSystemPromptRequest {
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    _encrypted: Option<bool>,
}

#[derive(Deserialize, Default)]
struct DeleteMessageRequest {
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

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
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
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

    let session = bridge::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for update_memory");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    if let Some(username) = session.username.as_deref() {
        let key = session
            .encryption_key
            .as_ref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "relogin required".to_string()))?;

        persistence
            .store_memory(
                username,
                &set_name,
                &memory_text,
                EncryptionMode::Fernet(key.as_slice()),
            )
            .map_err(persistence_error_to_http)?;

        bridge::session_set_memory(&session.session_id, &memory_text).map_err(|err| {
            error!(?err, "failed to update python session memory");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to disk",
                "storage": "disk"
            }),
        )
    } else {
        bridge::session_set_memory(&session.session_id, &memory_text).map_err(|err| {
            error!(?err, "failed to cache guest memory in python session");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

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

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
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
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

    let session = bridge::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(
            ?err,
            "failed to obtain session context for update_system_prompt"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    if let Some(username) = session.username.as_deref() {
        let key = session
            .encryption_key
            .as_ref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "relogin required".to_string()))?;

        persistence
            .store_system_prompt(
                username,
                &set_name,
                &system_prompt,
                EncryptionMode::Fernet(key.as_slice()),
            )
            .map_err(persistence_error_to_http)?;

        bridge::session_set_system_prompt(&session.session_id, &system_prompt).map_err(|err| {
            error!(?err, "failed to update python session system prompt");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

        build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to disk",
                "storage": "disk"
            }),
        )
    } else {
        bridge::session_set_system_prompt(&session.session_id, &system_prompt).map_err(|err| {
            error!(?err, "failed to cache guest system prompt");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

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

    let body_bytes = body::to_bytes(body, 256 * 1024).await.map_err(|err| {
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
    let ai_trimmed = payload.ai_message.unwrap_or_default().trim().to_owned();
    if trimmed.is_empty() {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "user_message is required"}),
        );
    }

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(persistence_error_to_http)?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers)?;

    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

    let session = bridge::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for delete_message");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    let mut history = bridge::session_get_history(&session.session_id).map_err(|err| {
        error!(?err, "failed to read python session history");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    let mut match_index = None;

    if !ai_trimmed.is_empty() {
        for (index, (user, assistant)) in history.iter().enumerate() {
            if user.trim() == trimmed && assistant.trim() == ai_trimmed {
                match_index = Some(index);
                break;
            }
        }
    }

    if match_index.is_none() {
        for (index, (user, _assistant)) in history.iter().enumerate() {
            if user.trim() == trimmed {
                match_index = Some(index);
                break;
            }
        }
    }

    if let Some(index) = match_index {
        history.remove(index);

        bridge::session_set_history(&session.session_id, &history).map_err(|err| {
            error!(?err, "failed to update python session history");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

        if let Some(username) = session.username.as_deref() {
            let key = session
                .encryption_key
                .as_ref()
                .ok_or_else(|| (StatusCode::UNAUTHORIZED, "relogin required".to_string()))?;

            persistence
                .store_history(
                    username,
                    &set_name,
                    &history,
                    EncryptionMode::Fernet(key.as_slice()),
                )
                .map_err(persistence_error_to_http)?;
        }

        build_json_response(StatusCode::OK, json!({"status": "success"}))
    } else {
        build_json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "message pair not found"}),
        )
    }
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

fn extract_csrf(headers: &axum::http::HeaderMap) -> Result<&str, (StatusCode, String)> {
    headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing CSRF token".to_string()))
}

fn validate_csrf(
    cookie_header: Option<&str>,
    csrf_token: &str,
) -> Result<(), (StatusCode, String)> {
    let valid = bridge::validate_csrf_token(cookie_header, csrf_token).map_err(|err| {
        error!(?err, "failed to validate CSRF token for memory endpoint");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    if !valid {
        return Err((StatusCode::BAD_REQUEST, "Invalid CSRF token".to_string()));
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
