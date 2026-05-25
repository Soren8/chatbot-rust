use axum::{
    body::{self, Body},
    http::{Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{auth::Session as AuthSession, responses};

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
    AuthSession(session): AuthSession,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;
    let (_, body) = request.into_parts();

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
        return Ok(responses::json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "Memory content is required"}),
        ));
    }

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(responses::persistence_error_to_http)?;

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;

    if payload.logged_in.unwrap_or(false) && session.username.is_none() {
        return Ok(responses::json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        ));
    }

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
            .map_err(responses::persistence_error_to_http)?;

        session::update_session_memory(&session.session_id, &memory_text);

        Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to disk",
                "storage": "disk"
            }),
        ))
    } else {
        session::update_session_memory(&session.session_id, &memory_text);

        Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Memory saved to session memory",
                "storage": "session"
            }),
        ))
    }
}

pub async fn handle_update_system_prompt(
    AuthSession(session): AuthSession,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;
    let (_, body) = request.into_parts();

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
        return Ok(responses::json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "System prompt is required"}),
        ));
    }

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(responses::persistence_error_to_http)?;

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;

    if payload.logged_in.unwrap_or(false) && session.username.is_none() {
        return Ok(responses::json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Session expired"}),
        ));
    }

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
            .map_err(responses::persistence_error_to_http)?;

        session::update_session_system_prompt(&session.session_id, &system_prompt);

        Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to disk",
                "storage": "disk"
            }),
        ))
    } else {
        session::update_session_system_prompt(&session.session_id, &system_prompt);

        Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "System prompt saved to session memory",
                "storage": "session"
            }),
        ))
    }
}

pub async fn handle_delete_message(
    AuthSession(session): AuthSession,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;
    let (_, body) = request.into_parts();

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
        return Ok(responses::json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "user_message is required"}),
        ));
    }
    if ai_trimmed.is_empty() {
        return Ok(responses::json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": "ai_message is required"}),
        ));
    }
    let pair_index = match payload.pair_index {
        Some(index) if index >= 0 => index as usize,
        _ => {
            return Ok(responses::json_response(
                StatusCode::BAD_REQUEST,
                json!({"status": "error", "error": "pair_index is required"}),
            ));
        }
    };

    let set_name = DataPersistence::normalise_set_name(payload.set_name.as_deref())
        .map_err(responses::persistence_error_to_http)?;

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;

    let mut history = session::session_history(&session.session_id);

    if pair_index >= history.len() {
        return Ok(responses::json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "pair_index out of range"}),
        ));
    }

    let (stored_user, stored_assistant) = &history[pair_index];
    if stored_user.trim() != trimmed || stored_assistant.trim() != ai_trimmed {
        return Ok(responses::json_response(
            StatusCode::CONFLICT,
            json!({"status": "error", "error": "content mismatch at pair_index"}),
        ));
    }

    history.remove(pair_index);

    session::update_session_history(&session.session_id, &history);

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
            .map_err(responses::persistence_error_to_http)?;
    }

    Ok(responses::json_response(StatusCode::OK, json!({"status": "success"})))
}
