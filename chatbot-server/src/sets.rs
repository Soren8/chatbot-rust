use axum::{
    body::{self, Body},
    http::{Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{auth::RequireUser, responses};

#[derive(Deserialize, Default)]
struct SetNameRequest {
    #[serde(default)]
    set_name: Option<String>,
}

#[derive(Deserialize)]
struct RenameSetRequest {
    old_name: String,
    new_name: String,
}

pub async fn handle_get_sets(
    RequireUser(session): RequireUser,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_get(request.method())?;

    let username = session.username.as_deref().expect("RequireUser ensures username");

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;
    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    let sets = persistence
        .list_sets(username, encryption_mode)
        .map_err(responses::persistence_error_to_http)?;

    let mut sets_vec: Vec<(String, chatbot_core::persistence::SetMetadata)> = sets.into_iter().collect();
    sets_vec.sort_by(|a, b| b.1.modified.partial_cmp(&a.1.modified).unwrap_or(std::cmp::Ordering::Equal));

    let payload = json!(sets_vec.into_iter().map(|(name, meta)| {
        json!({
            "name": name,
            "created": meta.created,
            "modified": meta.modified,
            "encrypted": meta.encrypted
        })
    }).collect::<Vec<_>>());

    Ok(responses::json_response(StatusCode::OK, payload))
}

pub async fn handle_create_set(
    RequireUser(session): RequireUser,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /create_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /create_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let username = session.username.as_deref().expect("RequireUser ensures username");

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;
    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    let set_name = match DataPersistence::normalise_custom_set_name(&set_name_raw) {
        Ok(value) => value,
        Err(_) => {
            return Ok(responses::json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Set already exists or invalid name"
                }),
            ));
        }
    };

    match persistence.create_set(username, &set_name, encryption_mode) {
        Ok(_) => Ok(responses::json_response(StatusCode::OK, json!({"status": "success"}))),
        Err(PersistenceError::InvalidSetName) => Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Set already exists or invalid name"
            }),
        )),
        Err(err) => Err(responses::persistence_error_to_http(err)),
    }
}

pub async fn handle_delete_set(
    RequireUser(session): RequireUser,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /delete_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /delete_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let username = session.username.as_deref().expect("RequireUser ensures username");

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;
    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    let set_name = match DataPersistence::normalise_set_name(Some(&set_name_raw)) {
        Ok(value) => value,
        Err(_) => {
            return Ok(responses::json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "status": "error",
                    "error": "invalid set name"
                }),
            ));
        }
    };

    match persistence.delete_set(username, &set_name, encryption_mode) {
        Ok(()) => Ok(responses::json_response(StatusCode::OK, json!({"status": "success"}))),
        Err(PersistenceError::InvalidSetName) => Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Cannot delete set"
            }),
        )),
        Err(err) => Err(responses::persistence_error_to_http(err)),
    }
}

pub async fn handle_rename_set(
    RequireUser(session): RequireUser,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /rename_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: RenameSetRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload for /rename_set");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let username = session.username.as_deref().expect("RequireUser ensures username");

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;
    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    match persistence.rename_set(username, &payload.old_name, &payload.new_name, encryption_mode) {
        Ok(()) => Ok(responses::json_response(StatusCode::OK, json!({"status": "success"}))),
        Err(PersistenceError::InvalidSetName) => Ok(responses::json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Invalid set name or set already exists"
            }),
        )),
        Err(err) => Err(responses::persistence_error_to_http(err)),
    }
}

pub async fn handle_load_set(
    RequireUser(session): RequireUser,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /load_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /load_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let persistence = DataPersistence::new().map_err(responses::persistence_error_to_http)?;

    let username = session.username.as_deref().expect("RequireUser ensures username");

    let set_name = match DataPersistence::normalise_set_name(Some(&set_name_raw)) {
        Ok(value) => value,
        Err(_) => {
            return Ok(responses::json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid request"}),
            ));
        }
    };

    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    let loaded = match persistence.load_set(username, &set_name, encryption_mode) {
        Ok(value) => value,
        Err(PersistenceError::MissingEncryptionKey) => {
            return Ok(responses::json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "relogin required"}),
            ));
        }
        Err(PersistenceError::InvalidSetName) => {
            return Ok(responses::json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid request"}),
            ));
        }
        Err(err) => return Err(responses::persistence_error_to_http(err)),
    };

    session::update_session_memory(&session.session_id, &loaded.memory);
    session::update_session_system_prompt(&session.session_id, &loaded.system_prompt);
    session::update_session_history(&session.session_id, &loaded.history);

    let history_json = loaded
        .history
        .iter()
        .map(|(user, assistant)| json!([user, assistant]))
        .collect::<Vec<_>>();

    Ok(responses::json_response(
        StatusCode::OK,
        json!({
            "memory": loaded.memory,
            "system_prompt": loaded.system_prompt,
            "history": history_json,
            "encrypted": loaded.encrypted
        }),
    ))
}
