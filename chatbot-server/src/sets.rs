use axum::{
    body::{self, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{
    history::{HistoryError, HistoryService, SetId, SetVersion},
    persistence::DataPersistence,
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize, Default)]
struct SetRequest {
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
}

#[derive(Deserialize)]
struct RenameSetRequest {
    #[serde(default)]
    old_name: Option<String>,
    #[serde(default)]
    new_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
}

pub async fn handle_get_sets(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::GET {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only GET allowed".to_string(),
        ));
    }

    let cookie_header = extract_cookie(request.headers());
    let encryption_key = crate::chat_utils::extract_enc_key(request.headers());

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for get_sets");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let username = match session.username.as_deref() {
        Some(value) => value,
        None => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    if let Err(response) =
        session::validate_encryption_key_for_user(username, encryption_key.as_ref())
    {
        return build_service_response(response);
    }
    let key = encryption_key.as_ref().expect("validated encryption key");

    let history = HistoryService::global().map_err(history_error_to_http)?;
    // Ensure at least default exists for new accounts
    if history.list_sets(username, key).map_err(history_error_to_http)?.is_empty() {
        history
            .ensure_default_set(username, key)
            .map_err(history_error_to_http)?;
    }

    let sets = history.list_sets(username, key).map_err(history_error_to_http)?;
    let payload = json!(sets
        .into_iter()
        .map(|s| {
            json!({
                "set_id": s.set_id.to_string(),
                "name": s.display_name,
                "version": s.version.get(),
                "modified": (s.updated_at as f64) / 1000.0,
                "created": (s.updated_at as f64) / 1000.0,
                "is_default": s.is_default,
                "encrypted": true
            })
        })
        .collect::<Vec<_>>());

    build_json_response(StatusCode::OK, payload)
}

pub async fn handle_create_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /create_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /create_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for create_set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let username = match session.username.as_deref() {
        Some(value) => value,
        None => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    if let Err(response) =
        session::validate_encryption_key_for_user(username, encryption_key.as_ref())
    {
        return build_service_response(response);
    }
    let key = encryption_key.as_ref().expect("validated encryption key");

    let set_name = match DataPersistence::normalise_custom_set_name(&set_name_raw) {
        Ok(value) => value,
        Err(_) => {
            return build_json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Set already exists or invalid name"
                }),
            );
        }
    };

    let history = HistoryService::global().map_err(history_error_to_http)?;
    match history.create_set(username, &set_name, key) {
        Ok(summary) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "set_id": summary.set_id.to_string(),
                "name": summary.display_name,
                "version": summary.version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Set already exists or invalid name"
            }),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_delete_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /delete_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /delete_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for delete_set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let username = match session.username.as_deref() {
        Some(value) => value,
        None => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    if let Err(response) =
        session::validate_encryption_key_for_user(username, encryption_key.as_ref())
    {
        return build_service_response(response);
    }
    let key = encryption_key.as_ref().expect("validated encryption key");
    let history = HistoryService::global().map_err(history_error_to_http)?;

    let snap = match resolve_set(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.set_name.as_deref(),
        key,
    ) {
        Ok(s) => s,
        Err(err) => {
            return build_json_response(
                StatusCode::OK,
                json!({"status": "error", "error": err}),
            );
        }
    };

    if snap.is_default || snap.display_name == "default" {
        return build_json_response(
            StatusCode::OK,
            json!({"status": "error", "error": "Cannot delete set"}),
        );
    }

    let expected = payload
        .expected_version
        .map(SetVersion)
        .unwrap_or(snap.version);

    match history.delete_set(username, snap.set_id, expected, key) {
        Ok(()) => build_json_response(StatusCode::OK, json!({"status": "success"})),
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "set_id": snap.set_id.to_string(),
                "current_version": current_version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({"status": "error", "error": "Cannot delete set"}),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_rename_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /rename_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: RenameSetRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload for /rename_set");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for rename_set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let username = match session.username.as_deref() {
        Some(value) => value,
        None => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    if let Err(response) =
        session::validate_encryption_key_for_user(username, encryption_key.as_ref())
    {
        return build_service_response(response);
    }
    let key = encryption_key.as_ref().expect("validated encryption key");
    let new_name_raw = payload.new_name.unwrap_or_default();
    let new_name = match DataPersistence::normalise_custom_set_name(&new_name_raw) {
        Ok(v) => v,
        Err(_) => {
            return build_json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Invalid set name or set already exists"
                }),
            );
        }
    };

    let history = HistoryService::global().map_err(history_error_to_http)?;
    let snap = match resolve_set(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.old_name.as_deref(),
        key,
    ) {
        Ok(s) => s,
        Err(_) => {
            return build_json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Invalid set name or set already exists"
                }),
            );
        }
    };

    let expected = payload
        .expected_version
        .map(SetVersion)
        .unwrap_or(snap.version);

    match history.rename_set(username, snap.set_id, expected, &new_name, key) {
        Ok(version) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "set_id": snap.set_id.to_string(),
                "name": new_name,
                "version": version.get(),
            }),
        ),
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "set_id": snap.set_id.to_string(),
                "current_version": current_version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Invalid set name or set already exists"
            }),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_load_set(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024).await.map_err(|err| {
        error!(?err, "failed to read /load_set body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /load_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;
    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session context for load_set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let username = match session.username.as_deref() {
        Some(value) => value,
        None => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    if let Err(response) =
        session::validate_encryption_key_for_user(username, encryption_key.as_ref())
    {
        return build_service_response(response);
    }
    let key = encryption_key.as_ref().expect("validated encryption key");
    let history = HistoryService::global().map_err(history_error_to_http)?;

    let loaded = match resolve_set(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.set_name.as_deref(),
        key,
    ) {
        Ok(s) => s,
        Err(msg) => {
            return build_json_response(StatusCode::BAD_REQUEST, json!({"error": msg}));
        }
    };

    // Keep session cache in sync for the loaded set only (keyed by set_id).
    if let Err(response) = session::replace_session_set(
        &session.session_id,
        Some(username),
        Some(loaded.set_id),
        &loaded.memory,
        &loaded.system_prompt,
        &loaded.history,
        true,
        encryption_key.as_ref(),
    ) {
        return build_service_response(response);
    }

    let history_json = loaded
        .history
        .iter()
        .map(|(user, assistant)| json!([user, assistant]))
        .collect::<Vec<_>>();

    build_json_response(
        StatusCode::OK,
        json!({
            "set_id": loaded.set_id.to_string(),
            "name": loaded.display_name,
            "version": loaded.version.get(),
            "memory": loaded.memory,
            "system_prompt": loaded.system_prompt,
            "history": history_json,
            "encrypted": true,
            "is_default": loaded.is_default,
        }),
    )
}

fn resolve_set(
    history: &HistoryService,
    username: &str,
    set_id: Option<&str>,
    set_name: Option<&str>,
    key: &chatbot_core::enc_key::EncryptionKey,
) -> Result<chatbot_core::history::SetSnapshot, &'static str> {
    if let Some(id_str) = set_id.filter(|s| !s.trim().is_empty()) {
        let id = SetId::parse(id_str).map_err(|_| "invalid set_id")?;
        return history
            .load(username, id, key)
            .map_err(|_| "set not found");
    }
    let name = set_name.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("default");
    match history.find_by_display_name(username, name, key) {
        Ok(Some(snap)) => Ok(snap),
        Ok(None) if name == "default" => history
            .ensure_default_set(username, key)
            .map_err(|_| "set not found"),
        Ok(None) => Err("set not found"),
        Err(_) => Err("set not found"),
    }
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
        error!(?err, "failed to validate CSRF token for sets endpoint");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or missing CSRF token".to_string(),
        ));
    }

    Ok(())
}

fn history_error_to_http(err: HistoryError) -> (StatusCode, String) {
    match err {
        HistoryError::MissingKey | HistoryError::DecryptFailed => (
            StatusCode::UNAUTHORIZED,
            "Encryption key required. Please unlock.".to_string(),
        ),
        HistoryError::NotFound => (StatusCode::NOT_FOUND, "set not found".to_string()),
        HistoryError::Conflict { current_version } => (
            StatusCode::CONFLICT,
            format!("version_conflict:{}", current_version.get()),
        ),
        HistoryError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.to_string()),
        HistoryError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
        HistoryError::Internal => {
            error!("internal history error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "history store error".to_string(),
            )
        }
    }
}

fn build_service_response(
    response: session::ServiceResponse,
) -> Result<Response<Body>, (StatusCode, String)> {
    crate::build_response(response).map_err(|(status, message)| (status, message))
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
