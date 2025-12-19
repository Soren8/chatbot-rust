use axum::{
    body::{self, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    session,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize, Default)]
struct SetNameRequest {
    #[serde(default)]
    set_name: Option<String>,
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
                StatusCode::FORBIDDEN,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;
    let sets = persistence
        .list_sets(username)
        .map_err(persistence_error_to_http)?;

    let payload = serde_json::to_value(sets).map_err(|err| {
        error!(?err, "failed to serialize sets map");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response serialization failed".to_string(),
        )
    })?;

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
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /create_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;

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
                StatusCode::FORBIDDEN,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

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

    match persistence.create_set(username, &set_name) {
        Ok(_) => build_json_response(StatusCode::OK, json!({"status": "success"})),
        Err(PersistenceError::InvalidSetName) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Set already exists or invalid name"
            }),
        ),
        Err(err) => Err(persistence_error_to_http(err)),
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
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /delete_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;

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
                StatusCode::FORBIDDEN,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;
    let set_name = match DataPersistence::normalise_set_name(Some(&set_name_raw)) {
        Ok(value) => value,
        Err(_) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "status": "error",
                    "error": "invalid set name"
                }),
            );
        }
    };

    match persistence.delete_set(username, &set_name) {
        Ok(()) => build_json_response(StatusCode::OK, json!({"status": "success"})),
        Err(PersistenceError::InvalidSetName) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Cannot delete set"
            }),
        ),
        Err(err) => Err(persistence_error_to_http(err)),
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
        SetNameRequest::default()
    } else {
        serde_json::from_slice::<SetNameRequest>(&body_bytes).map_err(|err| {
            error!(?err, "invalid JSON payload for /load_set");
            (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
        })?
    };

    let set_name_raw = payload.set_name.unwrap_or_default();

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(cookie_header.as_deref(), csrf_token)?;

    let persistence = DataPersistence::new().map_err(persistence_error_to_http)?;

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
                StatusCode::FORBIDDEN,
                json!({"error": "Not authenticated"}),
            );
        }
    };

    let set_name = match DataPersistence::normalise_set_name(Some(&set_name_raw)) {
        Ok(value) => value,
        Err(_) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid request"}),
            );
        }
    };

    let encryption_mode = session
        .encryption_key
        .as_ref()
        .map(|key| EncryptionMode::Fernet(key.as_slice()));

    let loaded = match persistence.load_set(username, &set_name, encryption_mode) {
        Ok(value) => value,
        Err(PersistenceError::MissingEncryptionKey) => {
            return build_json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "relogin required"}),
            );
        }
        Err(PersistenceError::InvalidSetName) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid request"}),
            );
        }
        Err(err) => return Err(persistence_error_to_http(err)),
    };

    session::update_session_memory(&session.session_id, &loaded.memory);
    session::update_session_system_prompt(&session.session_id, &loaded.system_prompt);
    session::update_session_history(&session.session_id, &loaded.history);

    let history_json = loaded
        .history
        .iter()
        .map(|(user, assistant)| json!([user, assistant]))
        .collect::<Vec<_>>();

    build_json_response(
        StatusCode::OK,
        json!({
            "memory": loaded.memory,
            "system_prompt": loaded.system_prompt,
            "history": history_json,
            "encrypted": loaded.encrypted
        }),
    )
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
        return Err((StatusCode::BAD_REQUEST, "Invalid or missing CSRF token".to_string()));
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
