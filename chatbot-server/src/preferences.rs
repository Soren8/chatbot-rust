use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    session,
    user_store::UserStore,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize)]
struct UpdatePreferencesRequest {
    last_set: Option<String>,
    last_model: Option<String>,
    render_markdown: Option<bool>,
}

pub async fn handle_update_preferences(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != axum::http::Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 1024).await.map_err(|err| {
        error!(?err, "failed to read body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: UpdatePreferencesRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let valid_csrf = session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
        error!(?err, "failed to validate CSRF");
        (StatusCode::INTERNAL_SERVER_ERROR, "session error".to_string())
    })?;

    if !valid_csrf {
        return Err((StatusCode::UNAUTHORIZED, "Invalid CSRF token".to_string()));
    }

    let session = session::session_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to obtain session");
        (StatusCode::INTERNAL_SERVER_ERROR, "session error".to_string())
    })?;

    if let Some(username) = session.username {
        let mut store = UserStore::new().map_err(|err| {
            error!(?err, "failed to open user store");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".to_string())
        })?;

        store.update_user_preferences(&username, payload.last_set, payload.last_model, payload.render_markdown).map_err(|err| {
            error!(?err, "failed to update preferences");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".to_string())
        })?;
    }

    let response = json!({ "status": "success" });
    let body = serde_json::to_vec(&response).unwrap();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap())
}
