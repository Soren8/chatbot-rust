use axum::{
    body::{self, Body},
    http::{Request, Response, StatusCode},
};
use chatbot_core::user_store::UserStore;
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{auth::Session as AuthSession, responses};

#[derive(Deserialize)]
struct UpdatePreferencesRequest {
    last_set: Option<String>,
    last_model: Option<String>,
    render_markdown: Option<bool>,
    autoplay_tts: Option<bool>,
}

pub async fn handle_update_preferences(
    AuthSession(session): AuthSession,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    responses::ensure_post(request.method())?;

    let (_, body) = request.into_parts();

    let body_bytes = body::to_bytes(body, 1024).await.map_err(|err| {
        error!(?err, "failed to read body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: UpdatePreferencesRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    if let Some(username) = session.username {
        let mut store = UserStore::new().map_err(|err| {
            error!(?err, "failed to open user store");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".to_string())
        })?;

        store.update_user_preferences(&username, payload.last_set, payload.last_model, payload.render_markdown, payload.autoplay_tts).map_err(|err| {
            error!(?err, "failed to update preferences");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".to_string())
        })?;
    }

    Ok(responses::json_response(StatusCode::OK, json!({ "status": "success" })))
}
