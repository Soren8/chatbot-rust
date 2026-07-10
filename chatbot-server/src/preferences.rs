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
use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_session_err, map_user_store_err,
    HttpError,
};

#[derive(Deserialize)]
struct UpdatePreferencesRequest {
    last_set: Option<String>,
    last_model: Option<String>,
    render_markdown: Option<bool>,
    autoplay_tts: Option<bool>,
}

pub async fn handle_update_preferences(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 1024)
        .await
        .map_err(|err| map_body_read_err(err, "preferences::post"))?;

    let payload: UpdatePreferencesRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "preferences::post"))?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let valid_csrf = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "preferences::post::csrf"))?;

    if !valid_csrf {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid CSRF token"));
    }

    let session = session::session_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "preferences::post::session"))?;

    if let Some(username) = session.username {
        let mut store = UserStore::new().map_err(|err| {
            map_user_store_err(err, "preferences::post::open_store", "store error")
        })?;

        store
            .update_user_preferences(
                &username,
                payload.last_set,
                payload.last_model,
                payload.render_markdown,
                payload.autoplay_tts,
            )
            .map_err(|err| {
                map_user_store_err(err, "preferences::post::update", "store error")
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