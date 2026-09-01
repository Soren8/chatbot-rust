use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::{remember_store, session};
use crate::http_error::{
    log_and_api_error, map_response_build_err, map_session_err, HttpError,
};

pub async fn handle_logout(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let headers = request.headers();
    let ip = crate::chat_utils::get_ip(headers, request.extensions());
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let username = session::session_context(cookie_header.as_deref())
        .ok()
        .and_then(|ctx| ctx.username)
        .unwrap_or_else(|| "guest".to_string());

    let finalize = session::logout_user(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "logout::post"))?;

    // Explicit logout revokes this device's remember token (and clears the
    // cookie even when no valid token was presented).
    if let Err(err) = revoke_remember_token(cookie_header.as_deref()) {
        tracing::warn!(?err, "failed to revoke remember token on logout");
    }

    tracing::info!(username = %username, ip = %ip, "Logout successful");

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/"));

    let set_cookie = HeaderValue::from_str(&finalize.set_cookie).map_err(|err| {
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error",
            "logout::post::set_cookie",
            err,
        )
    })?;

    builder = builder.header(header::SET_COOKIE, set_cookie);

    if let Ok(value) = HeaderValue::from_str(&remember_store::build_clear_cookie()) {
        builder = builder.header(header::SET_COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&crate::chat_utils::build_enc_key_clear_cookie()) {
        builder = builder.header(header::SET_COOKIE, value);
    }

    builder
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "logout::post::response"))
}

fn revoke_remember_token(cookie_header: Option<&str>) -> Result<(), remember_store::RememberError> {
    let store = remember_store::RememberStore::new()?;
    store.revoke(remember_store::extract_token(cookie_header).as_deref());
    Ok(())
}