use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::session;
use tracing::error;

pub async fn handle_logout(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
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

    let finalize = session::logout_user(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to perform logout");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    tracing::info!(username = %username, ip = %ip, "Logout successful");

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/"));

    let set_cookie = HeaderValue::from_str(&finalize.set_cookie).map_err(|err| {
        error!(?err, "invalid Set-Cookie header from logout");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    builder = builder.header(header::SET_COOKIE, set_cookie);

    builder.body(Body::empty()).map_err(|err| {
        error!(?err, "failed to build logout response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
}
