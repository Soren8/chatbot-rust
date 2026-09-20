use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use crate::http_error::{
    log_and_api_error, map_response_build_err, map_session_err, HttpError,
};
use crate::services::AppServices;

pub async fn handle_logout(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let identity = services.identity().clone();
    let headers = request.headers();
    let ip = crate::request_context::get_ip(headers, request.extensions());
    let cookie_header = crate::request_context::extract_cookie(headers);

    let username = identity
        .session_context(cookie_header.as_deref())
        .ok()
        .and_then(|ctx| ctx.username)
        .unwrap_or_else(|| "guest".to_string());

    let finalize = identity
        .logout_user(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "logout::post"))?;

    tracing::info!(username = %username, ip = %ip, "Logout successful");

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/login"));

    let set_cookie = HeaderValue::from_str(&finalize.set_cookie).map_err(|err| {
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error",
            "logout::post::set_cookie",
            err,
        )
    })?;

    builder = builder.header(header::SET_COOKIE, set_cookie);

    // Single emit resolves CSRF once, like the original per-build read.
    if let Ok(value) = HeaderValue::from_str(
        &crate::chat_utils::build_enc_key_clear_cookie_with_csrf(
            services.config_source().csrf(),
        ),
    ) {
        builder = builder.header(header::SET_COOKIE, value);
    }

    builder
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "logout::post::response"))
}