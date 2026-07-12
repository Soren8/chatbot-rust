//! HTTP middleware for production request rate limiting.

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chatbot_core::{config::app_config, rate_limit, session};
use serde_json::json;

use crate::chat_utils::get_ip;

const LIMITED_PATHS: &[&str] = &[
    "/chat",
    "/regenerate",
    "/tts",
    "/tts_stream",
    "/stt",
    "/api/tts",
    "/api/tts/stream",
    "/signup",
    "/login",
];

fn path_is_limited(path: &str) -> bool {
    LIMITED_PATHS.iter().any(|prefix| {
        path == *prefix || path.starts_with(&format!("{prefix}/"))
    })
}

fn client_key(request: &Request<Body>) -> String {
    let cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());

    if let Some(identity) = session::rate_limit_identity(cookie) {
        return identity;
    }

    format!("ip:{}", get_ip(request.headers(), request.extensions()))
}

pub async fn middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !path_is_limited(&path) {
        return next.run(request).await;
    }

    let config = app_config();
    let per_user = config.rate_limit_per_user_per_minute;
    let global = config.rate_limit_global_per_minute;
    if per_user == 0 && global == 0 {
        return next.run(request).await;
    }

    let key = client_key(&request);
    match rate_limit::check(&key, per_user, global) {
        Ok(()) => next.run(request).await,
        Err(exceeded) => {
            let message = match exceeded.scope {
                rate_limit::RateLimitScope::PerUser => {
                    "Rate limit exceeded for this user. Please try again later."
                }
                rate_limit::RateLimitScope::Global => {
                    "Server is busy (global rate limit). Please try again later."
                }
            };
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": message,
                    "retry_after": exceeded.retry_after_secs,
                })),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&exceeded.retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    }
}
