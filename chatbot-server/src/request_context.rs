//! Bounded request-transport extraction.
//!
//! Raw HTTP header parsing only: `Cookie` / `X-CSRF-Token` / client IP.
//! No session lookup, no CSRF validation, no auth decisions, no logging.

use axum::{
    extract::ConnectInfo,
    http::{header, Extensions, HeaderMap},
};
use std::net::SocketAddr;

/// Owned `Cookie` header value (`None` when absent or malformed UTF-8).
pub fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    extract_cookie_ref(headers).map(|s| s.to_owned())
}

/// Borrowed `Cookie` header value (`None` when absent or malformed UTF-8).
///
/// Exists so borrowed call sites (rate-limit identity) keep zero-copy
/// semantics instead of being forced through the owned adapter.
pub fn extract_cookie_ref(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
}

/// Borrowed `X-CSRF-Token` header value (`None` when absent or malformed UTF-8).
pub fn extract_csrf(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
}

pub fn get_ip(headers: &HeaderMap, extensions: &Extensions) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}
