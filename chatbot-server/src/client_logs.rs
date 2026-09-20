use axum::{
    body::{self, Body},
    http::{Method, Request, Response, StatusCode},
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_response_build_err, map_session_err,
    HttpError,
};
use crate::identity::RequestIdentity;

const MAX_LOG_BODY_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 64;
pub const MAX_LINE_CHARS: usize = 512;

static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("email regex"));

static IPV4_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("ipv4 regex"));

// Long hex runs: session ids, TTS tokens, CSRF tokens, remember secrets.
static HEX_TOKEN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[0-9a-fA-F]{16,}\b").expect("hex token regex"));

// Long opaque runs (base64 / JWT-ish / signed values) without spaces.
static OPAQUE_TOKEN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/_=\-]{40,}").expect("opaque token regex"));

static BEARER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+").expect("bearer regex"));

// Credential-bearing key=value pairs (cookies, tokens, keys) — keep the key,
// redact the value.
static SECRET_ASSIGNMENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)((?:x-)?(?:csrf-token|enc-key|enc_key[a-z0-9_-]*)|remember[a-z0-9_-]*|session|cookie|token|authorization)\s*[:=]\s*("[^"]*"|[^\s;,)"']+)"#)
        .expect("secret assignment regex")
});

// Query strings on URLs can carry tokens (?token=..., ?csrf=...).
static URL_QUERY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\?[^\s"'<>]{8,}"#).expect("url query regex"));

/// Scrub PII / credentials from one client log line before it reaches the
/// server log. Keep it conservative and readable: named placeholders so the
/// redaction itself is visible, and truncate overly long lines.
pub fn sanitize_client_log_line(input: &str) -> String {
    let mut line = String::from(input);

    line = BEARER_REGEX.replace_all(&line, "[REDACTED]").into_owned();
    line = SECRET_ASSIGNMENT_REGEX
        .replace_all(&line, "$1=[REDACTED]")
        .into_owned();
    line = URL_QUERY_REGEX.replace_all(&line, "?[REDACTED]").into_owned();
    line = EMAIL_REGEX.replace_all(&line, "[EMAIL]").into_owned();
    line = IPV4_REGEX.replace_all(&line, "[IP]").into_owned();
    line = HEX_TOKEN_REGEX.replace_all(&line, "[HEX]").into_owned();
    line = OPAQUE_TOKEN_REGEX.replace_all(&line, "[REDACTED]").into_owned();

    if line.chars().count() > MAX_LINE_CHARS {
        line = line.chars().take(MAX_LINE_CHARS).collect();
        line.push_str("…[truncated]");
    }
    line
}

#[derive(Debug, Deserialize)]
struct ClientLogPayload {
    #[serde(default)]
    lines: Vec<String>,
    #[serde(default)]
    source: Option<String>,
}

pub async fn handle_client_logs(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let identity = RequestIdentity::from_extensions(&parts.extensions);
    let cookie_header = crate::request_context::extract_cookie(&parts.headers);
    let csrf_token = crate::request_context::extract_csrf(&parts.headers);

    // Log-only endpoint: no state mutation. The native reporter cannot obtain
    // the page's CSRF token, so a live session cookie is accepted as
    // authorization when no CSRF header is presented; a presented CSRF token
    // must still validate. Rate limiting applies (route is in LIMITED_PATHS).
    // The throttling identity also accepts presented-but-unknown cookies.
    let authorized = match csrf_token {
        Some(token) => identity
            .validate_csrf_token(cookie_header.as_deref(), Some(token))
            .map_err(|err| map_session_err(err, "client_logs::csrf"))?,
        None => identity.rate_limit_identity(cookie_header.as_deref()).is_some(),
    };
    if !authorized {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Invalid or missing session",
        ));
    }

    let body_bytes = body::to_bytes(body, MAX_LOG_BODY_BYTES)
        .await
        .map_err(|err| map_body_read_err(err, "client_logs::post"))?;

    let payload: ClientLogPayload = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "client_logs::post"))?;

    let source = payload
        .source
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "client".to_string());

    // The client is expected to sanitize before upload; this is defense in
    // depth so credentials/PII never reach the host log even from a careless
    // reporter. Warn level: these payloads ship only on errors and crashes.
    for line in payload.lines.iter().take(MAX_LINES) {
        tracing::warn!(
            source = %source,
            client_log = %sanitize_client_log_line(line),
            "client log"
        );
    }

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "client_logs::post"))
}
