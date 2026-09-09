//! Client log ingestion: PII sanitization contract and route authorization.

mod common;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, client_logs, resolve_static_root};
use chatbot_test_support::TestWorkspace;
use tower::ServiceExt;

fn test_config() -> String {
    r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
tts_provider: kokoro
"#
    .to_string()
}

#[test]
fn sanitizer_redacts_emails_ips_and_tokens() {
    common::init_tracing();

    let email = client_logs::sanitize_client_log_line("failed for alice@example.com at login");
    assert!(email.contains("[EMAIL]"), "email must be redacted: {email}");
    assert!(!email.contains("alice@example.com"));

    let ip = client_logs::sanitize_client_log_line("connect 192.168.1.55 refused");
    assert!(ip.contains("[IP]"), "ipv4 must be redacted: {ip}");
    assert!(!ip.contains("192.168.1.55"));

    let hex = client_logs::sanitize_client_log_line(
        "GET /tts_stream/5da8f308f00ace67e09c6b96f21271de failed",
    );
    assert!(
        hex.contains("[HEX]"),
        "long hex tokens (tts/session/csrf) must be redacted: {hex}"
    );
    assert!(!hex.contains("5da8f308f00ace67"));

    let bearer = client_logs::sanitize_client_log_line("auth: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
    assert!(
        bearer.contains("[REDACTED]") && !bearer.contains("eyJhbGciOiJIUzI1NiJ9"),
        "bearer credentials must be redacted: {bearer}"
    );

    let secret = client_logs::sanitize_client_log_line("request sent cookie: session=abcdef0123456789abcdef; ok");
    assert!(
        !secret.contains("abcdef0123456789abcdef"),
        "cookie values must be redacted: {secret}"
    );

    let query = client_logs::sanitize_client_log_line("GET /login?next=/chat&token=supersecretvalue1 retry");
    assert!(
        !query.contains("supersecretvalue1"),
        "URL query strings must be redacted: {query}"
    );

    // Readable content survives: words, numbers, and structure stay intact.
    let plain = client_logs::sanitize_client_log_line("STT codec fallback: reason=insecure-context bytes=48000");
    assert_eq!(plain, "STT codec fallback: reason=insecure-context bytes=48000");
}

#[test]
fn sanitizer_truncates_overlong_lines() {
    common::init_tracing();
    let long = "x".repeat(4000);
    let out = client_logs::sanitize_client_log_line(&long);
    assert!(
        out.chars().count() <= chatbot_server::client_logs::MAX_LINE_CHARS + "…[truncated]".len(),
        "lines must be truncated"
    );
}

async fn session_cookie_from_home(
    app: &axum::Router,
) -> String {
    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();
    common::extract_cookie(&set_cookie)
}

#[tokio::test]
async fn client_logs_accept_live_session_cookie_without_csrf() {
    common::init_tracing();
    let _workspace = TestWorkspace::with_config(&test_config());
    let app = build_router(resolve_static_root());

    let cookie = session_cookie_from_home(&app).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/client_logs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    r#"{"source":"android","lines":["CRASH: uncaught at NativeVoiceTts","STT codec fallback: reason=no-webcodecs"]}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("POST /client_logs");

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "a live session cookie must authorize log ingestion without a CSRF header"
    );
}

#[tokio::test]
async fn client_logs_reject_unknown_sessions() {
    common::init_tracing();
    let _workspace = TestWorkspace::with_config(&test_config());
    let app = build_router(resolve_static_root());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/client_logs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"lines":["hello"]}"#))
                .unwrap(),
        )
        .await
        .expect("POST /client_logs without cookie");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "no session cookie -> reject; do not accept anonymous log spam"
    );
}
