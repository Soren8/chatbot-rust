//! Request-transport parsing: cookie, CSRF header, and client IP helpers
//! plus the `/chat` vs `/client_logs` CSRF authorization difference.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Extensions, HeaderMap, HeaderValue, Method, Request, StatusCode},
};
use chatbot_server::{
    build_router,
    request_context::{extract_cookie, extract_cookie_ref, extract_csrf, get_ip},
    resolve_static_root,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use tower::ServiceExt;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn extensions_with_loopback() -> Extensions {
    let mut extensions = Extensions::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    extensions.insert(ConnectInfo(addr));
    extensions
}

#[test]
fn extract_cookie_returns_none_when_header_absent() {
    let headers = HeaderMap::new();

    assert_eq!(extract_cookie(&headers), None);
    assert_eq!(extract_cookie_ref(&headers), None);
}

#[test]
fn extract_cookie_returns_owned_value_when_present() {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, "session=abc".parse().unwrap());

    assert_eq!(
        extract_cookie(&headers).as_deref(),
        Some("session=abc")
    );
    assert_eq!(extract_cookie_ref(&headers), Some("session=abc"));
}

#[test]
fn extract_cookie_returns_empty_string_when_header_empty() {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_static(""));

    assert_eq!(extract_cookie(&headers).as_deref(), Some(""));
    assert_eq!(extract_cookie_ref(&headers), Some(""));
}

#[test]
fn extract_cookie_returns_none_for_malformed_utf8() {
    let mut headers = HeaderMap::new();
    let malformed = HeaderValue::from_bytes(&[0xff]).expect("obs-text header value");
    headers.insert(header::COOKIE, malformed);

    assert_eq!(extract_cookie(&headers), None);
    assert_eq!(extract_cookie_ref(&headers), None);
}

#[test]
fn extract_cookie_uses_first_value_when_duplicated() {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, "session=first".parse().unwrap());
    headers.append(header::COOKIE, "session=second".parse().unwrap());

    assert_eq!(
        extract_cookie(&headers).as_deref(),
        Some("session=first")
    );
    assert_eq!(extract_cookie_ref(&headers), Some("session=first"));
}

#[test]
fn extract_csrf_returns_none_when_header_absent() {
    let headers = HeaderMap::new();

    assert_eq!(extract_csrf(&headers), None);
}

#[test]
fn extract_csrf_returns_borrowed_value_when_present() {
    let mut headers = HeaderMap::new();
    headers.insert("X-CSRF-Token", "token-123".parse().unwrap());

    assert_eq!(extract_csrf(&headers), Some("token-123"));
}

#[test]
fn extract_csrf_returns_none_for_malformed_utf8() {
    let mut headers = HeaderMap::new();
    let malformed = HeaderValue::from_bytes(&[0xff]).expect("obs-text header value");
    headers.insert("X-CSRF-Token", malformed);

    assert_eq!(extract_csrf(&headers), None);
}

#[test]
fn extract_csrf_uses_first_value_when_duplicated() {
    let mut headers = HeaderMap::new();
    headers.insert("X-CSRF-Token", "first".parse().unwrap());
    headers.append("X-CSRF-Token", "second".parse().unwrap());

    assert_eq!(extract_csrf(&headers), Some("first"));
}

#[test]
fn get_ip_trims_first_xff_entry() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "  10.0.0.1  , 10.0.0.2".parse().unwrap());

    assert_eq!(get_ip(&headers, &Extensions::new()), "10.0.0.1");
}

#[test]
fn get_ip_empty_xff_takes_precedence_over_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "   ".parse().unwrap());
    headers.insert("X-Real-IP", "10.0.0.2".parse().unwrap());

    assert_eq!(get_ip(&headers, &Extensions::new()), "");
}

#[test]
fn get_ip_uses_first_xff_value_when_duplicated() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "10.0.0.9".parse().unwrap());
    headers.append("X-Forwarded-For", "10.0.0.10".parse().unwrap());

    assert_eq!(get_ip(&headers, &Extensions::new()), "10.0.0.9");
}

#[test]
fn get_ip_falls_back_to_real_ip_when_xff_malformed() {
    let mut headers = HeaderMap::new();
    let malformed = HeaderValue::from_bytes(&[0xff]).expect("obs-text header value");
    headers.insert("X-Forwarded-For", malformed);
    headers.insert("X-Real-IP", "10.0.0.2".parse().unwrap());

    assert_eq!(get_ip(&headers, &Extensions::new()), "10.0.0.2");
}

#[test]
fn get_ip_returns_unknown_when_no_info() {
    let headers = HeaderMap::new();

    assert_eq!(get_ip(&headers, &Extensions::new()), "unknown");
}

#[test]
fn get_ip_prefers_xff_over_real_ip_and_connect_info() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "10.0.0.1, 10.0.0.2".parse().unwrap());
    headers.insert("X-Real-IP", "10.0.0.2".parse().unwrap());

    assert_eq!(get_ip(&headers, &extensions_with_loopback()), "10.0.0.1");
}

#[test]
fn chat_utils_get_ip_reexport_matches_request_context() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "  10.0.0.7 , 10.0.0.8".parse().unwrap());

    assert_eq!(
        chatbot_server::chat_utils::get_ip(&headers, &Extensions::new()),
        get_ip(&headers, &Extensions::new())
    );
}

fn test_config() -> String {
    r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
"#
    .to_string()
}

async fn session_cookie(app: &axum::Router) -> String {
    let home = app
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
    let set_cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();
    chatbot_test_support::extract_cookie(&set_cookie)
}

#[tokio::test]
async fn route_csrf_difference_chat_requires_token_while_client_logs_accepts_session() {
    let _guard = test_mutex().lock().unwrap();
    chatbot_test_support::init_tracing();
    let _workspace = chatbot_test_support::TestWorkspace::with_config(&test_config());
    let app = build_router(resolve_static_root());

    let cookie = session_cookie(&app).await;

    let chat = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap(),
        )
        .await
        .expect("POST /chat without CSRF");
    assert_eq!(
        chat.status(),
        StatusCode::UNAUTHORIZED,
        "standard routes must still reject a session cookie without a CSRF token"
    );

    let logs = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/client_logs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(r#"{"lines":["hello"]}"#))
                .unwrap(),
        )
        .await
        .expect("POST /client_logs without CSRF");
    assert_eq!(
        logs.status(),
        StatusCode::NO_CONTENT,
        "client_logs must still accept a live session cookie without a CSRF header"
    );
}

#[tokio::test]
async fn client_logs_rejects_presented_invalid_csrf() {
    let _guard = test_mutex().lock().unwrap();
    chatbot_test_support::init_tracing();
    let _workspace = chatbot_test_support::TestWorkspace::with_config(&test_config());
    let app = build_router(resolve_static_root());

    let cookie = session_cookie(&app).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/client_logs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", "bogus-token")
                .body(Body::from(r#"{"lines":["hello"]}"#))
                .unwrap(),
        )
        .await
        .expect("POST /client_logs with invalid CSRF");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a presented CSRF token on client_logs must still validate"
    );
}
