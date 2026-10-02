//! Search result truncation boundaries.
//!
//! Given oversized Brave results, when chat streams a search-assisted answer,
//! then truncation must not panic on UTF-8 boundaries and must mark clipping.

mod common;

use std::sync::{Mutex, OnceLock};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn set_chunks(chunks: &[&str]) {
    let owned: Vec<String> = chunks.iter().map(|s| s.to_string()).collect();
    std::env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", serde_json::to_string(&owned).unwrap());
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app.clone().oneshot(Request::builder().method(Method::GET).uri("/").body(Body::empty()).unwrap()).await.expect("GET /");
    let set_cookie = response.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).expect("session cookie").to_owned();
    let body = to_bytes(response.into_body(), 256 * 1024).await.expect("home body");
    let csrf = CSRF_META_RE.captures(std::str::from_utf8(&body).expect("utf8"))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned())).expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf)
}

async fn post_chat(app: &Router, cookie: &str, csrf: &str) -> (StatusCode, String) {
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/chat")
        .header(header::CONTENT_TYPE, "application/json").header("X-CSRF-Token", csrf)
        .header(header::COOKIE, cookie).body(Body::from(serde_json::to_vec(&json!({
            "message": "What is the weather today?", "set_name": "default",
            "model_name": "default", "web_search": true,
        })).unwrap())).unwrap()).await.expect("POST /chat");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.expect("chat body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn search_chat(results: String) -> (StatusCode, String) {
    std::env::set_var("SECRET_KEY", "search_truncation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    std::env::set_var("BRAVE_API_KEY", "test-brave-key");
    std::env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "weather today");
    std::env::set_var("CHATBOT_TEST_BRAVE_RESULTS", results);
    set_chunks(&["The final answer."]);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;
    let result = post_chat(&app, &cookie, &csrf).await;
    for key in ["BRAVE_API_KEY", "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "CHATBOT_TEST_BRAVE_RESULTS", "CHATBOT_TEST_OPENAI_CHUNKS"] {
        std::env::remove_var(key);
    }
    result
}

#[tokio::test]
async fn truncating_multibyte_search_result_does_not_panic() {
    let _guard = test_mutex().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let results = format!("{}{}", "a".repeat(7_999), "é".repeat(10));
    let (status, body) = search_chat(results).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<think>Search complete.</think>"), "search completion marker missing: {body}");
    assert!(body.contains("The final answer."), "final answer chunk missing: {body}");
}

#[tokio::test]
async fn long_ascii_search_result_completes_chat() {
    let _guard = test_mutex().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (status, body) = search_chat("a".repeat(8_010)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<think>Search complete.</think>"));
    assert!(body.contains("The final answer."));
}
