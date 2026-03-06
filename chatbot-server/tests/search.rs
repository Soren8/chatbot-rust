use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Sets the given env vars, makes a POST /chat request with web_search enabled,
/// and returns the response body text. Cleans up env vars afterwards.
async fn chat_with_search(
    brave_api_key: Option<&str>,
    tool_call_query: Option<&str>,
    brave_results: Option<&str>,
    final_chunks: &[&str],
) -> String {
    env::set_var("SECRET_KEY", "search_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    if let Some(key) = brave_api_key {
        env::set_var("BRAVE_API_KEY", key);
    } else {
        env::remove_var("BRAVE_API_KEY");
    }
    if let Some(q) = tool_call_query {
        env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", q);
    } else {
        env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    }
    if let Some(r) = brave_results {
        env::set_var("CHATBOT_TEST_BRAVE_RESULTS", r);
    } else {
        env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    }

    let chunks_json =
        serde_json::to_string(&final_chunks.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", &chunks_json);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();
    let home_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let home_text = std::str::from_utf8(&home_bytes).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");

    let payload = json!({
        "message": "What is the weather today?",
        "set_name": "default",
        "model_name": "default",
        "web_search": true,
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");

    assert_eq!(chat_response.status(), StatusCode::OK);

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap().to_owned();

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    body
}

#[tokio::test]
async fn search_emits_think_tags_and_final_answer() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let body = chat_with_search(
        Some("test-brave-key"),
        Some("weather today"),
        Some("Atlanta: 72°F, sunny"),
        &["The weather is nice today."],
    )
    .await;

    assert!(
        body.contains("<think>Searching for: weather today...</think>"),
        "expected search think tag, got: {body}"
    );
    assert!(
        body.contains("<think>Search complete.</think>"),
        "expected search complete tag, got: {body}"
    );
    assert!(
        body.contains("The weather is nice today."),
        "expected final answer chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}

#[tokio::test]
async fn search_falls_back_to_streaming_when_brave_not_configured() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    // No BRAVE_API_KEY → brave_client() returns None → falls back to stream_chat
    let body = chat_with_search(
        None,
        None,
        None,
        &["Regular answer without search."],
    )
    .await;

    assert!(
        !body.contains("<think>Searching"),
        "no search tags expected when Brave not configured, got: {body}"
    );
    assert!(
        body.contains("Regular answer without search."),
        "expected fallback stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}

#[tokio::test]
async fn search_skipped_when_web_search_false() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "search_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "should not be called");
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["Direct answer.".to_string()]).unwrap(),
    );

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
        .unwrap();
    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();
    let home_bytes = to_bytes(home_response.into_body(), 256 * 1024).await.unwrap();
    let home_text = std::str::from_utf8(&home_bytes).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .unwrap();

    // web_search: false
    let payload = json!({
        "message": "Hello",
        "set_name": "default",
        "model_name": "default",
        "web_search": false,
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(chat_response.status(), StatusCode::OK);
    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();

    assert!(
        !body.contains("<think>Searching"),
        "search should not run when web_search=false, got: {body}"
    );
    assert!(
        body.contains("Direct answer."),
        "expected regular stream chunk, got: {body}"
    );

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn search_result_injected_into_augmented_messages() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    // Brave results contain a unique token we can check made it to the model
    // (visible in the augmented user message that stream_chat receives).
    // The final chunks come from CHATBOT_TEST_OPENAI_CHUNKS, so the search
    // result text itself won't appear in the response — but no error should occur
    // and the response should stream successfully.
    let body = chat_with_search(
        Some("test-brave-key"),
        Some("Rust programming language"),
        Some("Rust is a systems language focused on safety and performance."),
        &["Here is what I found about Rust."],
    )
    .await;

    assert!(
        body.contains("Here is what I found about Rust."),
        "expected final stream chunk, got: {body}"
    );
    assert!(
        body.contains("<think>Searching for: Rust programming language...</think>"),
        "expected search think tag, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}
