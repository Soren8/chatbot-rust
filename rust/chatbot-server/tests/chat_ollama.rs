use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

const OLLAMA_CONFIG: &str = r#"
llms:
  - provider_name: "ollama-test"
    type: "ollama"
    model_name: "dolphin"
    base_url: "http://localhost:11434"
    context_size: 4096
    test_chunks:
      - "hello from rust ollama "
      - "<think>ollama-plan</think>"
      - "final rust chunk"

default_llm: "ollama-test"
"#;

#[tokio::test]
async fn chat_endpoint_streams_via_rust_ollama() {
    if !common::ensure_flask_available() {
        eprintln!("skipping chat_endpoint_streams_via_rust_ollama: flask not available");
        return;
    }

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_config(OLLAMA_CONFIG);

    bridge::initialize_python().expect("python bridge init");

    env::set_var(
        "CHATBOT_TEST_OLLAMA_CHUNKS",
        serde_json::to_string(&[
            "hello from rust ollama ",
            "<think>ollama-plan</think>",
            "final rust chunk",
        ])
        .expect("serialize ollama chunks"),
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
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();

    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "ollama-test",
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let content_type = chat_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.to_lowercase().starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");

    for indicator in ["[Error]", "bridge error", "Traceback"] {
        assert!(
            !body_text.contains(indicator),
            "chat response contained unexpected error indicator '{indicator}': {body_text}"
        );
    }

    assert!(body_text.contains("hello from rust ollama "));
    assert!(body_text.contains("<think>ollama-plan</think>"));
    assert!(body_text.contains("final rust chunk"));

    env::remove_var("CHATBOT_TEST_OLLAMA_CHUNKS");
}
