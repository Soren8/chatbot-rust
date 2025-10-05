use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn regenerate_endpoint_streams_response() {
    if !common::ensure_flask_available() {
        eprintln!("skipping regenerate_endpoint_streams_response: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());

    bridge::initialize_python().expect("python bridge init");

    Python::with_gil(|py| {
        let code = std::ffi::CString::new(
            r#"
from app.config import Config

Config.LLM_PROVIDERS = [{
    'provider_name': 'default',
    'type': 'openai',
    'model_name': 'gpt-test',
    'base_url': 'https://api.openai.com/v1',
    'api_key': 'test-key',
    'context_size': 4096,
}]
Config.DEFAULT_LLM = Config.LLM_PROVIDERS[0]
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, None)
            .expect("configure openai provider");
    });

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

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["initial chunk".to_string()]).expect("chunk json"),
    );

    let chat_payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
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
                .body(Body::from(
                    serde_json::to_vec(&chat_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "regen chunk 1".to_string(),
            "<think>hidden</think>".to_string(),
            "regen final".to_string(),
        ])
        .expect("chunk json"),
    );

    let regen_payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let regen_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(
                    serde_json::to_vec(&regen_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate response");

    assert_eq!(regen_response.status(), StatusCode::OK);
    let content_type = regen_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );

    let body_bytes = to_bytes(regen_response.into_body(), 512 * 1024)
        .await
        .expect("read regenerate body");
    let body_text = std::str::from_utf8(&body_bytes).expect("regen utf8");

    assert!(body_text.contains("regen chunk 1"));
    assert!(body_text.contains("regen final"));

    let error_indicators = [
        "Error: bridge error",
        "Failed to load resource",
        "500 (Internal Server Error)",
        "Internal Server Error",
        "[Error]",
        "Traceback",
    ];

    for indicator in error_indicators {
        assert!(
            !body_text.contains(indicator),
            "regenerate returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    let error_count = chatbot_server::test_instrumentation::take_error_count();
    assert_eq!(
        error_count, 0,
        "server emitted {} HTTP 5xx responses",
        error_count
    );

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}
