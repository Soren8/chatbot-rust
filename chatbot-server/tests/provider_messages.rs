//! Characterization of the shared provider message DTO (MOD-007 messages).
//!
//! Given a guest `/chat` request against an OpenAI-compatible provider, when
//! the server forwards core messages upstream, then the captured
//! `/chat/completions` body must carry the shared shape: roles preserved,
//! user turns as multimodal `text`/`image_url` parts, system and assistant
//! turns as plain strings, unset fields omitted, and the request envelope
//! (`model`/`stream`/`temperature` with no `provider`/`tools`/`tool_choice`)
//! unchanged. The XAI `input_text`/`input_image` projection of the same
//! shared types is already pinned by `generation_dispatch.rs` and is not
//! duplicated here. No production stub was added; the mock is test-only.

mod common;

use std::{
    env,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    routing::post,
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn clear_message_env() {
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("XAI_API_KEY");
}

fn openai_config(base_url: &str) -> String {
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "{base_url}"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
"#
    )
}

async fn spawn_openai_mock(
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>,
    hits: std::sync::Arc<AtomicUsize>,
    delta: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let delta = delta.to_owned();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(payload): axum::Json<Value>| {
            let captured = captured.clone();
            let hits = hits.clone();
            let delta = delta.clone();
            async move {
                captured.lock().await.push(payload);
                hits.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{delta}\"}}}}]}}\n\ndata: [DONE]\n\n"
                );
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind openai mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

async fn guest_session(app: &Router) -> (String, String) {
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
        .expect("session cookie")
        .to_owned();
    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("utf8");
    let csrf_token = CSRF_META_RE
        .captures(body_text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf_token)
}

async fn post_chat(app: &Router, cookie: &str, csrf: &str, payload: Value) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("chat body");
    (
        status,
        std::str::from_utf8(&body_bytes).unwrap().to_owned(),
    )
}

fn fresh_capture() -> (
    std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>,
    std::sync::Arc<AtomicUsize>,
) {
    (
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        std::sync::Arc::new(AtomicUsize::new(0)),
    )
}

#[tokio::test]
async fn user_text_request_uses_multimodal_text_part_and_envelope() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let (captured, hits) = fresh_capture();
    let (mock_addr, mock_handle) = spawn_openai_mock(captured.clone(), hits.clone(), "hi").await;

    clear_message_env();
    env::set_var("SECRET_KEY", "provider_messages_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello upstream",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_message_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hi"), "expected mock delta, got: {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let payload = payloads.first().expect("captured payload");
    assert_eq!(payload["model"], "gpt-test");
    assert_eq!(payload["stream"], true);
    assert_eq!(payload["temperature"], 0.7);
    assert!(payload.get("provider").is_none());
    assert!(payload.get("tools").is_none());
    assert!(payload.get("tool_choice").is_none());

    let messages = payload["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "system");
    // No explicit prompt: the configured default system prompt is sent first
    // as a plain string.
    assert!(
        messages[0]["content"].as_str().is_some_and(|s| !s.is_empty()),
        "default system prompt must be a plain string, got: {:?}",
        messages[0]["content"]
    );
    assert!(messages[0].get("tool_calls").is_none());
    assert!(messages[0].get("tool_call_id").is_none());
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(
        messages[1]["content"],
        json!([{"type": "text", "text": "Hello upstream"}])
    );
    assert!(messages[1].get("tool_calls").is_none());
    assert!(messages[1].get("tool_call_id").is_none());
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn image_marker_request_uses_text_plus_image_url_parts() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let (captured, hits) = fresh_capture();
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), "saw it").await;

    clear_message_env();
    env::set_var("SECRET_KEY", "provider_messages_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Look at this: [IMAGE:data:image/png;base64,abc123]",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_message_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("saw it"), "expected mock delta, got: {body}");

    let payload = payloads.first().expect("captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "system");
    assert!(
        messages[0]["content"].as_str().is_some_and(|s| !s.is_empty()),
        "default system prompt must be a plain string, got: {:?}",
        messages[0]["content"]
    );
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(
        messages[1]["content"],
        json!([
            {"type": "text", "text": "Look at this:"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc123"}},
        ])
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn system_prompt_request_uses_plain_string_system_message() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let (captured, hits) = fresh_capture();
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), "noted").await;

    clear_message_env();
    env::set_var("SECRET_KEY", "provider_messages_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello upstream",
            "set_name": "default",
            "model_name": "default",
            "system_prompt": "You are a test oracle",
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_message_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("noted"), "expected mock delta, got: {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let payload = payloads.first().expect("captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], "You are a test oracle");
    assert!(messages[0].get("tool_calls").is_none());
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(
        messages[1]["content"],
        json!([{"type": "text", "text": "Hello upstream"}])
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn second_turn_assistant_history_uses_plain_string() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let (captured, hits) = fresh_capture();
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), "first answer").await;

    clear_message_env();
    env::set_var("SECRET_KEY", "provider_messages_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (first_status, first_body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "first question",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    assert!(
        first_body.contains("first answer"),
        "expected mock delta, got: {first_body}"
    );

    let (second_status, second_body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "second question",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_message_env();

    assert_eq!(second_status, StatusCode::OK);
    assert!(
        second_body.contains("first answer"),
        "expected mock delta, got: {second_body}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    let payload = payloads.last().expect("second captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    let assistant = messages
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history in second request");
    assert_eq!(assistant["content"], "first answer");
    assert!(assistant.get("tool_calls").is_none());
    assert!(assistant.get("tool_call_id").is_none());
    for user in messages.iter().filter(|m| m["role"] == "user") {
        assert!(
            user["content"].is_array(),
            "user turns stay multimodal, got: {user:?}"
        );
    }
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}
