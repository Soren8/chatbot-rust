//! Characterization of shared generation dispatch (MOD-007).
//!
//! Given a chat or regenerate request, when provider construction, message
//! mapping and search-gated streaming run, then both handlers must stream
//! the same search tool/direct/disabled/no-Brave behavior, render stream
//! errors without persisting, and map multimodal content. XAI native
//! dispatch is observed through a local mock Responses API; no production
//! test stub was added.

mod common;

use std::{
    env,
    fs,
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
use bcrypt::{hash, DEFAULT_COST};
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

fn clear_generation_env() {
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("XAI_API_KEY");
}

fn set_chunks(chunks: &[&str]) {
    let owned: Vec<String> = chunks.iter().map(|s| s.to_string()).collect();
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&owned).unwrap(),
    );
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

async fn post_regenerate(
    app: &Router,
    cookie: &str,
    csrf: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate");
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("regenerate body");
    (
        status,
        std::str::from_utf8(&body_bytes).unwrap().to_owned(),
    )
}

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
}

fn seed_user(workspace_path: &std::path::Path, username: &str, password: &str) {
    let hashed = hash(password, DEFAULT_COST).expect("hash");
    fs::write(
        workspace_path.join("users.json"),
        serde_json::to_string_pretty(&json!({
            username: { "password": hashed, "tier": "free" }
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn login_user(app: &Router, username: &str, password: &str) -> AuthCtx {
    let login_page = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    let mut cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("cookie");
    let body = to_bytes(login_page.into_body(), 128 * 1024).await.unwrap();
    let csrf_login =
        common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).expect("csrf");

    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf_login),
    );
    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    if let Some(v) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024).await.unwrap();

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    if let Some(v) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).unwrap())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf meta");
    let enc_key = common::derive_encryption_key_header(username, password);
    AuthCtx {
        cookie,
        csrf,
        enc_key,
    }
}

async fn load_set_by_name(app: &Router, auth: &AuthCtx, name: &str) -> Value {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": name})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 512 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn xai_config(base_url: &str, xai_search: bool) -> String {
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "xai"
    model_name: "grok-test"
    base_url: "{base_url}"
    api_key: "${{XAI_API_KEY}}"
    context_size: 4096
    xai_search: {xai_search}
"#
    )
}

async fn spawn_xai_mock(
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>,
    hits: std::sync::Arc<AtomicUsize>,
    delta: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let delta = delta.to_owned();
    let app = Router::new().route(
        "/v1/responses",
        post(move |axum::Json(payload): axum::Json<Value>| {
            let captured = captured.clone();
            let hits = hits.clone();
            let delta = delta.clone();
            async move {
                captured.lock().await.push(payload);
                hits.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    "data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{delta}\"}}\n\ndata: {{\"type\":\"response.completed\"}}\n\ndata: [DONE]\n\n"
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
        .expect("bind xai mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

#[tokio::test]
async fn chat_search_tool_streams_search_markers_and_final_answer() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "weather today");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "Atlanta: 72F, sunny");
    set_chunks(&["The weather is nice today."]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "What is the weather today?",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
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
        0
    );
}

#[tokio::test]
async fn regenerate_search_tool_streams_search_markers_and_final_answer() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    set_chunks(&["initial chunk"]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "What is the weather today?",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "weather today");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "Atlanta: 72F, sunny");
    set_chunks(&["Regenerated forecast."]);

    let (status, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "What is the weather today?",
            "set_name": "default",
            "model_name": "default",
            "pair_index": 0,
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<think>Searching for: weather today...</think>"),
        "expected search think tag, got: {body}"
    );
    assert!(
        body.contains("<think>Search complete.</think>"),
        "expected search complete tag, got: {body}"
    );
    assert!(
        body.contains("Regenerated forecast."),
        "expected regenerated answer chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_search_direct_streams_without_search_markers() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Direct answer while search is enabled."]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "direct answer must not emit search status, got: {body}"
    );
    assert!(
        body.contains("Direct answer while search is enabled."),
        "expected direct stream content, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_search_direct_streams_without_search_markers() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    set_chunks(&["initial chunk"]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Regenerated direct answer."]);

    let (status, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "pair_index": 0,
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "direct regenerate must not emit search status, got: {body}"
    );
    assert!(
        body.contains("Regenerated direct answer."),
        "expected direct stream content, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_search_disabled_ignores_tool_request() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var(
        "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY",
        "should not be called",
    );
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Direct answer."]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": false,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "disabled search must not run, got: {body}"
    );
    assert!(
        body.contains("Direct answer."),
        "expected regular stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_search_disabled_ignores_tool_request() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    set_chunks(&["initial chunk"]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var(
        "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY",
        "should not be called",
    );
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Regenerated without search."]);

    let (status, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "pair_index": 0,
            "web_search": false,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "disabled regenerate search must not run, got: {body}"
    );
    assert!(
        body.contains("Regenerated without search."),
        "expected regular stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_search_without_brave_key_falls_back_to_direct() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Regular answer without search."]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "no search tags expected without Brave key, got: {body}"
    );
    assert!(
        body.contains("Regular answer without search."),
        "expected fallback stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_search_without_brave_key_falls_back_to_direct() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    set_chunks(&["initial chunk"]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    set_chunks(&["Regenerated without Brave."]);

    let (status, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "pair_index": 0,
            "web_search": true,
        }),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<think>Searching"),
        "no search tags expected without Brave key, got: {body}"
    );
    assert!(
        body.contains("Regenerated without Brave."),
        "expected fallback stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_stream_error_renders_clean_error_and_persists_nothing() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "gen_dispatch_err", "GenDispatch1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "gen_dispatch_err", "GenDispatch1!").await;

    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["partial","__STREAM_ERROR__"]"#);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "should-not-save",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&body).to_string();
    clear_generation_env();

    assert!(
        text.contains("[Error] Injected test stream error by backend LLM provider."),
        "client must see a clean error message, got: {text}"
    );
    assert!(
        text.contains("[ConsoleError]"),
        "full error chain must reach the console marker, got: {text}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    assert_eq!(
        loaded["history"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "failed stream must not append history"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_stream_error_preserves_original_pair() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "gen_dispatch_regen_err", "GenRegenErr1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "gen_dispatch_regen_err", "GenRegenErr1!").await;

    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["initial"]"#);
    let chat_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "Initial prompt",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(chat_res.status(), StatusCode::OK);
    let _ = to_bytes(chat_res.into_body(), 512 * 1024).await.unwrap();

    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["partial","__STREAM_ERROR__"]"#);
    let regen_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "Initial prompt",
                        "set_name": "default",
                        "pair_index": 0
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(regen_res.status(), StatusCode::OK);
    let regen_body = to_bytes(regen_res.into_body(), 512 * 1024).await.unwrap();
    let regen_text = String::from_utf8_lossy(&regen_body).to_string();
    clear_generation_env();

    assert!(
        regen_text.contains("[Error]"),
        "regenerate error must render a saved-turn style error, got: {regen_text}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 1, "failed regenerate must keep one pair");
    assert_eq!(history[0][0], "Initial prompt");
    assert!(
        history[0][1].as_str().unwrap().contains("initial"),
        "original assistant text must be preserved, got: {}",
        history[0][1]
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_xai_native_search_dispatches_to_responses_with_tool() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) =
        spawn_xai_mock(captured.clone(), hits.clone(), "hello xai").await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    env::set_var("XAI_API_KEY", "test-key");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&xai_config(&base_url, true));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    let hit_count = hits.load(Ordering::SeqCst);
    mock_handle.abort();
    clear_generation_env();
    env::remove_var("XAI_API_KEY");

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("hello xai"),
        "expected mock XAI delta, got: {body}"
    );
    assert_eq!(hit_count, 1, "native search must hit the Responses API once");
    let payload = payloads.first().expect("captured XAI payload");
    let tools = payload["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1, "native search must request one tool");
    assert_eq!(tools[0]["type"], "web_search");
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_xai_native_search_dispatches_to_responses_with_tool() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) =
        spawn_xai_mock(captured.clone(), hits.clone(), "regen xai").await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    env::set_var("XAI_API_KEY", "test-key");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&xai_config(&base_url, true));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
        }),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    let (status, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "pair_index": 0,
            "web_search": true,
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_generation_env();
    env::remove_var("XAI_API_KEY");

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("regen xai"),
        "expected mock XAI delta on regenerate, got: {body}"
    );
    assert!(
        payloads.len() >= 2,
        "chat plus regenerate must both hit Responses API, got {}",
        payloads.len()
    );
    let regen_payload = payloads.last().expect("regen payload");
    let tools = regen_payload["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["type"], "web_search");
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_xai_brave_search_uses_openai_compatible_tool_path() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) =
        spawn_xai_mock(captured.clone(), hits.clone(), "should not be used").await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    env::set_var("XAI_API_KEY", "test-key");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&xai_config(&base_url, false));
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "weather today");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "Atlanta: 72F, sunny");
    set_chunks(&["Brave answer via XAI."]);

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "What is the weather today?",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    let hit_count = hits.load(Ordering::SeqCst);
    mock_handle.abort();
    clear_generation_env();
    env::remove_var("XAI_API_KEY");

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<think>Searching for: weather today...</think>"),
        "XAI Brave path must emit search think tag, got: {body}"
    );
    assert!(
        body.contains("Brave answer via XAI."),
        "expected Brave final answer, got: {body}"
    );
    assert_eq!(
        hit_count, 0,
        "Brave path must not hit the native Responses API"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_xai_without_brave_key_falls_back_to_native() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) =
        spawn_xai_mock(captured.clone(), hits.clone(), "native fallback").await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    env::set_var("XAI_API_KEY", "test-key");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&xai_config(&base_url, false));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        json!({
            "message": "Hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": true,
        }),
    )
    .await;

    let payloads = captured.lock().await.clone();
    let hit_count = hits.load(Ordering::SeqCst);
    mock_handle.abort();
    clear_generation_env();
    env::remove_var("XAI_API_KEY");

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("native fallback"),
        "expected native mock delta, got: {body}"
    );
    assert_eq!(hit_count, 1);
    let payload = payloads.first().expect("captured payload");
    assert_eq!(payload["tools"].as_array().unwrap().len(), 1);
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_xai_multimodal_image_maps_to_input_image() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) =
        spawn_xai_mock(captured.clone(), hits.clone(), "saw image").await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_dispatch_secret");
    env::set_var("XAI_API_KEY", "test-key");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&xai_config(&base_url, true));

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
    clear_generation_env();
    env::remove_var("XAI_API_KEY");

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("saw image"), "expected mock delta, got: {body}");

    let payload = payloads.first().expect("captured payload");
    let messages = payload["input"].as_array().expect("input messages");
    let user = messages
        .iter()
        .rev()
        .find(|m| m["role"] == "user")
        .expect("user message in XAI input");
    let content = user["content"].as_array().expect("multimodal content");
    assert!(
        content
            .iter()
            .any(|p| p["type"] == "input_text"
                && p["text"].as_str().unwrap().contains("Look at this:")),
        "text part must map to input_text, got: {content:?}"
    );
    assert!(
        content.iter().any(|p| p["type"] == "input_image"
            && p["image_url"] == "data:image/png;base64,abc123"),
        "image marker must map to input_image, got: {content:?}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}
