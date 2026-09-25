//! Baseline characterization for MOD003 generation dependency ownership.
//!
//! Given a `/chat` or `/regenerate` request, when provider selection,
//! model-error ordering, thought persistence/forwarding, and search gating
//! resolve through live global configuration, then both handlers must share
//! one observable contract: omitted/empty models backfill to the configured
//! default, unknown/unsupported models return a direct 400 for empty messages
//! and a 200 saved error turn otherwise, `save_thoughts` controls persisted
//! history but never the stream, and `send_thoughts` controls upstream
//! history forwarding.
//!
//! These tests pin the current global-config behavior that the later narrow
//! `GenerationDeps` owner must preserve: an explicit provider map plus
//! default plus save/send-thoughts plus Brave key, with lazy live-global
//! compatibility. No config schema changes, no freezing of production config,
//! exact constructor/search error messages and prepare ordering preserved.
//! Read-only exploration recommends a concrete owned dependency, not a
//! provider trait.
//!
//! Fixture pattern: `TestWorkspace` serialized config plus env
//! (`CHATBOT_TEST_*`, `BRAVE_API_KEY`), actual HTTP assertions via
//! `build_router`. No real secrets, live config, or `data/` reads.
//!
//! Already pinned elsewhere and not duplicated here:
//! - `generation_dispatch.rs` (15 tests): OpenAI search tool/direct/disabled/
//!   no-Brave on chat and regenerate, stream-error no-persist on chat and
//!   preserved-original on regenerate, XAI native on chat/regenerate, XAI
//!   Brave on chat, XAI no-Brave native fallback, XAI multimodal image.
//! - `search.rs` (5 tests): OpenAI search overlap for `/chat`.
//! - `data_request_context_boundary::model_error_still_saved_as_200_before_invalid_key`:
//!   chat unknown-model nonempty 200 wins over an invalid key.
//! - `generation_lease_boundary::chat_unknown_model_saves_error_turn_without_holding_lock`:
//!   chat unknown-model nonempty saves an error turn and releases the lock.
//! - `prepare_validation_boundary::{chat,regenerate}_empty_message_returns_raw400`:
//!   empty-message validation 400 shape and saved-turn versus raw-400 helpers.
//! - Core `chat::prepare_chat_messages_strips_thinking_when_disabled`: the
//!   `send_thoughts` packing rule itself (HTTP wiring is pinned here via mock
//!   capture).
//!
//! Deferred to the next turn (needs the explicit owner): two-router isolation.
//! No two-router tests here; separate `GenerationDeps` per router must later
//! isolate the provider map, default, thought flags, and Brave key.

mod common;

use std::{
    env, fs,
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

use chatbot_core::{config::ProviderConfig, session_identity::HttpSessionStore};
use chatbot_server::{
    build_router_with_services, generation_deps::GenerationDeps, identity::RequestIdentity,
    services::AppServices,
};
use std::collections::HashMap;
use std::sync::Arc;

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
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::remove_var("XAI_API_KEY");
}

fn set_chunks(chunks: &[&str]) {
    let owned: Vec<String> = chunks.iter().map(|s| s.to_string()).collect();
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&owned).unwrap(),
    );
}

const TWO_PROVIDER_CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    test_chunks: ["from-default-marker-aaa"]
  - provider_name: "second"
    type: "openai"
    model_name: "gpt-second"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    test_chunks: ["from-second-marker-bbb"]
"#;

const TWO_PROVIDER_WITH_DEFAULT_LLM_CONFIG: &str = r#"
default_llm: "second"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    test_chunks: ["from-default-marker-aaa"]
  - provider_name: "second"
    type: "openai"
    model_name: "gpt-second"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
    test_chunks: ["from-second-marker-bbb"]
"#;

const STUB_MIXED_CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
  - provider_name: "legacy"
    type: "stub"
    model_name: "stub-model"
    base_url: "https://example.test/v1"
    context_size: 4096
"#;

const SAVE_FALSE_CONFIG: &str = r#"
save_thoughts: false
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
"#;

fn openai_mock_config(base_url: &str) -> String {
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

fn openai_mock_config_with_send_true(base_url: &str) -> String {
    format!(
        r#"
send_thoughts: true
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

async fn post_chat(
    app: &Router,
    cookie: &str,
    csrf: &str,
    enc_key: Option<&str>,
    payload: Value,
) -> (StatusCode, String, String) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf)
        .header(header::COOKIE, cookie);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("chat body");
    (
        status,
        content_type,
        std::str::from_utf8(&body_bytes).unwrap().to_owned(),
    )
}

async fn post_regenerate(
    app: &Router,
    cookie: &str,
    csrf: &str,
    enc_key: Option<&str>,
    payload: Value,
) -> (StatusCode, String, String) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/regenerate")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf)
        .header(header::COOKIE, cookie);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("regenerate body");
    (
        status,
        content_type,
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
    let csrf_login = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).expect("csrf");

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

fn fresh_capture() -> (
    std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>,
    std::sync::Arc<AtomicUsize>,
) {
    (
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        std::sync::Arc::new(AtomicUsize::new(0)),
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

#[tokio::test]
async fn chat_omitted_model_uses_first_provider_by_default() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(TWO_PROVIDER_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/plain"),
        "expected stream content-type, got {content_type}"
    );
    assert!(
        body.contains("from-default-marker-aaa"),
        "omitted model must use the first provider, got: {body}"
    );
    assert!(
        !body.contains("from-second-marker-bbb"),
        "omitted model must not reach the second provider, got: {body}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_empty_model_uses_first_provider_by_default() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(TWO_PROVIDER_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, _, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": ""}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("from-default-marker-aaa"),
        "empty model must backfill to the first provider, got: {body}"
    );
    assert!(
        !body.contains("from-second-marker-bbb"),
        "empty model must not reach the second provider, got: {body}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_explicit_second_model_uses_second_provider() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(TWO_PROVIDER_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, _, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": "second"}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("from-second-marker-bbb"),
        "explicit second model must use the second provider, got: {body}"
    );
    assert!(
        !body.contains("from-default-marker-aaa"),
        "explicit second model must not use the default provider, got: {body}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_omitted_model_uses_default_llm_when_configured() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(TWO_PROVIDER_WITH_DEFAULT_LLM_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, _, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("from-second-marker-bbb"),
        "omitted model must follow default_llm, got: {body}"
    );
    assert!(
        !body.contains("from-default-marker-aaa"),
        "default_llm must win over list order, got: {body}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn regenerate_omitted_model_uses_first_provider_by_default() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(TWO_PROVIDER_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (chat_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    let (status, _, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "Hello", "set_name": "default", "pair_index": 0}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("from-default-marker-aaa"),
        "regenerate without a model must share the chat default, got: {body}"
    );
    assert!(
        !body.contains("from-second-marker-bbb"),
        "regenerate default must not reach the second provider, got: {body}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_unknown_model_empty_message_returns_direct400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "", "model_name": "no-such-model"}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        content_type.contains("application/json"),
        "direct model error must be JSON, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&body).expect("400 body must be JSON");
    assert_eq!(payload, json!({"error": "requested model not found"}));
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn regenerate_unknown_model_whitespace_returns_direct400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "   ", "model_name": "no-such-model", "pair_index": 0}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        content_type.contains("application/json"),
        "direct model error must be JSON, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&body).expect("400 body must be JSON");
    assert_eq!(payload, json!({"error": "requested model not found"}));
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn regenerate_unknown_model_nonempty_saves_error_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_regen_unknown", "ProvCfgRegen1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_regen_unknown", "ProvCfgRegen1!").await;

    set_chunks(&["seed answer"]);
    let (first_status, _, _) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "first", "set_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    set_chunks(&["unused"]);
    let (status, content_type, body) = post_regenerate(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "second attempt", "set_name": "default", "model_name": "no-such-model", "pair_index": 0}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/plain"),
        "saved model error must stream as text, got {content_type}"
    );
    assert!(
        body.contains("requested model not found"),
        "regenerate must save the unknown-model error, got: {body}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 2);
    assert_eq!(history[1][0], "second attempt");
    assert!(
        history[1][1]
            .as_str()
            .unwrap()
            .contains("requested model not found"),
        "saved turn must carry the model error, got: {}",
        history[1][1]
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_unsupported_provider_nonempty_saves_error_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_config(STUB_MIXED_CONFIG);
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_stub_chat", "ProvCfgStub1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_stub_chat", "ProvCfgStub1!").await;

    set_chunks(&["seed answer"]);
    let (first_status, _, _) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "first", "set_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    set_chunks(&["unused"]);
    let (status, content_type, body) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "second attempt", "set_name": "default", "model_name": "legacy"}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/plain"),
        "saved provider error must stream as text, got {content_type}"
    );
    assert!(
        body.contains("unsupported provider type"),
        "chat must save the exact unsupported-type error, got: {body}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 2);
    assert_eq!(history[1][0], "second attempt");
    assert!(
        history[1][1]
            .as_str()
            .unwrap()
            .contains("unsupported provider type"),
        "saved turn must carry the provider error, got: {}",
        history[1][1]
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_unsupported_provider_empty_returns_direct400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(STUB_MIXED_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, body) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "", "model_name": "legacy"}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        content_type.contains("application/json"),
        "direct provider error must be JSON, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&body).expect("400 body must be JSON");
    assert_eq!(payload, json!({"error": "unsupported provider type"}));
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn regenerate_unsupported_provider_nonempty_saves_error_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_config(STUB_MIXED_CONFIG);
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_stub_regen", "ProvCfgStub2!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_stub_regen", "ProvCfgStub2!").await;

    set_chunks(&["seed answer"]);
    let (first_status, _, _) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "first", "set_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    set_chunks(&["unused"]);
    let (status, content_type, body) = post_regenerate(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "second attempt", "set_name": "default", "model_name": "legacy", "pair_index": 0}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/plain"),
        "saved provider error must stream as text, got {content_type}"
    );
    assert!(
        body.contains("unsupported provider type"),
        "regenerate must save the exact unsupported-type error, got: {body}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 2);
    assert!(
        history[1][1]
            .as_str()
            .unwrap()
            .contains("unsupported provider type"),
        "saved turn must carry the provider error, got: {}",
        history[1][1]
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn regenerate_unsupported_provider_whitespace_returns_direct400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_config(STUB_MIXED_CONFIG);
    clear_generation_env();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, body) = post_regenerate(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "   ", "model_name": "legacy", "pair_index": 0}),
    )
    .await;

    clear_generation_env();

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        content_type.contains("application/json"),
        "direct provider error must be JSON, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&body).expect("400 body must be JSON");
    assert_eq!(payload, json!({"error": "unsupported provider type"}));
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_save_thoughts_default_preserves_think_in_history() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_save_default", "ProvCfgSave1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_save_default", "ProvCfgSave1!").await;

    set_chunks(&["answer-start ", "<think>secret-plan</think>", " answer-end"]);
    let (status, _, body) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "hello", "set_name": "default"}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<think>secret-plan</think>"),
        "stream always carries raw thinking, got: {body}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 1);
    let assistant = history[0][1].as_str().expect("assistant text");
    assert!(
        assistant.contains("<think>secret-plan</think>"),
        "default save_thoughts=true must persist thinking, got: {assistant}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_save_thoughts_false_strips_think_on_persist_but_streams_raw() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_save_false", "ProvCfgSave2!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_save_false", "ProvCfgSave2!").await;

    set_chunks(&["answer-start ", "<think>secret-plan</think>", " answer-end"]);
    let (status, _, body) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "hello", "set_name": "default", "save_thoughts": false}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<think>secret-plan</think>"),
        "stream stays raw even when persistence strips, got: {body}"
    );

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    assert_eq!(history.len(), 1);
    let assistant = history[0][1].as_str().expect("assistant text");
    assert!(
        !assistant.contains("<think>") && !assistant.contains("secret-plan"),
        "save_thoughts=false must strip thinking on persist, got: {assistant}"
    );
    assert!(
        assistant.contains("answer-start") && assistant.contains("answer-end"),
        "visible answer text must persist, got: {assistant}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_save_thoughts_config_false_strips_by_default() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_config(SAVE_FALSE_CONFIG);
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_save_cfg", "ProvCfgSave3!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_save_cfg", "ProvCfgSave3!").await;

    set_chunks(&["answer-start ", "<think>secret-plan</think>", " answer-end"]);
    let (status, _, _) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "hello", "set_name": "default"}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    let assistant = history[0][1].as_str().expect("assistant text");
    assert!(
        !assistant.contains("<think>") && !assistant.contains("secret-plan"),
        "config save_thoughts=false must strip by default, got: {assistant}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_save_thoughts_true_overrides_config_false() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let workspace = common::TestWorkspace::with_config(SAVE_FALSE_CONFIG);
    clear_generation_env();
    seed_user(workspace.path(), "prov_cfg_save_override", "ProvCfgSave4!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "prov_cfg_save_override", "ProvCfgSave4!").await;

    set_chunks(&["answer-start ", "<think>secret-plan</think>", " answer-end"]);
    let (status, _, _) = post_chat(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(&auth.enc_key),
        json!({"message": "hello", "set_name": "default", "save_thoughts": true}),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let history = loaded["history"].as_array().expect("history array");
    let assistant = history[0][1].as_str().expect("assistant text");
    assert!(
        assistant.contains("<think>secret-plan</think>"),
        "explicit save_thoughts=true must win over config false, got: {assistant}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_send_thoughts_default_strips_think_upstream() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    let (captured, hits) = fresh_capture();
    let seed_delta = "first answer <think>secret-plan</think> tail";
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), seed_delta).await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_mock_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (first_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_generation_env();

    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let payload = payloads.last().expect("second captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    let assistant = messages
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history in second request");
    let content = assistant["content"]
        .as_str()
        .expect("assistant plain string");
    assert!(
        !content.contains("<think>") && !content.contains("secret-plan"),
        "default send_thoughts=false must strip thinking upstream, got: {content}"
    );
    assert!(
        content.contains("first answer") && content.contains("tail"),
        "visible history text must still forward, got: {content}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_send_thoughts_true_preserves_think_upstream() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    let (captured, hits) = fresh_capture();
    let seed_delta = "first answer <think>secret-plan</think> tail";
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), seed_delta).await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&openai_mock_config(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (first_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default", "send_thoughts": true}),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_generation_env();

    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let payload = payloads.last().expect("second captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    let assistant = messages
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history in second request");
    let content = assistant["content"]
        .as_str()
        .expect("assistant plain string");
    assert!(
        content.contains("<think>secret-plan</think>"),
        "explicit send_thoughts=true must forward thinking, got: {content}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn chat_send_thoughts_config_true_preserves_by_default() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    let (captured, hits) = fresh_capture();
    let seed_delta = "first answer <think>secret-plan</think> tail";
    let (mock_addr, mock_handle) =
        spawn_openai_mock(captured.clone(), hits.clone(), seed_delta).await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let _workspace =
        common::TestWorkspace::with_config(&openai_mock_config_with_send_true(&base_url));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (first_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (second_status, _, _) = post_chat(
        &app,
        &cookie,
        &csrf,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;

    let payloads = captured.lock().await.clone();
    mock_handle.abort();
    clear_generation_env();

    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let payload = payloads.last().expect("second captured payload");
    let messages = payload["messages"].as_array().expect("messages array");
    let assistant = messages
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history in second request");
    let content = assistant["content"]
        .as_str()
        .expect("assistant plain string");
    assert!(
        content.contains("<think>secret-plan</think>"),
        "config send_thoughts=true must forward by default, got: {content}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

fn test_provider_with_chunks(name: &str, chunks: &[&str]) -> ProviderConfig {
    ProviderConfig {
        privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        search_privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        provider_name: name.to_owned(),
        provider_type: "openai".to_owned(),
        tier: None,
        model_name: format!("{name}-model"),
        context_size: Some(4096),
        base_url: "https://api.openai.com/v1".to_owned(),
        api_key: None,
        allowed_providers: Vec::new(),
        request_timeout: None,
        rate_limit_retries: None,
        rate_limit_max_wait_secs: None,
        test_chunks: Some(chunks.iter().map(|s| s.to_string()).collect()),
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn mock_provider(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        search_privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        provider_name: "default".to_owned(),
        provider_type: "openai".to_owned(),
        tier: None,
        model_name: "gpt-test".to_owned(),
        context_size: Some(4096),
        base_url: base_url.to_owned(),
        api_key: None,
        allowed_providers: Vec::new(),
        request_timeout: None,
        rate_limit_retries: None,
        rate_limit_max_wait_secs: None,
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn deps_from_list(
    entries: Vec<ProviderConfig>,
    default: &str,
    save: bool,
    send: bool,
    brave: Option<&str>,
) -> GenerationDeps {
    let mut map = HashMap::new();
    for entry in entries {
        map.insert(entry.provider_name.clone(), entry);
    }
    GenerationDeps::new(
        map,
        default.to_owned(),
        save,
        send,
        brave.map(|key| key.to_owned()),
    )
}

fn isolated_router(deps: GenerationDeps) -> Router {
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let services = AppServices::with_owned_stores(identity).with_generation_deps(deps);
    build_router_with_services(resolve_static_root(), services)
}

#[tokio::test]
async fn two_routers_isolate_provider_maps_and_default_selection() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();

    let deps_a = deps_from_list(
        vec![
            test_provider_with_chunks("default", &["router-a-default-aaa"]),
            test_provider_with_chunks("second", &["router-a-second-bbb"]),
            test_provider_with_chunks("only-a", &["router-a-only-eee"]),
        ],
        "default",
        true,
        false,
        None,
    );
    let deps_b = deps_from_list(
        vec![
            test_provider_with_chunks("default", &["router-b-default-ccc"]),
            test_provider_with_chunks("second", &["router-b-second-ddd"]),
        ],
        "second",
        true,
        false,
        None,
    );
    let app_a = isolated_router(deps_a);
    let app_b = isolated_router(deps_b);
    let (cookie_a, csrf_a) = guest_session(&app_a).await;
    let (cookie_b, csrf_b) = guest_session(&app_b).await;

    let (_, _, body_a_default) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    let (_, _, body_b_default) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    let (_, _, body_a_second) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": "second"}),
    )
    .await;
    let (_, _, body_b_second) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": "second"}),
    )
    .await;
    let (_, _, body_b_explicit_default) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": "default"}),
    )
    .await;

    let (status_a_regen, _, body_a_regen) = post_regenerate(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "Hello", "set_name": "default", "pair_index": 0}),
    )
    .await;
    let (status_b_regen, _, body_b_regen) = post_regenerate(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "Hello", "set_name": "default", "pair_index": 0}),
    )
    .await;

    let (_, _, body_a_only) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "Hello", "set_name": "default", "model_name": "only-a"}),
    )
    .await;
    let (status_b_missing, content_type_b_missing, body_b_missing) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "", "model_name": "only-a"}),
    )
    .await;

    clear_generation_env();

    assert!(
        body_a_default.contains("router-a-default-aaa"),
        "router A default must use its own map, got: {body_a_default}"
    );
    assert!(
        body_b_default.contains("router-b-second-ddd"),
        "router B default_llm must use its own second, got: {body_b_default}"
    );
    assert!(
        body_a_second.contains("router-a-second-bbb"),
        "router A explicit second must stay scoped, got: {body_a_second}"
    );
    assert!(
        body_b_second.contains("router-b-second-ddd"),
        "router B explicit second must stay scoped, got: {body_b_second}"
    );
    assert!(
        body_b_explicit_default.contains("router-b-default-ccc"),
        "router B explicit default must still reach its own default, got: {body_b_explicit_default}"
    );
    assert!(
        !body_a_default.contains("router-b-") && !body_b_default.contains("router-a-"),
        "provider maps must not leak across routers: {body_a_default} / {body_b_default}"
    );
    assert_eq!(status_a_regen, StatusCode::OK);
    assert!(
        body_a_regen.contains("router-a-default-aaa"),
        "router A regenerate without a model must use its own default, got: {body_a_regen}"
    );
    assert_eq!(status_b_regen, StatusCode::OK);
    assert!(
        body_b_regen.contains("router-b-second-ddd"),
        "router B regenerate without a model must use its own default, got: {body_b_regen}"
    );
    assert!(
        body_a_only.contains("router-a-only-eee"),
        "router A must reach its unique provider, got: {body_a_only}"
    );
    assert_eq!(status_b_missing, StatusCode::BAD_REQUEST);
    assert!(
        content_type_b_missing.contains("application/json"),
        "missing model must be a direct JSON error, got {content_type_b_missing}"
    );
    let missing_payload: Value =
        serde_json::from_str(&body_b_missing).expect("400 body must be JSON");
    assert_eq!(
        missing_payload,
        json!({"error": "requested model not found"})
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_brave_eligibility() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();

    let deps_a = deps_from_list(
        vec![test_provider_with_chunks(
            "default",
            &["brave-final-marker"],
        )],
        "default",
        true,
        false,
        Some("router-a-brave-key"),
    )
    .with_fake_tool_query("weather today".to_string())
    .with_fake_brave_results("Atlanta: 72F, sunny".to_string());
    let deps_b = deps_from_list(
        vec![test_provider_with_chunks(
            "default",
            &["brave-final-marker"],
        )],
        "default",
        true,
        false,
        None,
    );
    let app_a = isolated_router(deps_a);
    let app_b = isolated_router(deps_b);

    // Ambient decoys must not leak into owned routers: the explicit fakes
    // above win for A, and B stays keyless despite the ambient key.
    env::set_var("BRAVE_API_KEY", "ambient-decoy-key");
    env::set_var(
        "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY",
        "ambient-decoy-query",
    );
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "ambient-decoy-results");

    let (cookie_a, csrf_a) = guest_session(&app_a).await;
    let (cookie_b, csrf_b) = guest_session(&app_b).await;

    let (status_a, _, body_a) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "What is the weather?", "set_name": "default", "model_name": "default", "web_search": true}),
    )
    .await;
    let (status_b, _, body_b) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "What is the weather?", "set_name": "default", "model_name": "default", "web_search": true}),
    )
    .await;

    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    clear_generation_env();

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert!(
        body_a.contains("<think>Searching for: weather today...</think>"),
        "Brave router must run search, got: {body_a}"
    );
    assert!(
        body_a.contains("brave-final-marker"),
        "Brave router must still stream the final answer, got: {body_a}"
    );
    assert!(
        !body_b.contains("<think>Searching"),
        "keyless router must fall back to direct streaming, got: {body_b}"
    );
    assert!(
        body_b.contains("brave-final-marker"),
        "keyless router must still stream directly, got: {body_b}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_save_thought_defaults() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    let seed_delta = "first answer <think>secret-plan</think> tail";
    let (captured_a, hits_a) = fresh_capture();
    let (captured_b, hits_b) = fresh_capture();
    let (addr_a, handle_a) =
        spawn_openai_mock(captured_a.clone(), hits_a.clone(), seed_delta).await;
    let (addr_b, handle_b) =
        spawn_openai_mock(captured_b.clone(), hits_b.clone(), seed_delta).await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let url_a = format!("http://{addr_a}/v1");
    let url_b = format!("http://{addr_b}/v1");
    let deps_a = deps_from_list(vec![mock_provider(&url_a)], "default", true, true, None);
    let deps_b = deps_from_list(vec![mock_provider(&url_b)], "default", false, true, None);
    let app_a = isolated_router(deps_a);
    let app_b = isolated_router(deps_b);
    let (cookie_a, csrf_a) = guest_session(&app_a).await;
    let (cookie_b, csrf_b) = guest_session(&app_b).await;

    let (first_a, _, _) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_a, StatusCode::OK);
    let (first_b, _, _) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_b, StatusCode::OK);

    let (second_a, _, _) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    let (second_b, _, _) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;

    let payloads_a = captured_a.lock().await.clone();
    let payloads_b = captured_b.lock().await.clone();
    handle_a.abort();
    handle_b.abort();
    clear_generation_env();

    assert_eq!(second_a, StatusCode::OK);
    assert_eq!(second_b, StatusCode::OK);
    let content_a = payloads_a.last().expect("router A second payload")["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history")["content"]
        .as_str()
        .expect("plain string")
        .to_owned();
    let content_b = payloads_b.last().expect("router B second payload")["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history")["content"]
        .as_str()
        .expect("plain string")
        .to_owned();
    assert!(
        content_a.contains("<think>secret-plan</think>"),
        "save-true router must persist thinking upstream, got: {content_a}"
    );
    assert!(
        !content_b.contains("<think>") && !content_b.contains("secret-plan"),
        "save-false router must strip before forwarding, got: {content_b}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_send_thought_defaults() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());

    let seed_delta = "first answer <think>secret-plan</think> tail";
    let (captured_a, hits_a) = fresh_capture();
    let (captured_b, hits_b) = fresh_capture();
    let (addr_a, handle_a) =
        spawn_openai_mock(captured_a.clone(), hits_a.clone(), seed_delta).await;
    let (addr_b, handle_b) =
        spawn_openai_mock(captured_b.clone(), hits_b.clone(), seed_delta).await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "provider_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let url_a = format!("http://{addr_a}/v1");
    let url_b = format!("http://{addr_b}/v1");
    let deps_a = deps_from_list(vec![mock_provider(&url_a)], "default", true, true, None);
    let deps_b = deps_from_list(vec![mock_provider(&url_b)], "default", true, false, None);
    let app_a = isolated_router(deps_a);
    let app_b = isolated_router(deps_b);
    let (cookie_a, csrf_a) = guest_session(&app_a).await;
    let (cookie_b, csrf_b) = guest_session(&app_b).await;

    let (first_a, _, _) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_a, StatusCode::OK);
    let (first_b, _, _) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "first question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(first_b, StatusCode::OK);

    let (second_a, _, _) = post_chat(
        &app_a,
        &cookie_a,
        &csrf_a,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;
    let (second_b, _, _) = post_chat(
        &app_b,
        &cookie_b,
        &csrf_b,
        None,
        json!({"message": "second question", "set_name": "default", "model_name": "default"}),
    )
    .await;

    let payloads_a = captured_a.lock().await.clone();
    let payloads_b = captured_b.lock().await.clone();
    handle_a.abort();
    handle_b.abort();
    clear_generation_env();

    assert_eq!(second_a, StatusCode::OK);
    assert_eq!(second_b, StatusCode::OK);
    let content_a = payloads_a.last().expect("router A second payload")["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history")["content"]
        .as_str()
        .expect("plain string")
        .to_owned();
    let content_b = payloads_b.last().expect("router B second payload")["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant history")["content"]
        .as_str()
        .expect("plain string")
        .to_owned();
    assert!(
        content_a.contains("<think>secret-plan</think>"),
        "send-true router must forward thinking, got: {content_a}"
    );
    assert!(
        !content_b.contains("<think>") && !content_b.contains("secret-plan"),
        "send-false router must strip upstream, got: {content_b}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}
