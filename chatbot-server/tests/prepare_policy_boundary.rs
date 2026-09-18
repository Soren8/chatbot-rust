//! Prepare policy boundary: generation-busy and premium-model gates.
//!
//! Given a chat/regenerate prepare outcome, when the generation lock is held
//! or a premium model is requested without entitlement, then the route
//! returns the exact 429/403 JSON body and releases the lock on policy
//! failure so a follow-up request can succeed.

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

const BUSY_BODY: &str =
    "A response is currently being generated. Please wait and try again.";
const PREMIUM_BODY: &str = "This model requires a Premium account";

const POLICY_CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
  - provider_name: "premium-model"
    type: "openai"
    model_name: "premium-test"
    tier: "premium"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
"#;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn guest_session(app: &axum::Router) -> (String, String) {
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
    assert_eq!(home.status(), StatusCode::OK);
    let cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("session cookie");
    let body = to_bytes(home.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let html = std::str::from_utf8(&body).expect("home utf8");
    let csrf = CSRF_META_RE
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");
    (cookie, csrf)
}

async fn post_chat(app: &axum::Router, cookie: &str, csrf: &str, payload: &Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(serde_json::to_vec(payload).expect("payload")))
                .unwrap(),
        )
        .await
        .expect("POST /chat")
}

async fn post_chat_authed(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: &Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(serde_json::to_vec(payload).expect("payload")))
                .unwrap(),
        )
        .await
        .expect("POST /chat")
}

async fn post_regenerate(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    payload: &Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(serde_json::to_vec(payload).expect("payload")))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate")
}

async fn post_regenerate_authed(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: &Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(serde_json::to_vec(payload).expect("payload")))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate")
}

async fn read_raw(response: Response) -> (StatusCode, String, String) {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let text = String::from_utf8_lossy(&body).into_owned();
    (status, content_type, text)
}

fn assert_exact_json(
    status: StatusCode,
    content_type: &str,
    text: &str,
    expected_status: StatusCode,
    expected_error: &str,
) {
    assert_eq!(status, expected_status, "expected {expected_status}, got {text}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json content-type, got {content_type}"
    );
    let payload: Value = serde_json::from_str(text).expect("policy body must be JSON");
    assert_eq!(payload, json!({ "error": expected_error }));
}

/// Hold the per-session generation lock via the core adapter so the next
/// route prepare sees a busy session. Returns the session id for release.
fn hold_generation_lock(cookie: &str) -> String {
    let ctx =
        chatbot_core::session::session_context(Some(cookie)).expect("session context for lock");
    let provider = chatbot_core::config::get_provider_config(Some("default"))
        .expect("default provider for lock");
    let request = chatbot_core::session::ChatRequestData {
        message: "hold lock",
        system_prompt: None,
        set_name: None,
        set_id: None,
        model_name: None,
        encrypted: false,
        send_thoughts: false,
    };
    let result = chatbot_core::session::chat_prepare(&ctx, &request, &provider, None);
    assert!(
        result.error.is_none(),
        "lock-holder prepare must succeed, got {:?}",
        result.error.map(|e| format!("{e:?}"))
    );
    assert!(result.context.is_some(), "lock-holder needs context");
    ctx.session_id
}

fn write_user(workspace: &common::TestWorkspace, username: &str, password: &str, tier: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    let path = workspace.path().join("users.json");
    let current: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| json!({}));
    let mut users = current.as_object().cloned().unwrap_or_default();
    users.insert(
        username.to_string(),
        json!({"password": hashed, "tier": tier}),
    );
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&Value::Object(users)).expect("users json"),
    )
    .expect("write users.json");
}

async fn login_user(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> (String, String, String) {
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
    assert_eq!(login_page.status(), StatusCode::OK);
    let mut session_cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("login cookie");
    let login_body = to_bytes(login_page.into_body(), 64 * 1024)
        .await
        .expect("login body");
    let login_csrf =
        common::extract_csrf_token(std::str::from_utf8(&login_body).expect("login utf8"))
            .expect("login csrf");

    let form_body = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&login_csrf),
    );
    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert!(
        login_post.status() == StatusCode::SEE_OTHER
            || login_post.status() == StatusCode::FOUND,
        "expected redirect, got {}",
        login_post.status()
    );
    if let Some(value) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
    {
        session_cookie = value;
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024).await;

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / after login");
    assert_eq!(home.status(), StatusCode::OK);
    if let Some(value) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
    {
        session_cookie = value;
    }
    let home_body = to_bytes(home.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).expect("home utf8"))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    let enc_key = common::derive_encryption_key_header(username, password);
    (session_cookie, csrf, enc_key)
}

#[tokio::test]
async fn chat_busy_returns_exact429() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let session_id = hold_generation_lock(&cookie);

    let (status, content_type, text) = read_raw(
        post_chat(&app, &cookie, &csrf, &json!({"message": "hello", "model_name": "default"}))
            .await,
    )
    .await;
    assert_exact_json(status, &content_type, &text, StatusCode::TOO_MANY_REQUESTS, BUSY_BODY);

    chatbot_core::session::release_session_lock(&session_id);
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["recovered".to_string()]).expect("chunk json"),
    );
    let (status, _, text) = read_raw(
        post_chat(&app, &cookie, &csrf, &json!({"message": "hello", "model_name": "default"}))
            .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "lock must be reusable, got {text}");
    assert!(text.contains("recovered"), "unexpected body: {text}");
}

#[tokio::test]
async fn regenerate_busy_returns_exact429() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let session_id = hold_generation_lock(&cookie);

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_exact_json(status, &content_type, &text, StatusCode::TOO_MANY_REQUESTS, BUSY_BODY);

    chatbot_core::session::release_session_lock(&session_id);
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["recovered".to_string()]).expect("chunk json"),
    );
    let (status, _, text) = read_raw(
        post_chat(&app, &cookie, &csrf, &json!({"message": "hello", "model_name": "default"}))
            .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "shared lock must be reusable, got {text}");
    assert!(text.contains("recovered"), "unexpected body: {text}");
}

#[tokio::test]
async fn chat_guest_premium_returns_exact403() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_chat(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "premium-model"}),
        )
        .await,
    )
    .await;
    assert_exact_json(status, &content_type, &text, StatusCode::FORBIDDEN, PREMIUM_BODY);
}

#[tokio::test]
async fn regenerate_guest_premium_returns_exact403() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "premium-model", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_exact_json(status, &content_type, &text, StatusCode::FORBIDDEN, PREMIUM_BODY);
}

#[tokio::test]
async fn chat_free_user_premium_returns_exact403() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    write_user(&workspace, "free-user", "Fr33P4ssw0rd!", "free");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "free-user", "Fr33P4ssw0rd!").await;

    let (status, content_type, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "model_name": "premium-model"}),
        )
        .await,
    )
    .await;
    assert_exact_json(status, &content_type, &text, StatusCode::FORBIDDEN, PREMIUM_BODY);
}

#[tokio::test]
async fn chat_premium_user_allowed() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    write_user(&workspace, "premium-user", "Pr3m1umP4ss!", "premium");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "premium-user", "Pr3m1umP4ss!").await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["premium hello".to_string()]).expect("chunk json"),
    );
    let (status, content_type, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "model_name": "premium-model"}),
        )
        .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "premium user must stream, got {text}");
    assert!(
        content_type.starts_with("text/plain"),
        "expected stream content-type, got {content_type}"
    );
    assert!(
        text.contains("premium hello") && !text.contains("[Error]"),
        "premium stream must carry chunk cleanly, got: {text}"
    );
}

#[tokio::test]
async fn regenerate_premium_user_allowed() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    write_user(&workspace, "premium-regen", "Pr3m1umR3g3n!", "premium");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "premium-regen", "Pr3m1umR3g3n!").await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["seed chunk".to_string()]).expect("chunk json"),
    );
    let seed = post_chat_authed(
        &app,
        &cookie,
        &csrf,
        &enc_key,
        &json!({"message": "Hello", "model_name": "premium-model"}),
    )
    .await;
    assert_eq!(seed.status(), StatusCode::OK);
    let _ = to_bytes(seed.into_body(), 512 * 1024).await.expect("drain seed");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["regen chunk".to_string()]).expect("chunk json"),
    );
    let (status, content_type, text) = read_raw(
        post_regenerate_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "Hello", "model_name": "premium-model", "pair_index": 0}),
        )
        .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "premium regenerate must stream, got {text}");
    assert!(
        content_type.starts_with("text/plain"),
        "expected stream content-type, got {content_type}"
    );
    assert!(
        text.contains("regen chunk") && !text.contains("[Error]"),
        "premium regenerate must carry chunk cleanly, got: {text}"
    );
}

#[tokio::test]
async fn chat_failed_policy_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, _, text) = read_raw(
        post_chat(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "premium-model"}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "policy must reject, got {text}");
    assert!(text.contains(PREMIUM_BODY), "unexpected body: {text}");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["after policy".to_string()]).expect("chunk json"),
    );
    let (status, _, text) = read_raw(
        post_chat(&app, &cookie, &csrf, &json!({"message": "hello", "model_name": "default"}))
            .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "lock must release after policy failure, got {text}");
    assert!(text.contains("after policy"), "unexpected body: {text}");
}

#[tokio::test]
async fn regenerate_failed_policy_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    let _workspace = common::TestWorkspace::with_config(POLICY_CONFIG);
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, _, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "premium-model", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "policy must reject, got {text}");
    assert!(text.contains(PREMIUM_BODY), "unexpected body: {text}");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["after policy".to_string()]).expect("chunk json"),
    );
    let (status, _, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    // Guest empty history accepts pair_index 0 as the live append index; the
    // point is the policy failure did not leave the generation lock held.
    assert_eq!(status, StatusCode::OK, "lock must release after policy failure, got {text}");
    assert!(text.contains("after policy"), "unexpected body: {text}");
}
