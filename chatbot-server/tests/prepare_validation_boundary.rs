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

async fn post_chat(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
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

fn assert_raw400(status: StatusCode, content_type: &str, text: &str, expected_error: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected raw 400, got {text}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json content-type, got {content_type}"
    );
    let payload: Value = serde_json::from_str(text).expect("400 body must be JSON");
    assert_eq!(payload, json!({ "error": expected_error }));
}

fn assert_saved_turn(status: StatusCode, content_type: &str, text: &str, expected_error: &str) {
    assert_eq!(status, StatusCode::OK, "expected saved 200 turn, got {text}");
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );
    assert!(
        text.contains("[Error]") && text.contains(expected_error),
        "saved turn must carry '[Error] {expected_error}', got: {text}"
    );
}

#[tokio::test]
async fn chat_empty_message_returns_raw400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_chat(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "   ", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_raw400(status, &content_type, &text, "message is required");
}

#[tokio::test]
async fn regenerate_empty_message_returns_raw400() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_raw400(status, &content_type, &text, "message is required");
}

#[tokio::test]
async fn chat_invalid_set_name_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_chat(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "set_name": "bad/name!", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set name");
}

#[tokio::test]
async fn chat_invalid_set_id_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_chat(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "set_id": "not-a-valid-set-id", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set_id");
}

#[tokio::test]
async fn regenerate_invalid_set_name_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "set_name": "bad/name!", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set name");
}

#[tokio::test]
async fn regenerate_invalid_set_id_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "hello", "set_id": "not-a-valid-set-id", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set_id");
}

async fn guest_session_with_history(app: &axum::Router) -> (String, String) {
    let (cookie, csrf) = guest_session(app).await;
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["seed chunk".to_string()]).expect("chunk json"),
    );
    let response = post_chat(
        app,
        &cookie,
        &csrf,
        &json!({"message": "Hello", "set_name": "default", "model_name": "default"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("drain seed chat");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    (cookie, csrf)
}

#[tokio::test]
async fn regenerate_pair_index_out_of_range_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session_with_history(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "Hello", "set_name": "default", "model_name": "default", "pair_index": 99}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "pair_index out of range");
}

#[tokio::test]
async fn regenerate_missing_pair_index_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session_with_history(&app).await;

    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "a different question", "set_name": "default", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_saved_turn(
        status,
        &content_type,
        &text,
        "pair_index is required when message is not the last user turn",
    );
}

#[tokio::test]
async fn regenerate_postlock_validation_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session_with_history(&app).await;

    let (status, _, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "Hello", "set_name": "default", "model_name": "default", "pair_index": 99}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "post-lock failure must save turn, got {text}");
    assert!(text.contains("pair_index out of range"), "unexpected body: {text}");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["recovered chunk".to_string()]).expect("chunk json"),
    );
    let (status, content_type, text) = read_raw(
        post_regenerate(
            &app,
            &cookie,
            &csrf,
            &json!({"message": "Hello", "set_name": "default", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "lock must be released after post-lock failure, got {text}");
    assert!(
        content_type.starts_with("text/plain"),
        "expected stream content-type, got {content_type}"
    );
    assert!(
        text.contains("recovered chunk") && !text.contains("[Error]"),
        "subsequent valid regenerate must stream cleanly, got: {text}"
    );
}

#[tokio::test]
async fn chat_lookup_unknown_set_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "prepare_lookup_user";
    const PASSWORD: &str = "L00kupS3cret!";

    let hashed = bcrypt::hash(PASSWORD, bcrypt::DEFAULT_COST).expect("hash password");
    let users_json = workspace.path().join("users.json");
    std::fs::write(
        &users_json,
        serde_json::to_string_pretty(&json!({USERNAME: {"password": hashed, "tier": "free"}}))
            .expect("users json"),
    )
    .expect("write users.json");

    let app = build_router(resolve_static_root());

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
        urlencoding::encode(USERNAME),
        urlencoding::encode(PASSWORD),
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
        .expect("GET /");
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

    let enc_key = common::derive_encryption_key_header(USERNAME, PASSWORD);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf)
                .header("X-Enc-Key", &enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "set_name": "ghost-set-xyz",
                        "model_name": "default",
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat unknown set");
    let (status, content_type, text) = read_raw(response).await;
    assert_saved_turn(status, &content_type, &text, "invalid set name");
}
