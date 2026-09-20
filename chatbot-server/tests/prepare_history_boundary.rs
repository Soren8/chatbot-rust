//! Prepare history boundary: history failures from chat/regenerate prepare.
//!
//! Given an authenticated prepare that reaches the history store, when the
//! set is missing then the route saves a 200 error turn carrying
//! "invalid set name"; when the key is wrong it returns a raw 401; when the
//! system prompt is oversized it saves the invalid-input message as a turn.
//! Prepare-path `NotFound` stays a 400 (unlike the general history 404).

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use chatbot_core::{history::SetVersion, session::PrepareHistoryError};
use chatbot_server::{
    http_error::map_prepare_history_err, test_instrumentation::take_error_count,
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

fn write_user(workspace: &common::TestWorkspace, username: &str, password: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    std::fs::write(
        workspace.path().join("users.json"),
        serde_json::to_string_pretty(&json!({username: {"password": hashed, "tier": "free"}}))
            .expect("users json"),
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
    let body = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("read body");
    (status, content_type, String::from_utf8_lossy(&body).into_owned())
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
async fn chat_missing_set_saved_as_chat_turn_and_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    write_user(&workspace, "hist_missing_chat", "HistM1ssing!");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "hist_missing_chat", "HistM1ssing!").await;

    let (status, content_type, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "set_name": "ghost-set-xyz", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set name");

    // Prepare failure must release the generation lock for the next request.
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["recovered".to_string()]).expect("chunk json"),
    );
    let (status, _, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "set_name": "default", "model_name": "default"}),
        )
        .await,
    )
    .await;
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(status, StatusCode::OK, "lock must be released, got {text}");
    assert!(
        text.contains("recovered") && !text.contains("[Error]"),
        "follow-up chat must stream cleanly, got: {text}"
    );
}

#[tokio::test]
async fn regenerate_missing_set_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    write_user(&workspace, "hist_missing_regen", "HistM1ssing!");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "hist_missing_regen", "HistM1ssing!").await;

    let (status, content_type, text) = read_raw(
        post_regenerate_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "set_name": "ghost-set-xyz", "model_name": "default", "pair_index": 0}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "invalid set name");
}

#[tokio::test]
async fn chat_wrong_key_returns_raw401() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    write_user(&workspace, "hist_wrong_key", "HistM1ssing!");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, _) = login_user(&app, "hist_wrong_key", "HistM1ssing!").await;

    let (status, content_type, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            "definitely-not-the-right-key",
            &json!({"message": "hello", "set_name": "default", "model_name": "default"}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expected raw 401, got {text}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json content-type, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&text).expect("401 body must be JSON");
    assert_eq!(payload, json!({ "error": "Invalid encryption key." }));
}

#[tokio::test]
async fn chat_oversized_system_prompt_saved_as_chat_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    write_user(&workspace, "hist_big_prompt", "HistM1ssing!");
    let app = build_router(resolve_static_root());
    let (cookie, csrf, enc_key) = login_user(&app, "hist_big_prompt", "HistM1ssing!").await;

    let big_prompt = "x".repeat(900_001);
    let (status, content_type, text) = read_raw(
        post_chat_authed(
            &app,
            &cookie,
            &csrf,
            &enc_key,
            &json!({"message": "hello", "set_name": "default", "model_name": "default", "system_prompt": big_prompt}),
        )
        .await,
    )
    .await;
    assert_saved_turn(status, &content_type, &text, "system prompt too large");
}

fn mapper_body(err: &PrepareHistoryError) -> (StatusCode, Value) {
    let (status, body) = map_prepare_history_err(err);
    (status, body.0)
}

#[test]
fn prepare_history_mapper_preserves_direct_bodies() {
    // Client-visible contract moved from the prepare path unchanged.
    let (status, body) = mapper_body(&PrepareHistoryError::Unauthorized);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({ "error": "Encryption key required. Please unlock." })
    );

    let (status, body) = mapper_body(&PrepareHistoryError::NotFound);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({ "error": "invalid set name" }));

    let (status, body) =
        mapper_body(&PrepareHistoryError::InvalidInput("system prompt too large"));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({ "error": "system prompt too large" }));

    let (status, body) = mapper_body(&PrepareHistoryError::Forbidden);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({ "error": "forbidden" }));
}

#[test]
fn prepare_history_conflict_keeps_minimal409() {
    // Prepare conflicts carry only error + current_version: no sync "message"
    // (general history mapper) and no set_id (set-mutation helpers).
    let (status, body) = mapper_body(&PrepareHistoryError::Conflict {
        current_version: SetVersion(3),
    });
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({ "error": "version_conflict", "current_version": 3 })
    );
    assert!(body.get("message").is_none(), "prepare 409 has no message: {body}");
    assert!(body.get("set_id").is_none(), "prepare 409 has no set_id: {body}");
}

#[test]
fn prepare_history_internal_records_error_counter() {
    let _ = take_error_count();
    let (status, body) = mapper_body(&PrepareHistoryError::Internal);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({ "error": "internal error while accessing chat history" })
    );
    assert_eq!(take_error_count(), 1, "prepare 500 must record one error");

    // Non-500 prepare failures are client-visible, not server errors.
    let _ = mapper_body(&PrepareHistoryError::NotFound);
    let _ = mapper_body(&PrepareHistoryError::Conflict {
        current_version: SetVersion(3),
    });
    assert_eq!(take_error_count(), 0, "non-500 prepare failures record nothing");
}

#[test]
fn prepare_history_saved_message_classification() {
    // Only 400 variants become saved error turns; all else maps directly.
    assert_eq!(
        PrepareHistoryError::NotFound.saved_error_message(),
        Some("invalid set name")
    );
    assert_eq!(
        PrepareHistoryError::InvalidInput("system prompt too large").saved_error_message(),
        Some("system prompt too large")
    );
    for err in [
        PrepareHistoryError::Unauthorized,
        PrepareHistoryError::Conflict {
            current_version: SetVersion(3),
        },
        PrepareHistoryError::Forbidden,
        PrepareHistoryError::Internal,
    ] {
        assert_eq!(err.saved_error_message(), None, "{err:?} must map directly");
    }
}
