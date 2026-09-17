//! MOD001 boundary characterization: encryption-key validation outcomes.
//!
//! Given an authenticated session, when a data endpoint receives a missing or
//! wrong encryption key, then it returns a raw 401 JSON error (never a saved
//! chat turn), and a missing key verifier is never enrolled from a data
//! request.

use std::{
    env, fs,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::user_store::{CreateOutcome, UserStore};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

const MISSING_BODY: &str = "Encryption key required. Please unlock.";
const WRONG_BODY: &str = "Invalid encryption key.";
const WRONG_KEY: &str = "definitely-not-the-right-key";

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

/// Log in and return the session-only cookie plus a page CSRF token.
///
/// Only the `session=...` pair is kept so later requests carry no `enc_key`
/// cookies; tests add `X-Enc-Key` explicitly where needed.
async fn login_session(app: &axum::Router, username: &str, password: &str) -> (String, String) {
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

    let mut session_cookie = session_cookie_value(login_page.headers())
        .expect("initial session cookie");

    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("read login body");
    let login_csrf =
        common::extract_csrf_token(std::str::from_utf8(&login_body).expect("login utf8"))
            .expect("csrf token in login form");

    let form_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&login_csrf),
    );

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(form_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    let login_status = login_response.status();
    assert!(
        login_status == StatusCode::SEE_OTHER || login_status == StatusCode::FOUND,
        "expected redirect after login, got {login_status}"
    );
    if let Some(value) = session_cookie_value(login_response.headers()) {
        session_cookie = value;
    }
    let _ = to_bytes(login_response.into_body(), 32 * 1024).await;

    let home_response = app
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

    if let Some(value) = session_cookie_value(home_response.headers()) {
        session_cookie = value;
    }
    let home_body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    (session_cookie, csrf_token)
}

fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| cookie.starts_with("session="))
        .map(|cookie| common::extract_cookie(cookie))
}

async fn read_json(response: axum::response::Response) -> (StatusCode, String, Value) {
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
    let payload: Value = serde_json::from_slice(&body).expect("error body must be JSON");
    (status, content_type, payload)
}

fn assert_json_error(
    status: StatusCode,
    content_type: &str,
    payload: &Value,
    expected_status: StatusCode,
    expected_error: &str,
) {
    assert_eq!(status, expected_status, "unexpected status for {payload}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json content-type, got {content_type}"
    );
    assert_eq!(
        *payload,
        json!({ "error": expected_error }),
        "exact error body must be preserved"
    );
}

#[tokio::test]
async fn direct_endpoints_missing_key_return_unlock_401() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_boundary_missing";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // sets family: GET /get_sets needs no CSRF token.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets without enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    // memory family: POST /update_memory.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "boundary"})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory without enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    // reset family: POST /reset_chat.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/reset_chat")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"set_name": "default"})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /reset_chat without enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    // preferences family: POST /update_preferences.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_preferences")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"web_search": true})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_preferences without enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );
}

#[tokio::test]
async fn direct_endpoints_wrong_key_return_invalid_401() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_boundary_wrong";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // sets family.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-Enc-Key", WRONG_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets with wrong enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );

    // memory family.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header("X-Enc-Key", WRONG_KEY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "boundary"})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory with wrong enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );

    // reset family.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/reset_chat")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header("X-Enc-Key", WRONG_KEY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"set_name": "default"})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /reset_chat with wrong enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );

    // preferences family.
    let (status, content_type, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_preferences")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header("X-Enc-Key", WRONG_KEY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"web_search": true})).expect("payload"),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_preferences with wrong enc key"),
    )
    .await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );
}

#[tokio::test]
async fn chat_missing_and_wrong_key_return_raw_401_not_saved_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_boundary_chat";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // Missing key: raw 401 JSON, not a saved 200 text/plain assistant turn.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"message": "hello"})).expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat without enc key");
    let (status, content_type, payload) = read_json(response).await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    // Wrong key: distinct 401 body, still raw JSON.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", WRONG_KEY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"message": "hello"})).expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat with wrong enc key");
    let (status, content_type, payload) = read_json(response).await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );
}

#[tokio::test]
async fn regenerate_missing_and_wrong_key_return_raw_401_not_saved_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_boundary_regen";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // Missing key: raw 401 JSON, not a saved 200 text/plain assistant turn.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "pair_index": 0
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate without enc key");
    let (status, content_type, payload) = read_json(response).await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    // Wrong key: distinct 401 body, still raw JSON.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", WRONG_KEY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "pair_index": 0
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate with wrong enc key");
    let (status, content_type, payload) = read_json(response).await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        WRONG_BODY,
    );
}

#[tokio::test]
async fn missing_verifier_stays_missing_with_correct_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_boundary_no_enroll";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;
    let enc_key = common::derive_encryption_key_header(username, password);

    let verifier_dir = workspace.path().join("key_verifiers");
    fs::remove_dir_all(&verifier_dir).ok();
    fs::create_dir_all(&verifier_dir).expect("recreate verifier dir");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with no verifier");
    let (status, content_type, payload) = read_json(response).await;
    assert_json_error(
        status,
        &content_type,
        &payload,
        StatusCode::UNAUTHORIZED,
        MISSING_BODY,
    );

    let leftover: Vec<_> = fs::read_dir(&verifier_dir)
        .map(|entries| entries.filter_map(Result::ok).collect())
        .unwrap_or_default();
    assert!(
        leftover.is_empty(),
        "missing verifier must stay missing, found {leftover:?}"
    );
}

#[tokio::test]
async fn store_unavailable_maps_to_500_json_and_records_error() {
    // Store failures count as server errors; rejected credentials do not.
    let _guard = test_mutex().lock().unwrap();
    let _ = chatbot_server::test_instrumentation::take_error_count();

    let (status, axum::Json(body)) =
        chatbot_server::http_error::map_encryption_key_validation_err(
            chatbot_core::session::EncryptionKeyValidationError::StoreUnavailable,
        );

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({ "error": "internal error while accessing user store" })
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        1,
        "StoreUnavailable must increment the 5xx instrumentation counter"
    );
}

#[tokio::test]
async fn missing_and_invalid_map_to_401_without_recording_error() {
    let _guard = test_mutex().lock().unwrap();
    let _ = chatbot_server::test_instrumentation::take_error_count();

    let (status, axum::Json(body)) =
        chatbot_server::http_error::map_encryption_key_validation_err(
            chatbot_core::session::EncryptionKeyValidationError::Missing,
        );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": MISSING_BODY }));

    let (status, axum::Json(body)) =
        chatbot_server::http_error::map_encryption_key_validation_err(
            chatbot_core::session::EncryptionKeyValidationError::Invalid,
        );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": WRONG_BODY }));

    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "401 outcomes must not touch the 5xx instrumentation counter"
    );
}
