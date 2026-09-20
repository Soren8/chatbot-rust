//! MOD001 session-operation boundary: server-owned HTTP mapping.
//!
//! Given a typed `SessionOperationError`, when the server renders it, then
//! the status/body match the former service payloads exactly: 401s carry
//! their original strings with no counter, the single 400 uses the raw-body
//! path, and 500s record the error counter once. Guest custom sets stay a
//! raw 401 over HTTP (never a saved turn).

use std::{
    env,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use chatbot_core::{
    history::HistoryService,
    session::{ChatService, ChatSessionStore, SessionOperationError},
    session_identity::HttpSessionStore,
    user_store::UserStore,
};
use chatbot_server::{
    build_router, build_router_with_services, identity::RequestIdentity, resolve_static_root,
    services::AppServices,
};
use chatbot_server::{
    http_error::map_session_operation_err, test_instrumentation::take_error_count,
};
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
    (status, content_type, String::from_utf8_lossy(&body).into_owned())
}

fn mapper_body(err: &SessionOperationError) -> (StatusCode, Value) {
    let (status, body) = map_session_operation_err(err);
    (status, body.0)
}

fn disable_rate_limits() {
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
}

fn session_pair(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .find(|pair| pair.starts_with("session="))
        .expect("session cookie present")
}

fn csrf_from_home(html: &str) -> String {
    CSRF_META_RE
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("home csrf token present")
}

fn seed_global_user(username: &str, password: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    let mut store = UserStore::new().expect("global user store");
    match store.create_user(username, &hashed) {
        Ok(_) => {}
        Err(err) => panic!("seed global user: {err}"),
    }
}

struct ScopedBrokenSetup {
    _temp: tempfile::TempDir,
    app: axum::Router,
}

/// Owned router whose chat key/tier gates open an unusable account root.
/// History/sessions are valid; only `ChatService` account access fails, so
/// `/chat` prepare must surface the scoped store failure as 500.
fn make_scoped_broken_setup(secret: &str) -> ScopedBrokenSetup {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg = chatbot_core::config::app_config();
    let legacy_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&legacy_dir).expect("legacy dir");
    let history = HistoryService::open_with_data_dir(
        &temp.path().join("history.redb"),
        &legacy_dir,
        cfg.default_system_prompt.clone(),
    )
    .expect("open scoped history");
    let sessions = Arc::new(ChatSessionStore::new(
        cfg.session_timeout,
        cfg.default_system_prompt.clone(),
    ));
    let broken_root: PathBuf = temp.path().join("blocking-file");
    std::fs::write(&broken_root, b"regular file where a directory is needed")
        .expect("blocking file");
    let chat = ChatService::new(
        sessions,
        Arc::new(history),
        broken_root,
        secret.to_owned(),
    );
    let identity = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat);
    let app = build_router_with_services(resolve_static_root(), services);
    ScopedBrokenSetup { _temp: temp, app }
}

async fn login_scoped(app: &axum::Router, username: &str, password: &str) -> (String, String) {
    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let mut cookie = session_pair(&login_get);
    let body = to_bytes(login_get.into_body(), 128 * 1024)
        .await
        .expect("read login");
    let form_csrf =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8")).expect("login csrf");
    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&form_csrf),
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
    assert!(
        login_post.status() == StatusCode::FOUND
            || login_post.status() == StatusCode::SEE_OTHER,
        "expected redirect, got {}",
        login_post.status()
    );
    if let Some(raw) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(raw);
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .expect("drain login");

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    if let Some(raw) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        let rotated = common::extract_cookie(raw);
        if rotated.starts_with("session=") {
            cookie = rotated;
        }
    }
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));
    (cookie, csrf)
}

#[test]
fn missing_and_invalid_map_to_401_without_counter() {
    let _guard = test_mutex().lock().unwrap();
    let _ = take_error_count();

    let (status, body) = mapper_body(&SessionOperationError::MissingEncryptionKey);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({ "error": "Encryption key required. Please unlock." })
    );

    let (status, body) = mapper_body(&SessionOperationError::InvalidEncryptionKey);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": "Invalid encryption key." }));

    let (status, body) = mapper_body(&SessionOperationError::GuestCustomSetDenied);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": "Login required for custom sets" }));

    assert_eq!(
        take_error_count(),
        0,
        "401 session outcomes must not touch the 5xx counter"
    );
}

#[test]
fn misuse_maps_to_raw400_with_body_field() {
    let _guard = test_mutex().lock().unwrap();
    let _ = take_error_count();

    let (status, body) = mapper_body(&SessionOperationError::AuthenticatedBootstrapMisuse);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({ "error": "authenticated session must load via history store" })
    );
    // Raw 400s never touch the 5xx counter; response warn uses the body field.
    assert_eq!(take_error_count(), 0);
}

#[test]
fn store_and_history_map_to_500_with_single_counter() {
    let _guard = test_mutex().lock().unwrap();
    let _ = take_error_count();

    let (status, body) = mapper_body(&SessionOperationError::UserStoreUnavailable);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({ "error": "internal error while accessing user store" })
    );
    assert_eq!(take_error_count(), 1);

    let _ = take_error_count();
    let (status, body) = mapper_body(&SessionOperationError::HistoryUnavailable);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({ "error": "internal error while accessing chat history" })
    );
    assert_eq!(
        take_error_count(),
        1,
        "each 500 must record the counter exactly once"
    );
}

#[test]
fn session_messages_match_original_strings() {
    assert_eq!(
        SessionOperationError::MissingEncryptionKey.message(),
        "Encryption key required. Please unlock."
    );
    assert_eq!(
        SessionOperationError::InvalidEncryptionKey.message(),
        "Invalid encryption key."
    );
    assert_eq!(
        SessionOperationError::GuestCustomSetDenied.message(),
        "Login required for custom sets"
    );
    assert_eq!(
        SessionOperationError::AuthenticatedBootstrapMisuse.message(),
        "authenticated session must load via history store"
    );
    assert_eq!(
        SessionOperationError::UserStoreUnavailable.message(),
        "internal error while accessing user store"
    );
    assert_eq!(
        SessionOperationError::HistoryUnavailable.message(),
        "internal error while accessing chat history"
    );
}

#[tokio::test]
async fn guest_custom_set_returns_raw401_not_saved_turn() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "set_name": "my-custom-set",
                        "model_name": "default",
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat guest custom set");
    let (status, content_type, text) = read_raw(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expected raw 401, got {text}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&text).expect("401 body must be JSON");
    assert_eq!(payload, json!({ "error": "Login required for custom sets" }));
    assert!(
        !text.contains("[Error]"),
        "401 must not be saved as a 200 error turn, got: {text}"
    );
}

#[tokio::test]
async fn guest_custom_set_regenerate_returns_raw401() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "set_name": "my-custom-set",
                        "model_name": "default",
                        "pair_index": 0,
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate guest custom set");
    let (status, content_type, text) = read_raw(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expected raw 401, got {text}");
    assert!(
        content_type.contains("application/json"),
        "expected application/json, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&text).expect("401 body must be JSON");
    assert_eq!(payload, json!({ "error": "Login required for custom sets" }));
}

#[tokio::test]
async fn scoped_unusable_account_root_chat_returns_500_and_counts_once() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    const USERNAME: &str = "mod001_scoped_store_user";
    const PASSWORD: &str = "Sup3rS3cret!";
    const SECRET: &str = "mod001-scoped-store-secret";

    seed_global_user(USERNAME, PASSWORD);
    let enc_key = common::derive_encryption_key_header(USERNAME, PASSWORD);
    let setup = make_scoped_broken_setup(SECRET);
    let (cookie, csrf) = login_scoped(&setup.app, USERNAME, PASSWORD).await;

    // Require gate opens the scoped unusable root before any history access.
    let _ = take_error_count();
    let response = setup
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf)
                .header("X-Enc-Key", &enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "set_name": "default",
                        "model_name": "default",
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat scoped broken store");
    let (status, content_type, text) = read_raw(response).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "expected scoped 500, got {text}"
    );
    assert!(
        content_type.contains("application/json"),
        "expected application/json, got {content_type}"
    );
    let payload: Value = serde_json::from_str(&text).expect("500 body must be JSON");
    assert_eq!(
        payload,
        json!({ "error": "internal error while accessing user store" })
    );
    assert_eq!(
        take_error_count(),
        1,
        "scoped chat 500 must record the counter exactly once"
    );
}
