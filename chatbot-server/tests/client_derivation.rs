use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    session,
    user_store::{CreateOutcome, UserStore},
};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

#[tokio::test]
async fn get_salt_returns_salt_for_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "saltuser";
    seed_user(username, "password123");

    let app = build_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/salt/{}", username))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /auth/salt/username");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
    assert!(json.get("salt").is_some(), "salt field should be present");
    assert!(!json["salt"].as_str().unwrap().is_empty(), "salt should not be empty");
}

#[tokio::test]
async fn get_salt_returns_fake_salt_for_non_existent_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "nonexistent";

    let app = build_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/salt/{}", username))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /auth/salt/nonexistent");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
    assert!(json.get("salt").is_some());
    assert!(!json["salt"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn login_with_storage_key_uses_provided_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyuser";
    let password = "password123";
    let fake_storage_key = "fake_derived_key_base64_string";
    seed_user(username, password);

    let app = build_app();

    // 1. Get login page for CSRF
    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    let set_cookie = get_response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    let body = to_bytes(get_response.into_body(), 64 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).unwrap();

    // 2. Login with storage_key
    let payload = format!(
        "username={}&password={}&csrf_token={}&storage_key={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
        urlencoding::encode(fake_storage_key)
    );

    let post_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    let cookie_header = common::extract_cookie(&login_cookie);

    // 3. Verify session has the provided key
    let session = session::session_context(Some(&cookie_header)).expect("session context");
    let stored_key_bytes = session.encryption_key.expect("encryption key present");
    assert_eq!(std::str::from_utf8(&stored_key_bytes).unwrap(), fake_storage_key);
}
