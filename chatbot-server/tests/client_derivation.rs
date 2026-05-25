use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::session::{self, SessionRequest};
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

#[tokio::test]
async fn get_salt_returns_salt_for_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "saltuser";
    common::seed_user(username, "password123");

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
    assert_eq!(json["salt"], common::fixed_client_salt_b64());
    assert_eq!(json["auth_mode"], "legacy_password");
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
    assert_eq!(json["auth_mode"], "derived_token");
    assert!(!json["salt"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_login_uses_derived_storage_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyuser";
    let password = "password123";
    common::seed_user(username, password);
    let storage_key = common::derive_storage_key(username, password);

    let app = build_app();

    let payload = format!(
        "username={}&password={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
    );

    let post_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::OK);

    let session = session::session_context(SessionRequest {
        authorization: Some(&common::auth_header(&storage_key)),
        auth_user: Some(username),
        encryption_key: Some(&storage_key),
        guest_session: None,
    })
    .expect("session context");

    let stored_key_bytes = session.encryption_key.expect("encryption key present");
    assert_eq!(std::str::from_utf8(&stored_key_bytes).unwrap(), storage_key);
}

#[tokio::test]
async fn migrated_login_accepts_auth_token_payload() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "plaintext-user";
    let password = "hunter2";
    common::seed_user(username, password);
    let storage_key = common::derive_storage_key(username, password);

    let app = build_app();

    let first_payload = format!(
        "username={}&password={}",
        urlencoding::encode(username),
        urlencoding::encode(password)
    );

    let first_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(first_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login plaintext");

    assert_eq!(first_response.status(), StatusCode::OK);

    let second_payload = format!(
        "username={}&auth_token={}&enc_key={}",
        urlencoding::encode(username),
        urlencoding::encode(&storage_key),
        urlencoding::encode(&storage_key)
    );
    let second_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(second_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login token");

    assert_eq!(second_response.status(), StatusCode::OK);
}
