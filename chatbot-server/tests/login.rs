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

fn lock_test_mutex() -> std::sync::MutexGuard<'static, ()> {
    test_mutex()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
async fn login_get_renders_form_with_security_headers() {
    common::init_tracing();
    let _guard = lock_test_mutex();
    let _workspace = setup_workspace();

    let app = build_app();
    let response = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    let csp = headers
        .get("Content-Security-Policy")
        .and_then(|value| value.to_str().ok())
        .expect("CSP header present");
    assert!(csp.contains("default-src 'self'"));

    for name in [
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
    ] {
        assert!(headers.get(name).is_some(), "expected {name} header");
    }

    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let body_str = std::str::from_utf8(&body).expect("utf8 response body");
    assert!(body_str.contains("<form action=\"/login\" method=\"post\">"));
    assert!(body_str.contains("remember-device"));
    assert!(body_str.contains("Remember this computer for 30 days"));
}

#[tokio::test]
async fn login_flow_returns_json_and_session_context() {
    common::init_tracing();
    let _guard = lock_test_mutex();
    let _workspace = setup_workspace();
    let username = "sessionuser";
    let auth_token = "Sup3rS3cret!";
    let enc_key = common::fixed_enc_key_b64();
    common::seed_user(username, auth_token);

    let app = build_app();
    let payload = format!(
        "username={}&auth_token={}&enc_key={}",
        urlencoding::encode(username),
        urlencoding::encode(auth_token),
        urlencoding::encode(&enc_key)
    );

    let response = app
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

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read login body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json response");
    assert_eq!(json["status"], "success");
    assert_eq!(json["username"], username);

    let session = session::session_context(SessionRequest {
        authorization: Some(&common::auth_header(auth_token)),
        auth_user: Some(username),
        encryption_key: Some(&enc_key),
        guest_session: None,
    })
    .expect("session context after login");

    assert_eq!(session.username.as_deref(), Some(username));
    assert_eq!(session.session_id, username);
    assert_eq!(
        std::str::from_utf8(&session.encryption_key.expect("enc key present")).unwrap(),
        enc_key
    );
}

#[tokio::test]
async fn login_rejects_plaintext_password_payload() {
    common::init_tracing();
    let _guard = lock_test_mutex();
    let _workspace = setup_workspace();
    let username = "plaintext-user";
    common::seed_user(username, "derived-auth-token");

    let app = build_app();
    let payload = format!(
        "username={}&password={}",
        urlencoding::encode(username),
        urlencoding::encode("hunter2")
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login plaintext");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_bootstrap_survives_cache_clear() {
    common::init_tracing();
    let _guard = lock_test_mutex();
    let _workspace = setup_workspace();
    let username = "cache-user";
    let auth_token = "persisted-token";
    common::seed_user_with_profile(
        username,
        auth_token,
        "premium",
        Some("my-set"),
        Some("premium-model"),
        false,
        true,
    );

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), username, auth_token).await;
    session::clear_in_memory_state_for_tests();

    let response = app
        .oneshot(
            client
                .request(Method::GET, "/auth/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /auth/bootstrap after cache clear");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read bootstrap body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("bootstrap json");
    assert_eq!(json["logged_in"], true);
    assert_eq!(json["username"], username);
    assert_eq!(json["user_tier"], "premium");
    assert_eq!(json["last_set"], "my-set");
    assert_eq!(json["last_model"], "premium-model");
    assert_eq!(json["render_markdown"], false);
    assert_eq!(json["autoplay_tts"], true);
}
