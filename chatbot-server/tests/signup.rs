use std::{
    env,
    fs::File,
    io::BufReader,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::Value;
use tower::ServiceExt;
use urlencoding::encode;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

#[tokio::test]
async fn signup_get_renders_form_with_security_headers() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();
    let response = app
        .oneshot(Request::builder().uri("/signup").body(Body::empty()).unwrap())
        .await
        .expect("GET /signup");

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
    assert!(body_str.contains("<form action=\"/signup\" method=\"post\">"));
}

#[tokio::test]
async fn signup_flow_creates_user_record() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();
    let app = build_app();

    let username = format!(
        "testuser_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let auth_token = "Password123-derived-token";
    let payload = format!(
        "username={}&auth_token={}&salt={}",
        encode(&username),
        encode(auth_token),
        encode(&common::fixed_client_salt_b64())
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/signup")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /signup");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read signup body");
    let json: Value = serde_json::from_slice(&body).expect("signup json");
    assert_eq!(json["status"], "success");

    let users_file = workspace.path().join("users.json");
    let users_reader = BufReader::new(File::open(&users_file).expect("users.json exists"));
    let users: Value = serde_json::from_reader(users_reader).expect("valid users json");
    let user = users.get(&username).expect("signup persisted user");
    assert!(user.get("auth_hash").is_some());
    assert!(user.get("password").is_none());
}
