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
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /signup");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();

    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present");
    assert!(
        set_cookie.contains("session"),
        "session cookie should include session id"
    );

    let csp = headers
        .get("Content-Security-Policy")
        .and_then(|value| value.to_str().ok())
        .expect("CSP header present");
    assert!(
        csp.contains("default-src 'self'"),
        "CSP header should include default-src"
    );

    for name in [
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
    ] {
        assert!(
            headers.get(name).is_some(),
            "expected {name} header to be present"
        );
    }

    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let body_str = std::str::from_utf8(&body).expect("utf8 response body");
    assert!(
        body_str.contains("<form action=\"/signup\" method=\"post\">"),
        "signup form markup present"
    );

    let csrf = common::extract_csrf_token(body_str).expect("csrf token embedded in signup form");
    assert!(
        !csrf.is_empty(),
        "csrf token extracted from signup form should not be empty"
    );
}

#[tokio::test]
async fn signup_flow_creates_user_record() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();

    let app = build_app();

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /signup");

    assert_eq!(get_response.status(), StatusCode::OK);
    let set_cookie = get_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(get_response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let username = format!(
        "testuser_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let payload = format!(
        "username={}&password={}&csrf_token={}",
        encode(&username),
        encode("Password123"),
        encode(&csrf)
    );

    let post_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/signup")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /signup");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let location = post_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert_eq!(location, "/login");

    let users_file = workspace.path().join("users.json");
    let users_reader = BufReader::new(File::open(&users_file).expect("users.json exists"));
    let users: Value = serde_json::from_reader(users_reader).expect("valid users json");
    assert!(users.get(&username).is_some(), "signup persisted user");
}
