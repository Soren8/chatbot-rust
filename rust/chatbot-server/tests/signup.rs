use std::{
    env,
    fs::File,
    io::BufReader,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use urlencoding::encode;

mod common;

#[tokio::test]
async fn signup_get_renders_form_with_security_headers() {
    if !common::ensure_flask_available() {
        eprintln!("skipping signup_get_renders_form_with_security_headers: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "test_secret_key");

    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());
    common::configure_python_env(data_dir.path());

    let users_file = data_dir.path().join("users.json");
    if !users_file.exists() {
        std::fs::create_dir_all(data_dir.path()).expect("create host data dir");
        std::fs::write(&users_file, "{}").expect("initialize users.json");
    }

    bridge::initialize_python().expect("python init");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
    if !common::ensure_flask_available() {
        eprintln!("skipping signup_flow_creates_user_record: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "test_secret_key");

    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());
    common::configure_python_env(data_dir.path());

    bridge::initialize_python().expect("python init");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
                .method("POST")
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

    let users_file = data_dir.path().join("users.json");
    let users_reader = BufReader::new(File::open(&users_file).expect("users.json exists"));
    let users: Value = serde_json::from_reader(users_reader).expect("valid users json");
    assert!(users.get(&username).is_some(), "signup persisted user");
}
