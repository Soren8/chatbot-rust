use std::{
    env,
    fs::File,
    io::Write,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

struct LoginEnv {
    data_dir: tempfile::TempDir,
}

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn ensure_env() -> PathBuf {
    static ENV_STATE: OnceLock<LoginEnv> = OnceLock::new();

    let env_state = ENV_STATE.get_or_init(|| {
        common::ensure_pythonpath();
        common::init_tracing();
        env::set_var("SECRET_KEY", "test_secret_key");

        let dir = TempDir::new().expect("temp data dir");
        env::set_var("HOST_DATA_DIR", dir.path());
        common::configure_python_env(dir.path());

        LoginEnv { data_dir: dir }
    });

    env::set_var("HOST_DATA_DIR", env_state.data_dir.path());
    env_state.data_dir.path().to_path_buf()
}

fn build_app() -> axum::Router {
    ensure_env();
    bridge::initialize_python().expect("python init");
    let static_root = resolve_static_root();
    build_router(static_root)
}

#[tokio::test]
async fn login_get_renders_form_with_security_headers() {
    if !common::ensure_flask_available() {
        eprintln!("skipping login_get_renders_form_with_security_headers: flask not available");
        return;
    }
    common::init_tracing();

    let _guard = test_mutex().lock().unwrap();

    let data_dir = ensure_env();
    common::configure_python_env(data_dir.as_path());
    std::fs::write(data_dir.join("users.json"), "{}").expect("reset users");

    let app = build_app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");

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
        body_str.contains("<form action=\"/login\" method=\"post\">"),
        "login form markup present"
    );

    let csrf = common::extract_csrf_token(body_str).expect("csrf token embedded in login form");
    assert!(
        !csrf.is_empty(),
        "csrf token extracted from login form should not be empty"
    );
}

#[tokio::test]
async fn login_flow_sets_session_cookie() {
    if !common::ensure_flask_available() {
        eprintln!("skipping login_flow_sets_session_cookie: flask not available");
        return;
    }
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let data_dir = ensure_env();
    common::configure_python_env(data_dir.as_path());

    let password = "Sup3rS3cret!";
    let username = "testuser";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let users_json = data_dir.join("users.json");
    let mut file = File::create(&users_json).expect("users.json create");
    let payload = json!({
        username: {
            "password": hashed,
            "tier": "free"
        }
    });
    file.write_all(serde_json::to_string_pretty(&payload).unwrap().as_bytes())
        .expect("write users");

    let app = build_app();

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

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let post_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let location = post_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert_eq!(location, "/");

    let set_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("set-cookie on login");
    assert!(set_cookie.starts_with("session="));
}
