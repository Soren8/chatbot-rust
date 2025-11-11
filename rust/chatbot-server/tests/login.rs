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
async fn login_get_renders_form_with_security_headers() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

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
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "testuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

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

#[tokio::test]
async fn csrf_token_is_stable_for_existing_session() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();

    let first_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("first GET /login");

    assert_eq!(first_response.status(), StatusCode::OK);
    let set_cookie = first_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let first_body = to_bytes(first_response.into_body(), 64 * 1024)
        .await
        .expect("read first body");
    let first_csrf =
        common::extract_csrf_token(std::str::from_utf8(&first_body).expect("utf8 body"))
            .expect("csrf token in first response");

    let cookie_header = common::extract_cookie(&set_cookie);

    let second_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("second GET /login");

    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = to_bytes(second_response.into_body(), 64 * 1024)
        .await
        .expect("read second body");
    let second_csrf =
        common::extract_csrf_token(std::str::from_utf8(&second_body).expect("utf8 body"))
            .expect("csrf token in second response");

    assert_eq!(
        first_csrf, second_csrf,
        "csrf token should remain stable within a session"
    );
}

#[tokio::test]
async fn session_context_reflects_logged_in_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "sessionuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

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

    let initial_cookie = get_response
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
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&initial_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("set-cookie after login")
        .to_owned();

    let cookie_header = common::extract_cookie(&login_cookie);
    let session =
        session::session_context(Some(&cookie_header)).expect("session context after login");

    assert_eq!(
        session.username.as_deref(),
        Some(username),
        "username should be stored in session context"
    );
    assert_eq!(
        session.session_id, username,
        "session id should track the username after login"
    );
    let encryption_key = session
        .encryption_key
        .expect("encryption key present after login");
    assert!(
        !encryption_key.is_empty(),
        "encryption key bytes should not be empty"
    );
}

#[tokio::test]
async fn logout_clears_session_username() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "logoutuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

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

    let initial_cookie = get_response
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
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&initial_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("login set-cookie")
        .to_owned();
    let cookie_header = common::extract_cookie(&login_cookie);

    let logout_response = app
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /logout");

    assert_eq!(logout_response.status(), StatusCode::FOUND);
    let logout_cookie = logout_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("logout set-cookie");
    assert!(
        logout_cookie.contains("session="),
        "logout should include session cookie"
    );

    let logout_cookie_header = common::extract_cookie(logout_cookie);
    let session_after_logout = session::session_context(Some(&logout_cookie_header))
        .expect("session context after logout");

    assert!(
        session_after_logout.username.is_none(),
        "username should be cleared after logout"
    );
    assert!(
        session_after_logout.encryption_key.is_none(),
        "encryption key should be cleared after logout"
    );
}
