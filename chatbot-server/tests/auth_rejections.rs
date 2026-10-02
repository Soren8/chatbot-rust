//! Given isolated account stores and fresh browser sessions, when invalid login and signup submissions are sent, then handlers preserve their current rejection statuses, messages, and authentication state.

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::user_store::{CreateOutcome, UserStore};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::Value;
use tower::ServiceExt;

mod common;

const PASSWORD: &str = "Sup3rS3cret!";

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn build_app() -> axum::Router {
    build_router(resolve_static_root())
}

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

async fn get_csrf(app: &axum::Router, path: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("GET auth form");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();
    let cookie = common::extract_cookie(&set_cookie);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read auth form");
    let body = std::str::from_utf8(&body).expect("utf8 auth form");
    let csrf = common::extract_csrf_token(body).expect("csrf token");
    (cookie, csrf)
}

async fn post_form(
    app: &axum::Router,
    path: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> Response<Body> {
    let body = fields
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .expect("POST auth form")
}

async fn assert_api_error(response: Response<Body>, status: StatusCode, message: &str) {
    assert_eq!(response.status(), status);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read API error body");
    let body: Value = serde_json::from_slice(&body).expect("JSON API error body");
    assert_eq!(body["error"], message);
}

#[tokio::test]
async fn wrong_password_does_not_set_user_encryption_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "wrongpassuser";
    seed_user(username, PASSWORD);
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login",
        Some(&cookie),
        &[("username", username), ("password", "wrong-password"), ("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert!(
        set_cookies
            .iter()
            .all(|cookie| !cookie.starts_with(&format!("enc_key-{username}="))),
        "failed login must not set the account encryption-key cookie"
    );
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "Invalid credentials");
}

#[tokio::test]
async fn unknown_username_has_same_credentials_error() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login",
        Some(&cookie),
        &[("username", "unknownuser"), ("password", PASSWORD), ("csrf_token", &csrf)],
    )
    .await;
    assert_api_error(response, StatusCode::UNAUTHORIZED, "Invalid credentials").await;
}

#[tokio::test]
async fn empty_login_fields_are_rejected() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    for (username, password) in [("", PASSWORD), ("validuser", "")] {
        let response = post_form(
            &app,
            "/login",
            Some(&cookie),
            &[("username", username), ("password", password), ("csrf_token", &csrf)],
        )
        .await;
        assert_api_error(response, StatusCode::UNAUTHORIZED, "Invalid credentials").await;
    }
}

#[tokio::test]
async fn invalid_login_csrf_redirects_without_authenticating() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "csrfuser";
    seed_user(username, PASSWORD);
    let app = build_app();
    let (cookie, _) = get_csrf(&app, "/login").await;

    for fields in [
        vec![("username", username), ("password", PASSWORD)],
        vec![
            ("username", username),
            ("password", PASSWORD),
            ("csrf_token", "invalid-csrf"),
        ],
    ] {
        let response = post_form(&app, "/login", Some(&cookie), &fields).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/login");
    }

    let home = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / after rejected login");
    assert_eq!(home.status(), StatusCode::OK);
    let body = to_bytes(home.into_body(), 128 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("data-logged-in=\"false\""));
}

#[tokio::test]
async fn invalid_username_characters_are_rejected_by_login() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login",
        Some(&cookie),
        &[("username", "bad.user"), ("password", PASSWORD), ("csrf_token", &csrf)],
    )
    .await;
    assert_api_error(response, StatusCode::UNAUTHORIZED, "Invalid credentials").await;
}

#[tokio::test]
async fn remember_without_cookie_is_expired() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login/remember",
        Some(&cookie),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_api_error(
        response,
        StatusCode::UNAUTHORIZED,
        "Remembered session expired. Sign in again.",
    )
    .await;
}

#[tokio::test]
async fn remember_with_bad_csrf_is_rejected() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, _) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login/remember",
        Some(&cookie),
        &[("csrf_token", "bad-csrf")],
    )
    .await;
    assert_api_error(response, StatusCode::UNAUTHORIZED, "Session expired. Sign in again.").await;
}

#[tokio::test]
async fn forget_without_username_is_rejected() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login/forget",
        Some(&cookie),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_api_error(response, StatusCode::BAD_REQUEST, "username is required").await;
}

#[tokio::test]
async fn forget_with_bad_csrf_is_rejected() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, _) = get_csrf(&app, "/login").await;

    let response = post_form(
        &app,
        "/login/forget",
        Some(&cookie),
        &[("username", "forgetuser"), ("csrf_token", "bad-csrf")],
    )
    .await;
    assert_api_error(response, StatusCode::UNAUTHORIZED, "Session expired. Sign in again.").await;
}

#[tokio::test]
async fn empty_signup_fields_are_rejected() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/signup").await;

    for (username, password) in [("", PASSWORD), ("newuser", "")] {
        let response = post_form(
            &app,
            "/signup",
            Some(&cookie),
            &[("username", username), ("password", password), ("csrf_token", &csrf)],
        )
        .await;
        assert_api_error(response, StatusCode::BAD_REQUEST, "Username and password required.").await;
    }
}

#[tokio::test]
async fn bad_signup_csrf_redirects_without_creating_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, _) = get_csrf(&app, "/signup").await;
    let username = "signupcsrfuser";

    let response = post_form(
        &app,
        "/signup",
        Some(&cookie),
        &[("username", username), ("password", PASSWORD), ("csrf_token", "bad-csrf")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");

    let store = UserStore::new().expect("user store");
    assert!(!store.validate_user(username, PASSWORD).expect("check user"));
}

#[tokio::test]
async fn invalid_username_characters_are_rejected_by_signup() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let (cookie, csrf) = get_csrf(&app, "/signup").await;

    let response = post_form(
        &app,
        "/signup",
        Some(&cookie),
        &[("username", "bad.user"), ("password", PASSWORD), ("csrf_token", &csrf)],
    )
    .await;
    assert_api_error(
        response,
        StatusCode::BAD_REQUEST,
        "Username may only include letters, numbers, '_' or '-'",
    )
    .await;
}

#[tokio::test]
async fn duplicate_signup_preserves_original_password() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "duplicateuser";
    seed_user(username, PASSWORD);
    let app = build_app();
    let (signup_cookie, signup_csrf) = get_csrf(&app, "/signup").await;

    let response = post_form(
        &app,
        "/signup",
        Some(&signup_cookie),
        &[
            ("username", username),
            ("password", "DifferentPassword123!"),
            ("csrf_token", &signup_csrf),
        ],
    )
    .await;
    assert_api_error(response, StatusCode::BAD_REQUEST, "User already exists.").await;

    let (login_cookie, login_csrf) = get_csrf(&app, "/login").await;
    let login = post_form(
        &app,
        "/login",
        Some(&login_cookie),
        &[("username", username), ("password", PASSWORD), ("csrf_token", &login_csrf)],
    )
    .await;
    assert_eq!(login.status(), StatusCode::FOUND);
    assert_eq!(login.headers()[header::LOCATION], "/");
}
