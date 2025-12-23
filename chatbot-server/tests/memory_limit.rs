use std::{env, fs};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn memory_large_payload() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "memory_limit_user";
    let password = "Sup3rS3cret!";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let users_json = workspace.path().join("users.json");
    fs::write(
        &users_json,
        serde_json::to_string_pretty(&json!({
            username: {
                "password": hashed,
                "tier": "free"
            }
        }))
        .expect("serialize users"),
    )
    .expect("write users.json");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    // Login
    let login_page = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");

    let mut session_cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("initial session cookie");

    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("read login body");
    let login_csrf =
        common::extract_csrf_token(std::str::from_utf8(&login_body).expect("login utf8"))
            .expect("csrf token in login form");

    let form_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&login_csrf),
    );

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(form_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(login_response.status(), StatusCode::FOUND);
    if let Some(value) = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    // Get CSRF token from Home
    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");

    if let Some(value) = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    let home_body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    // Generate Moderate Memory (300KB), should now PASS (limit is 1MB)
    let moderate_memory = "a".repeat(300 * 1024);
    let payload = json!({
        "memory": moderate_memory,
        "set_name": "default",
        "encrypted": false,
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("payload bytes");

    let update_memory_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_memory")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .expect("POST /update_memory");

    assert_eq!(update_memory_response.status(), StatusCode::OK);

    // Generate Large Memory (> 1MB), should FAIL
    let large_memory = "a".repeat(1100 * 1024);
    let large_payload = json!({
        "memory": large_memory,
        "set_name": "default",
        "encrypted": false,
    });
    let large_payload_bytes = serde_json::to_vec(&large_payload).expect("large payload bytes");

    let update_large_memory_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_memory")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(large_payload_bytes))
                .unwrap(),
        )
        .await
        .expect("POST /update_memory large");

    assert_eq!(update_large_memory_response.status(), StatusCode::BAD_REQUEST);

    // Also check System Prompt moderate (300KB)
    let moderate_prompt = "b".repeat(300 * 1024);
    let prompt_payload = json!({
        "system_prompt": moderate_prompt,
        "set_name": "default",
        "encrypted": false,
    });
    let prompt_bytes = serde_json::to_vec(&prompt_payload).expect("prompt bytes");

    let update_prompt_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_system_prompt")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(prompt_bytes))
                .unwrap(),
        )
        .await
        .expect("POST /update_system_prompt");

    assert_eq!(update_prompt_response.status(), StatusCode::OK);
}
