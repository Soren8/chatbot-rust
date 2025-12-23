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
use std::{env, fs};

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn preferences_persistence() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "pref_user";
    let password = "password";
    let hashed = hash(password, DEFAULT_COST).expect("hash");

    let users_json = workspace.path().join("users.json");
    fs::write(
        &users_json,
        serde_json::to_string_pretty(&json!({
            username: {
                "password": hashed,
                "tier": "free"
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    // Login
    let login_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = common::extract_cookie(login_page.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    
    let login_body = to_bytes(login_page.into_body(), 128 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).unwrap()).unwrap();

    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("username={}&password={}&csrf_token={}", username, password, csrf)))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(login_resp.status(), StatusCode::FOUND);
    let cookie = if let Some(val) = login_resp.headers().get(header::SET_COOKIE) {
        common::extract_cookie(val.to_str().unwrap())
    } else {
        cookie
    };

    // Get CSRF from home
    let home = app.clone().oneshot(
        Request::builder()
            .uri("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let home_html = std::str::from_utf8(&home_body).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    // Update preferences
    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_preferences")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "last_set": "my-set",
                    "last_model": "gpt-4",
                    "render_markdown": false
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(update_resp.status(), StatusCode::OK);

    // Verify persistence via home page data
    let home_again = app.clone().oneshot(
        Request::builder()
            .uri("/")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();
    
    let home_body = to_bytes(home_again.into_body(), 1024 * 1024).await.unwrap();
    let body_str = std::str::from_utf8(&home_body).unwrap();
    
    assert!(body_str.contains(r#"lastSet": "my-set"#));
    assert!(body_str.contains(r#"lastModel": "gpt-4"#));
    assert!(body_str.contains(r#"renderMarkdown": false"#));
}
