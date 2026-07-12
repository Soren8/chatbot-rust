//! Production rate-limiter integration tests.

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::{config, rate_limit};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::Value;
use tower::ServiceExt;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn enable_tight_per_user_limit() {
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    config::reset();
    rate_limit::reset();
}

fn restore_disabled_limits() {
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    config::reset();
    rate_limit::reset();
}

async fn bootstrap_cookie(app: &axum::Router) -> String {
    // `/` is not rate-limited; establish a sticky session cookie first.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or(v).to_owned())
        .expect("Set-Cookie from home")
}

#[tokio::test]
async fn per_user_rate_limit_returns_429_with_retry_after() {
    let _guard = test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    enable_tight_per_user_limit();
    let _workspace = common::TestWorkspace::with_openai_provider();

    let app = build_router(resolve_static_root());
    let cookie = bootstrap_cookie(&app).await;

    for i in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/login")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /login");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} should be allowed"
        );
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("rate-limited GET /login");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .expect("Retry-After header");
    assert!(
        retry_after.parse::<u64>().unwrap_or(0) >= 1,
        "Retry-After should be >= 1, got {retry_after}"
    );

    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("JSON body");
    assert!(
        payload["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("rate limit"),
        "unexpected error payload: {payload}"
    );
    assert!(payload["retry_after"].as_u64().unwrap_or(0) >= 1);

    restore_disabled_limits();
}

#[tokio::test]
async fn health_is_not_rate_limited() {
    let _guard = test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    enable_tight_per_user_limit();
    let _workspace = common::TestWorkspace::with_openai_provider();

    let app = build_router(resolve_static_root());

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /health");
        assert_eq!(response.status(), StatusCode::OK);
    }

    restore_disabled_limits();
}
