use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn api_errors_return_json_body() {
    common::init_tracing();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_preferences")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"last_set":"default"}"#))
                .unwrap(),
        )
        .await
        .expect("POST /update_preferences");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "expected application/json content-type, got {content_type}"
    );

    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("read body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("error response should be JSON");

    assert_eq!(payload, json!({ "error": "Invalid CSRF token" }));
}

/// /regenerate prepare failures with a user message become a saved [Error]
/// assistant turn (200 text/plain) so the client can regenerate.
#[tokio::test]
async fn regenerate_out_of_range_is_saved_as_chat_turn() {
    common::init_tracing();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let home = app
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
    let cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("cookie")
        .to_owned();
    let body = to_bytes(home.into_body(), 256 * 1024).await.expect("home body");
    let html = std::str::from_utf8(&body).expect("utf8");
    let csrf = html
        .split("csrf-token\" content=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("csrf");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "pair_index": 99
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.expect("read");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[Error]")
            && (text.contains("pair_index") || text.contains("out of range") || text.contains("required")),
        "unexpected chat-error body: {text}"
    );
}