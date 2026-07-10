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