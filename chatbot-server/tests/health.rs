use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn health_route_returns_status_payload() {
    common::init_tracing();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /health");

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("health response JSON payload");

    assert_eq!(payload, json!({ "status": "healthy" }));
}
