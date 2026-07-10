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

#[tokio::test]
async fn deep_health_route_includes_dependency_checks() {
    common::init_tracing();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health?deep=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /health?deep=true");

    let http_status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body).expect("deep health response JSON payload");

    assert!(
        payload.get("checks").is_some(),
        "deep health should include checks object: {payload}"
    );
    assert!(
        payload["checks"]["history"].is_string(),
        "history check should be present: {payload}"
    );
    assert!(
        payload["checks"]["voice_service"].is_string(),
        "voice_service check should be present: {payload}"
    );

    let status = payload["status"].as_str().unwrap_or("");
    assert!(
        status == "healthy" || status == "degraded",
        "unexpected status: {status}"
    );
    let expected_code = if status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    assert_eq!(http_status, expected_code);
}
