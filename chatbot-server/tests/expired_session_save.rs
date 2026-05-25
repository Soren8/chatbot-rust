use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;
use std::env;

mod common;

#[tokio::test]
async fn save_memory_checks_expected_auth() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let invalid_auth = "Bearer INVALID_SESSION_ID";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_memory")
                .header(header::AUTHORIZATION, invalid_auth)
                .header("X-Auth-User", "ghost")
                .header("X-Enc-Key", common::fixed_enc_key_b64())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "memory": "test memory",
                        "set_name": "default",
                        "logged_in": true,
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /update_memory");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Should return 401 when logged_in=true but session is guest");
}

#[tokio::test]
async fn save_system_prompt_checks_expected_auth() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let invalid_auth = "Bearer INVALID_SESSION_ID";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_system_prompt")
                .header(header::AUTHORIZATION, invalid_auth)
                .header("X-Auth-User", "ghost")
                .header("X-Enc-Key", common::fixed_enc_key_b64())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "system_prompt": "test prompt",
                        "set_name": "default",
                        "logged_in": true,
                    }))
                    .expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /update_system_prompt");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Should return 401 when logged_in=true but session is guest");
}
