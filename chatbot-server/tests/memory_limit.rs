use std::{env, fs};
use axum::{
    body::Body,
    http::{header, Method, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

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
    let client = common::AuthedClient::login(app.clone(), username, password).await;

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
            client
                .request(Method::POST, "/update_memory")
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
            client
                .request(Method::POST, "/update_memory")
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
            client
                .request(Method::POST, "/update_system_prompt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(prompt_bytes))
                .unwrap(),
        )
        .await
        .expect("POST /update_system_prompt");

    assert_eq!(update_prompt_response.status(), StatusCode::OK);
}
