use std::{env, fs};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn set_names_leak_repro() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "testuser";
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

    let secret_set_name = "Top Secret Plans";
    let create_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/create_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": secret_set_name})).expect("create payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /create_set");

    assert_eq!(create_response.status(), StatusCode::OK);

    // Verify privacy on disk
    let user_set_dir = workspace.path().join("user_sets").join(username);
    let sets_json_path = user_set_dir.join("sets.json");
    
    let sets_json_content = fs::read_to_string(&sets_json_path).expect("read sets.json");
    // It should NOT be valid JSON (because it's encrypted with Fernet)
    let is_json = serde_json::from_str::<serde_json::Value>(&sets_json_content).is_ok();
    assert!(!is_json, "sets.json should be encrypted, but it's valid JSON: {}", sets_json_content);
    assert!(!sets_json_content.contains(secret_set_name), "Leaked set name in encrypted sets.json!");

    // We also need to save some data to see the filenames
    let save_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "Hello",
                        "set_name": secret_set_name
                    })).expect("chat payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat");

    assert_eq!(save_response.status(), StatusCode::OK);
    let _ = to_bytes(save_response.into_body(), 1024 * 1024)
        .await
        .expect("read chat response body");

    // Filenames should NOT exist (everything is in sets.json)
    let history_file = user_set_dir.join(format!("{}_history.json", secret_set_name));
    assert!(!history_file.exists(), "History file should NOT exist with plaintext name: {}", history_file.display());
}
