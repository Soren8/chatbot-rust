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
async fn memory_and_prompt_endpoints_round_trip() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "assistant response chunk ".to_string(),
            "<think>hidden</think>".to_string(),
            "final".to_string(),
        ])
        .expect("chunk json"),
    );

    let username = "memory_user";
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

    let update_memory_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/update_memory")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "memory": "Remember to review notes",
                        "set_name": "default",
                        "encrypted": false,
                    }))
                    .expect("memory payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /update_memory");

    assert_eq!(update_memory_response.status(), StatusCode::OK);
    let memory_body = to_bytes(update_memory_response.into_body(), 128 * 1024)
        .await
        .expect("memory body");
    let memory_json: serde_json::Value = serde_json::from_slice(&memory_body).expect("memory json");
    assert_eq!(
        memory_json.get("status"),
        Some(&serde_json::Value::String("success".into()))
    );

    let update_prompt_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/update_system_prompt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "system_prompt": "You are a diligent assistant",
                        "set_name": "default",
                        "encrypted": false,
                    }))
                    .expect("prompt payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /update_system_prompt");

    assert_eq!(update_prompt_response.status(), StatusCode::OK);

    let chat_payload = json!({
        "message": "Please summarise the meeting",
        "set_name": "default",
        "model_name": "default",
    });

    let chat_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&chat_payload).expect("chat payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let chat_body = to_bytes(chat_response.into_body(), 256 * 1024)
        .await
        .expect("chat body");
    assert!(chat_body.len() > 0, "chat should stream response");

    let load_before_delete = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set before delete");

    assert_eq!(load_before_delete.status(), StatusCode::OK);
    let load_before_body = to_bytes(load_before_delete.into_body(), 256 * 1024)
        .await
        .expect("load before delete body");
    let load_before_json: serde_json::Value =
        serde_json::from_slice(&load_before_body).expect("load before delete json");
    let history_entry = load_before_json
        .get("history")
        .and_then(|value| value.as_array())
        .and_then(|arr| arr.first())
        .and_then(|pair| pair.as_array())
        .expect("history entry after chat");
    let stored_user = history_entry[0].as_str().expect("stored user message");
    let stored_ai = history_entry[1].as_str().expect("stored ai message");

    let delete_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/delete_message")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 0,
                        "user_message": stored_user,
                        "ai_message": stored_ai,
                        "set_name": "default",
                    }))
                    .expect("delete payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message");

    assert_eq!(delete_response.status(), StatusCode::OK);
    let delete_body = to_bytes(delete_response.into_body(), 128 * 1024)
        .await
        .expect("delete body");
    let delete_json: serde_json::Value = serde_json::from_slice(&delete_body).expect("delete json");
    assert_eq!(
        delete_json.get("status"),
        Some(&serde_json::Value::String("success".into()))
    );

    let load_response = app
        .oneshot(
            client
                .request(Method::POST, "/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set");

    assert_eq!(load_response.status(), StatusCode::OK);
    let load_body = to_bytes(load_response.into_body(), 256 * 1024)
        .await
        .expect("load body");
    let load_json: serde_json::Value = serde_json::from_slice(&load_body).expect("load json");
    assert_eq!(
        load_json
            .get("history")
            .and_then(|value| value.as_array())
            .map(|arr| arr.len())
            .unwrap_or_default(),
        0,
        "history should be empty after deletion",
    );

    // Ensure the encrypted sets.json exists and individual files are GONE.
    let user_dir = workspace.path().join("user_sets").join(username);
    assert!(user_dir.exists(), "user data directory missing");
    let sets_json = user_dir.join("sets.json");
    assert!(sets_json.exists(), "sets.json missing");
    
    let memory_file = user_dir.join("default_memory.txt");
    let history_file = user_dir.join("default_history.json");
    assert!(!memory_file.exists(), "old memory file should NOT exist");
    assert!(!history_file.exists(), "old history file should NOT exist");
}
