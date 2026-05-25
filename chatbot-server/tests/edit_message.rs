use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, StatusCode},
};
use chatbot_core::persistence::{DataPersistence, EncryptionMode};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn edit_message_via_regenerate_endpoint() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "edit_user";
    const AUTH_TOKEN: &str = "Ed1tSecret!";
    let enc_key = common::fixed_enc_key_b64();
    common::seed_user(USERNAME, AUTH_TOKEN);

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let client = common::AuthedClient::login(app.clone(), USERNAME, AUTH_TOKEN).await;

    // 1. Initial Chat
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["initial response".to_string()]).unwrap(),
    );

    let initial_payload = json!({
        "message": "Original message",
        "set_name": "default",
        "model_name": "default",
    });

    let initial_chat = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&initial_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial_chat.status(), StatusCode::OK);
    let _ = to_bytes(initial_chat.into_body(), 512 * 1024).await.unwrap();

    // 2. Edit the message via /regenerate
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["edited response".to_string()]).unwrap(),
    );

    let edit_payload = json!({
        "message": "Edited message",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let edit_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&edit_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(edit_response.status(), StatusCode::OK);
    let edit_body = to_bytes(edit_response.into_body(), 512 * 1024).await.unwrap();
    let edit_text = std::str::from_utf8(&edit_body).unwrap();
    assert!(edit_text.contains("edited response"));

    // 3. Verify persistence
    let persistence = DataPersistence::new().unwrap();
    let loaded = persistence
        .load_set(
            USERNAME,
            "default",
            Some(EncryptionMode::Fernet(enc_key.as_bytes())),
        )
        .unwrap();

    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Edited message");
    assert!(loaded.history[0].1.contains("edited response"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}
