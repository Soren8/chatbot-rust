use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
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

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

#[tokio::test]
async fn regenerate_endpoint_streams_response() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let guest_session = "regen-guest";
    let app = build_app();

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["initial chunk".to_string()]).expect("chunk json"),
    );

    let chat_payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header("X-Guest-Session", guest_session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&chat_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let _ = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat response body");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "regen chunk 1".to_string(),
            "<think>hidden</think>".to_string(),
            "regen final".to_string(),
        ])
        .expect("chunk json"),
    );

    let regen_payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let regen_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header("X-Guest-Session", guest_session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&regen_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate response");

    let (regen_parts, regen_body) = regen_response.into_parts();
    let status = regen_parts.status;
    let content_type = regen_parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let body_bytes = to_bytes(regen_body, 512 * 1024)
        .await
        .expect("read regenerate body");
    if status != StatusCode::OK {
        let body_text = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        panic!("regenerate request failed: status={} body={}", status, body_text);
    }

    assert!(content_type.starts_with("text/plain"));
    let body_text = std::str::from_utf8(&body_bytes).expect("regen utf8");
    assert!(body_text.contains("regen chunk 1"));
    assert!(body_text.contains("regen final"));

    for indicator in [
        "Error: bridge error",
        "Failed to load resource",
        "500 (Internal Server Error)",
        "Internal Server Error",
        "[Error]",
        "Traceback",
    ] {
        assert!(
            !body_text.contains(indicator),
            "regenerate returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

#[tokio::test]
async fn regenerate_stream_replaces_history_entry_for_logged_in_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    const USERNAME: &str = "regen_user";
    const PASSWORD: &str = "R3genSecret!";
    common::seed_user(USERNAME, PASSWORD);
    let enc_key = common::derive_storage_key(USERNAME, PASSWORD);

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), USERNAME, PASSWORD).await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["initial chunk".to_string()]).expect("chunk json"),
    );

    let initial_payload = json!({
        "message": "Initial prompt",
        "system_prompt": "Regenerate prompt",
        "set_name": "default",
        "model_name": "default",
    });

    let initial_chat = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&initial_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(initial_chat.status(), StatusCode::OK);
    let _ = to_bytes(initial_chat.into_body(), 512 * 1024)
        .await
        .expect("drain initial chat body");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["regen chunk".to_string()]).expect("chunk json"),
    );

    let regen_payload = json!({
        "message": "Initial prompt",
        "system_prompt": "Regenerate prompt",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let regen_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&regen_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate response");

    assert_eq!(regen_response.status(), StatusCode::OK);
    let regen_body = to_bytes(regen_response.into_body(), 512 * 1024)
        .await
        .expect("read regen body");
    let regen_text = std::str::from_utf8(&regen_body).expect("regen utf8");
    assert!(regen_text.contains("regen chunk"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    let persistence = DataPersistence::new().expect("data persistence init");
    let loaded = persistence
        .load_set(
            USERNAME,
            "default",
            Some(EncryptionMode::Fernet(enc_key.as_bytes())),
        )
        .expect("load persisted set");

    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Initial prompt");
    assert!(loaded.history[0].1.contains("regen chunk"));
    assert_eq!(loaded.system_prompt, "Regenerate prompt");
}

#[tokio::test]
async fn regenerate_updates_system_prompt_in_history() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    const USERNAME: &str = "regen_sys_user";
    const PASSWORD: &str = "SysP@ss!";
    common::seed_user(USERNAME, PASSWORD);
    let enc_key = common::derive_storage_key(USERNAME, PASSWORD);

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), USERNAME, PASSWORD).await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["init".to_string()]).expect("chunk json"),
    );

    let initial_payload = json!({
        "message": "Hi",
        "system_prompt": "Old System Prompt",
        "set_name": "default",
        "model_name": "default",
    });

    let initial_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&initial_payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    assert_eq!(initial_response.status(), StatusCode::OK);
    let _ = to_bytes(initial_response.into_body(), 1024 * 1024).await.unwrap();

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["regen".to_string()]).expect("chunk json"),
    );

    let regen_payload = json!({
        "message": "Hi",
        "system_prompt": "New System Prompt",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let regen_res = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&regen_payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate");

    assert_eq!(regen_res.status(), StatusCode::OK);
    let _ = to_bytes(regen_res.into_body(), 1024).await.unwrap();

    let persistence = DataPersistence::new().unwrap();
    let loaded = persistence
        .load_set(
            USERNAME,
            "default",
            Some(EncryptionMode::Fernet(enc_key.as_bytes())),
        )
        .unwrap();

    assert_eq!(loaded.system_prompt, "New System Prompt");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}
