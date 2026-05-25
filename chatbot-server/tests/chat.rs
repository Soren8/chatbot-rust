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
async fn chat_endpoint_returns_stubbed_stream() {
    let _guard = test_mutex().lock().unwrap();

    let log_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    {
        let make_writer_buf = log_buf.clone();
        struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut inner = self.0.lock().unwrap();
                inner.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(move || BufWriter(make_writer_buf.clone()))
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let guest_session = "chat-guest";

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "Hello from test ".to_string(),
            "<think>plan</think>".to_string(),
            "final chunk".to_string(),
        ])
        .expect("chunk json"),
    );

    let app = build_app();
    let payload = json!({
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
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let content_type = chat_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(content_type.starts_with("text/plain"));
    assert!(chat_response.headers().get(header::TRANSFER_ENCODING).is_none());

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");

    for indicator in [
        "Error: bridge error",
        "Failed to load resource",
        "500 (Internal Server Error)",
        "Internal Server Error",
        "[Error]",
        "bridge error",
        "Traceback (most recent call last):",
        "Traceback",
        "PyErr",
        "NameError",
        "TypeError",
        "ValueError",
        "RuntimeError",
        "Exception:",
    ] {
        assert!(
            !body_text.contains(indicator),
            "chat returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    let logs = String::from_utf8_lossy(&log_buf.lock().unwrap()).to_string();
    for ind in ["Internal Server Error", "ERROR", "bridge error", "Traceback"] {
        assert!(
            !logs.contains(ind),
            "server logs contained error indicator '{}': {}",
            ind,
            logs
        );
    }

    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
    assert!(body_text.contains("Hello from test "));
    assert!(body_text.contains("<think>plan</think>"));
    assert!(body_text.contains("final chunk"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

#[tokio::test]
async fn chat_stream_persists_history_for_logged_in_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    const USERNAME: &str = "persisted_user";
    const AUTH_TOKEN: &str = "S3cur3Pass!";
    let enc_key = common::fixed_enc_key_b64();
    common::seed_user(USERNAME, AUTH_TOKEN);

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), USERNAME, AUTH_TOKEN).await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["streamed chunk".to_string()]).expect("chunk json"),
    );

    let payload = json!({
        "message": "Hello from rust",
        "system_prompt": "Custom prompt",
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
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let _ = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("drain chat body");

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    let persistence = DataPersistence::new().expect("data persistence init");
    let loaded = persistence
        .load_set(
            USERNAME,
            "default",
            Some(EncryptionMode::Fernet(enc_key.as_bytes())),
        )
        .expect("load persisted set");

    assert!(loaded.encrypted);
    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Hello from rust");
    assert!(loaded.history[0].1.contains("streamed chunk"));
    assert_eq!(loaded.system_prompt, "Custom prompt");
}
