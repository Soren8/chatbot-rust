use std::{
    env,
    fs::File,
    io::Write,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    enc_key::EncryptionKey,
    history::HistoryService,
    user_store::UserStore,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn update_session_cookie<B>(cookie_slot: &mut Option<String>, response: &Response<B>) {
    if let Some(raw) = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        *cookie_slot = Some(common::extract_cookie(raw));
    }
}

#[tokio::test]
async fn edit_message_via_regenerate_endpoint() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "edit_user";
    const PASSWORD: &str = "Ed1tSecret!";

    let hashed = hash(PASSWORD, DEFAULT_COST).expect("hash password");
    let users_json = workspace.path().join("users.json");
    let payload = json!({
        USERNAME: {
            "password": hashed,
            "tier": "free"
        }
    });
    let mut file = File::create(&users_json).expect("create users.json");
    file.write_all(serde_json::to_string_pretty(&payload).unwrap().as_bytes())
        .expect("write users.json");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let mut session_cookie: Option<String> = None;

    // Login process
    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login response");

    update_session_cookie(&mut session_cookie, &login_get);
    let login_body = to_bytes(login_get.into_body(), 64 * 1024).await.unwrap();
    let login_html = std::str::from_utf8(&login_body).unwrap();
    let login_csrf = common::extract_csrf_token(login_html).unwrap();

    let initial_cookie = session_cookie.clone().unwrap();
    let form_body = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(USERNAME),
        urlencoding::encode(PASSWORD),
        urlencoding::encode(&login_csrf),
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &initial_cookie)
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .expect("POST /login response");

    update_session_cookie(&mut session_cookie, &login_post);
    let home_cookie = session_cookie.clone().unwrap();

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &home_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / response");

    let home_body = to_bytes(home_response.into_body(), 256 * 1024).await.unwrap();
    let home_text = std::str::from_utf8(&home_body).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let enc_key = common::derive_encryption_key_header(USERNAME, PASSWORD);

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
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::COOKIE, &home_cookie)
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
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::COOKIE, &home_cookie)
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
    let store = UserStore::new().unwrap();
    let key_bytes = store.derive_encryption_key(USERNAME, PASSWORD).unwrap();
    let key = EncryptionKey::from_header_value(std::str::from_utf8(&key_bytes).unwrap()).unwrap();
    let history = HistoryService::global().unwrap();
    let loaded = history
        .find_by_display_name(USERNAME, "default", &key)
        .unwrap()
        .expect("default set");

    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Edited message");
    assert!(loaded.history[0].1.contains("edited response"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

/// Regression: Stop mid-generation (client aborts the stream body) must still
/// leave a durable history pair and release the session generate-lock so that
/// editing the last user message (/regenerate) succeeds.
///
/// Without finalize-on-cancel, the UI shows "Error: Network response was not ok"
/// because /regenerate returns 4xx (missing pair and/or lock still held).
#[tokio::test]
async fn stop_mid_generation_then_edit_last_message_succeeds() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "stop_edit_user";
    const PASSWORD: &str = "St0pEd1t!";

    let hashed = hash(PASSWORD, DEFAULT_COST).expect("hash password");
    let users_json = workspace.path().join("users.json");
    let payload = json!({
        USERNAME: {
            "password": hashed,
            "tier": "free"
        }
    });
    let mut file = File::create(&users_json).expect("create users.json");
    file.write_all(serde_json::to_string_pretty(&payload).unwrap().as_bytes())
        .expect("write users.json");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let mut session_cookie: Option<String> = None;

    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login response");

    update_session_cookie(&mut session_cookie, &login_get);
    let login_body = to_bytes(login_get.into_body(), 64 * 1024).await.unwrap();
    let login_html = std::str::from_utf8(&login_body).unwrap();
    let login_csrf = common::extract_csrf_token(login_html).unwrap();

    let initial_cookie = session_cookie.clone().unwrap();
    let form_body = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(USERNAME),
        urlencoding::encode(PASSWORD),
        urlencoding::encode(&login_csrf),
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &initial_cookie)
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .expect("POST /login response");

    update_session_cookie(&mut session_cookie, &login_post);
    let home_cookie = session_cookie.clone().unwrap();

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &home_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / response");

    let home_body = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let home_text = std::str::from_utf8(&home_body).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let enc_key = common::derive_encryption_key_header(USERNAME, PASSWORD);

    // Slow stream so we can abort after the first chunk (simulates Stop).
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "partial-one ".to_string(),
            "partial-two ".to_string(),
            "partial-three".to_string(),
        ])
        .unwrap(),
    );
    env::set_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS", "150");

    let chat_payload = json!({
        "message": "Message before stop",
        "set_name": "default",
        "model_name": "default",
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::COOKIE, &home_cookie)
                .body(Body::from(serde_json::to_vec(&chat_payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);

    // Read only the first body frame, then drop — same as aborting the fetch.
    {
        use futures_util::StreamExt;
        let mut data_stream = chat_response.into_body().into_data_stream();
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_stream.next(),
        )
        .await
        .expect("timed out waiting for first chat chunk")
        .expect("stream ended before first chunk")
        .expect("first chunk error");
        assert!(
            !first.is_empty(),
            "expected non-empty first stream chunk before stop"
        );
        drop(data_stream);
    }

    // Allow Drop of the generator (finalize-on-cancel) to run.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["edited after stop".to_string()]).unwrap(),
    );

    // Edit last message → /regenerate (same path as the chat UI Save on edit).
    let edit_payload = json!({
        "message": "Edited after stop",
        "set_name": "default",
        "model_name": "default",
        "pair_index": 0,
    });

    let edit_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::COOKIE, &home_cookie)
                .body(Body::from(serde_json::to_vec(&edit_payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate after stop");

    let edit_status = edit_response.status();
    let edit_body = to_bytes(edit_response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let edit_text = std::str::from_utf8(&edit_body).unwrap_or("");
    assert_eq!(
        edit_status,
        StatusCode::OK,
        "edit after stop must not fail (got {edit_status}): {edit_text}"
    );
    assert!(
        edit_text.contains("edited after stop"),
        "regenerate stream missing expected text: {edit_text}"
    );

    let store = UserStore::new().unwrap();
    let key_bytes = store.derive_encryption_key(USERNAME, PASSWORD).unwrap();
    let key = EncryptionKey::from_header_value(std::str::from_utf8(&key_bytes).unwrap()).unwrap();
    let history = HistoryService::global().unwrap();
    let loaded = history
        .find_by_display_name(USERNAME, "default", &key)
        .unwrap()
        .expect("default set");

    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Edited after stop");
    assert!(loaded.history[0].1.contains("edited after stop"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
}
