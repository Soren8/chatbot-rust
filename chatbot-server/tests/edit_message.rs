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
    persistence::{DataPersistence, EncryptionMode},
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
    let key = store.derive_encryption_key(USERNAME, PASSWORD).unwrap();
    let persistence = DataPersistence::new().unwrap();
    let loaded = persistence
        .load_set(USERNAME, "default", Some(EncryptionMode::Fernet(key.as_slice())))
        .unwrap();

    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.history[0].0, "Edited message");
    assert!(loaded.history[0].1.contains("edited response"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}
