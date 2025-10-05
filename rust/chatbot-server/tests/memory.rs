use std::{env, fs};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn memory_and_prompt_endpoints_round_trip() {
    if !common::ensure_flask_available() {
        eprintln!("skipping memory_and_prompt_endpoints_round_trip: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());

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

    let users_json = data_dir.path().join("users.json");
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

    bridge::initialize_python().expect("python init");

    Python::with_gil(|py| {
        let code = std::ffi::CString::new(
            r#"
from app.config import Config

Config.LLM_PROVIDERS = [{
    'provider_name': 'default',
    'type': 'openai',
    'model_name': 'gpt-test',
    'base_url': 'https://api.openai.com/v1',
    'api_key': 'test-key',
    'context_size': 4096,
}]
Config.DEFAULT_LLM = Config.LLM_PROVIDERS[0]
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, None)
            .expect("configure openai provider");
    });

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let login_page = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");

    assert_eq!(login_page.status(), StatusCode::OK);
    let mut session_cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("initial session cookie");

    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("read login body");
    let login_csrf =
        common::extract_csrf_token(std::str::from_utf8(&login_body).expect("login utf8"))
            .expect("csrf token in login form");

    let form_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&login_csrf),
    );

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(form_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(login_response.status(), StatusCode::FOUND);
    if let Some(value) = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");

    assert_eq!(home_response.status(), StatusCode::OK);
    if let Some(value) = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    let home_body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    let update_memory_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_memory")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
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
            Request::builder()
                .method(Method::POST)
                .uri("/update_system_prompt")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
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
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
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

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "user_message": "Please summarise the meeting",
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
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
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

    // Ensure the encrypted memory and history files were created for the user.
    let user_dir = data_dir.path().join("user_sets").join(username);
    assert!(user_dir.exists(), "user data directory missing");
    let memory_file = user_dir.join("default_memory.txt");
    let history_file = user_dir.join("default_history.json");
    assert!(memory_file.exists(), "memory file missing");
    assert!(history_file.exists(), "history file missing");
}
