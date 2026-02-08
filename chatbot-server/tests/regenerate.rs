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
async fn regenerate_endpoint_streams_response() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();

    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

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
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
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
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
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
        panic!(
            "regenerate request failed: status={} body={}",
            status, body_text
        );
    }
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );
    let body_text = std::str::from_utf8(&body_bytes).expect("regen utf8");

    assert!(body_text.contains("regen chunk 1"));
    assert!(body_text.contains("regen final"));

    let error_indicators = [
        "Error: bridge error",
        "Failed to load resource",
        "500 (Internal Server Error)",
        "Internal Server Error",
        "[Error]",
        "Traceback",
    ];

    for indicator in error_indicators {
        assert!(
            !body_text.contains(indicator),
            "regenerate returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    let error_count = chatbot_server::test_instrumentation::take_error_count();
    assert_eq!(
        error_count, 0,
        "server emitted {} HTTP 5xx responses",
        error_count
    );

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

#[tokio::test]
async fn regenerate_stream_replaces_history_entry_for_logged_in_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "regen_user";
    const PASSWORD: &str = "R3genSecret!";

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

    assert_eq!(login_get.status(), StatusCode::OK);
    update_session_cookie(&mut session_cookie, &login_get);
    let login_body = to_bytes(login_get.into_body(), 64 * 1024)
        .await
        .expect("read login body");
    let login_html = std::str::from_utf8(&login_body).expect("login utf8");
    let login_csrf = common::extract_csrf_token(login_html).expect("login csrf token");

    let initial_cookie = session_cookie
        .clone()
        .expect("session cookie after GET /login");

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

    let login_status = login_post.status();
    assert!(
        login_status == StatusCode::SEE_OTHER || login_status == StatusCode::FOUND,
        "expected redirect after login, got {login_status}"
    );
    update_session_cookie(&mut session_cookie, &login_post);
    let _ = to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .expect("drain login POST body");

    let cookie_for_home = session_cookie.clone().unwrap_or(initial_cookie);

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &cookie_for_home)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);
    update_session_cookie(&mut session_cookie, &home_response);
    let home_cookie = session_cookie.clone().unwrap_or(cookie_for_home);

    let home_body = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let home_text = std::str::from_utf8(&home_body).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

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
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &home_cookie)
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
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &home_cookie)
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
    assert!(
        regen_text.contains("regen chunk"),
        "regenerate stream should include stub chunk"
    );

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    let store = UserStore::new().expect("open user store");
    let key = store
        .derive_encryption_key(USERNAME, PASSWORD)
        .expect("derive encryption key");

    let persistence = DataPersistence::new().expect("data persistence init");
    let loaded = persistence
        .load_set(
            USERNAME,
            "default",
            Some(EncryptionMode::Fernet(key.as_slice())),
        )
        .expect("load persisted set");

    assert_eq!(
        loaded.history.len(),
        1,
        "regenerate should replace existing entry"
    );
    assert_eq!(loaded.history[0].0, "Initial prompt");
    assert!(
        loaded.history[0].1.contains("regen chunk"),
        "assistant response should reflect regenerated content"
    );
    assert_eq!(
        loaded.system_prompt, "Regenerate prompt",
        "system prompt should remain stored alongside regenerated history"
    );
}

#[tokio::test]
async fn regenerate_updates_system_prompt_in_history() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "regen_sys_user";
    const PASSWORD: &str = "SysP@ss!";

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

    // Login
    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
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
        .expect("POST /login");
    
    update_session_cookie(&mut session_cookie, &login_post);
    let auth_cookie = session_cookie.unwrap_or(initial_cookie);

    // Initial Chat
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["init".to_string()]).unwrap(),
    );

    // Actually, other tests extract CSRF from home page. Let's do that to be safe.
    let home_res = app.clone().oneshot(Request::builder().uri("/").header(header::COOKIE, &auth_cookie).body(Body::empty()).unwrap()).await.unwrap();
    let home_body = to_bytes(home_res.into_body(), 1024*1024).await.unwrap();
    let home_text = std::str::from_utf8(&home_body).unwrap();
    let csrf_token = CSRF_META_RE.captures(home_text).unwrap().get(1).unwrap().as_str().to_owned();

    let initial_payload = json!({
        "message": "Hi",
        "system_prompt": "Old System Prompt",
        "set_name": "default",
        "model_name": "default",
    });

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &auth_cookie)
                .body(Body::from(serde_json::to_vec(&initial_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Regenerate with NEW system prompt
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["regen".to_string()]).unwrap(),
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
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &auth_cookie)
                .body(Body::from(serde_json::to_vec(&regen_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(regen_res.status(), StatusCode::OK);
    let _ = to_bytes(regen_res.into_body(), 1024).await.unwrap();

    // Verify Persistence
    let store = UserStore::new().unwrap();
    let key = store.derive_encryption_key(USERNAME, PASSWORD).unwrap();
    let persistence = DataPersistence::new().unwrap();
    let loaded = persistence.load_set(USERNAME, "default", Some(EncryptionMode::Fernet(key.as_slice()))).unwrap();

    assert_eq!(loaded.system_prompt, "New System Prompt", "System prompt should be updated after regenerate");
}
