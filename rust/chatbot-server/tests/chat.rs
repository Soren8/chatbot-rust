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
async fn chat_endpoint_returns_stubbed_stream() {
    let _guard = test_mutex().lock().unwrap();
    // Initialize a tracing subscriber that captures logs into an in-memory
    // buffer so we can assert no internal server errors are logged during
    // the test. We avoid calling `common::init_tracing()` here because it
    // installs a global test writer we cannot inspect.
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

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "Hello from test ".to_string(),
            "<think>plan</think>".to_string(),
            "final chunk".to_string(),
        ])
        .expect("chunk json"),
    );

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
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
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
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );
    assert!(chat_response
        .headers()
        .get(header::TRANSFER_ENCODING)
        .is_none());

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");

    // Fail fast if the response indicates a bridge/server error so the
    // integration test surfaces real backend failures instead of silently
    // passing on a stubbed happy-path. Check a broad set of error
    // indicators (tracebacks, exception names, HTTP 500 markers, and
    // bridge-specific error chunks).
    let error_indicators = [
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
    ];

    for indicator in error_indicators {
        assert!(
            !body_text.contains(indicator),
            "chat returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    // Also ensure no internal server errors were recorded in the log buffer
    // we installed earlier. This catches cases where the server responded
    // with HTTP 500 to an XHR/fetch (seen only in browser console) and
    // where the response body itself doesn't include the error text.
    let logs = String::from_utf8_lossy(&log_buf.lock().unwrap()).to_string();
    let log_error_indicators = [
        "Internal Server Error",
        "ERROR",
        "bridge error",
        "Traceback",
    ];
    for ind in &log_error_indicators {
        assert!(
            !logs.contains(ind),
            "server logs contained error indicator '{}': {}",
            ind,
            logs
        );
    }

    // Also check the test instrumentation counter for any recorded 500s.
    // The server increments this counter whenever a 500 is built so tests
    // can detect server-side errors that may not surface in the response
    // body directly.
    let error_count = chatbot_server::test_instrumentation::take_error_count();
    assert_eq!(
        error_count, 0,
        "server emitted {} HTTP 5xx responses",
        error_count
    );

    // Validate expected streamed chunks are present
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
    let workspace = common::TestWorkspace::with_openai_provider();

    const USERNAME: &str = "persisted_user";
    const PASSWORD: &str = "S3cur3Pass!";

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

    let login_cookie = session_cookie
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
                .header(header::COOKIE, &login_cookie)
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

    let cookie_for_home = session_cookie.clone().unwrap_or(login_cookie);

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
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &home_cookie)
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

    assert!(loaded.encrypted, "history set should be marked encrypted");
    assert_eq!(
        loaded.history.len(),
        1,
        "first chat persists single history entry"
    );
    assert_eq!(loaded.history[0].0, "Hello from rust");
    assert!(
        loaded.history[0].1.contains("streamed chunk"),
        "assistant response should include streamed chunk"
    );
    assert_eq!(
        loaded.system_prompt, "Custom prompt",
        "system prompt update should be stored on disk"
    );
}
