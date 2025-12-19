use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;
use std::env;

mod common;

use std::sync::{Mutex, OnceLock};

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn chat_endpoint_bypasses_csrf_when_disabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    // Config with csrf: false
    let config = r#"
csrf: false
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;
    
    let _workspace = common::TestWorkspace::with_config(config);

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["Bypassed".to_string()]).expect("chunk json"),
    );

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
    });

    // Attempt POST /chat WITHOUT X-CSRF-Token header
    let chat_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                // NO X-CSRF-Token header here
                .body(Body::from(
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    // It should return 200 OK because CSRF is disabled
    assert_eq!(chat_response.status(), StatusCode::OK);
    
    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");
    
    assert!(body_text.contains("Bypassed"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

#[tokio::test]
async fn chat_endpoint_enforces_csrf_when_enabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    // Config with csrf: true (default)
    let config = r#"
csrf: true
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;
    
    let _workspace = common::TestWorkspace::with_config(config);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let payload = json!({
        "message": "Hello",
    });

    // Attempt POST /chat WITHOUT X-CSRF-Token header
    let chat_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                // NO X-CSRF-Token header here
                .body(Body::from(
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    // It should return 400 Bad Request because CSRF is enabled but missing
    assert_eq!(chat_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_cookie_is_secure_when_csrf_enabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    // Config with csrf: true (default)
    let config = r#"
csrf: true
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;
    
    let _workspace = common::TestWorkspace::with_config(config);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let home_response = app
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
    
    let cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header present");

    assert!(cookie.contains("Secure"), "Cookie should be Secure when CSRF is enabled: {}", cookie);
}

#[tokio::test]
async fn login_endpoint_bypasses_csrf_when_disabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    // Config with csrf: false
    let config = r#"
csrf: false
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;
    
    let _workspace = common::TestWorkspace::with_config(config);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let form_body = "username=testuser&password=testpassword"; // No csrf_token here

    let login_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .expect("POST /login response");

    // If CSRF is bypassed, it should proceed to check credentials.
    // Since 'testuser' doesn't exist in the fresh workspace, it should return 401 Unauthorized, NOT 400 Bad Request.
    assert_eq!(login_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_login_flow_with_csrf_disabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    let config = r#"
csrf: false
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;
    
    let workspace = common::TestWorkspace::with_config(config);

    // Create a user
    const USERNAME: &str = "testuser";
    const PASSWORD: &str = "testpassword";
    {
        let hashed = bcrypt::hash(PASSWORD, bcrypt::DEFAULT_COST).unwrap();
        let users_json = workspace.path().join("users.json");
        let payload = serde_json::json!({
            USERNAME: {
                "password": hashed,
                "tier": "free"
            }
        });
        std::fs::write(users_json, serde_json::to_string(&payload).unwrap()).unwrap();
    }

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let form_body = format!("username={}&password={}", USERNAME, PASSWORD);

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .expect("POST /login response");

    assert_eq!(login_response.status(), StatusCode::FOUND);
    
    let cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header present")
        .to_owned();

    assert!(!cookie.contains("Secure"), "Cookie should not be Secure when CSRF is disabled: {}", cookie);

    // Now access home page with this cookie
    let home_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, common::extract_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);
    
    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    
    // Check if "Sign Out" or similar logged-in indicator is present
    assert!(body_text.contains("Sign Out") || body_text.contains("logout"), "Should be logged in. Body: {}", body_text);
}
