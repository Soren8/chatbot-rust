use axum::{
    body::Body,
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
async fn expired_session_on_custom_set_returns_unauthorized() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    
    // Config with csrf: false to match user report
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

    // 1. Simulate an "expired" session by just being a guest (no cookie)
    // 2. Try to access a custom set "my-set"
    
    let payload = json!({
        "message": "Hello",
        "set_name": "my-set"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    // BEFORE FIX: This would return 200 OK (guest session created on the fly)
    // AFTER FIX: This should return 401 Unauthorized because guests cannot use custom sets
    assert_eq!(
        response.status(), 
        StatusCode::UNAUTHORIZED, 
        "Expected 401 Unauthorized when accessing custom set without valid session"
    );
}
