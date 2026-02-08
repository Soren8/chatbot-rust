use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;
use std::env;

mod common;

use std::sync::{Mutex, OnceLock};

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn unauthenticated_sets_access_returns_unauthorized() {
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
    
    let _workspace = common::TestWorkspace::with_config(config);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    // Try GET /get_sets without login
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/get_sets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /get_sets response");

    // Should be 401 (was 403)
    assert_eq!(
        response.status(), 
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized for /get_sets"
    );
}
