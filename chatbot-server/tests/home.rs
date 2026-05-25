use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::Value;
use tower::ServiceExt;

mod common;

const TEST_CONFIG: &str = r#"llms:
  - provider_name: "free-model"
    type: "openai"
    model_name: "free"
    tier: "free"
  - provider_name: "premium-model"
    type: "openai"
    model_name: "premium"
    tier: "premium"
default_system_prompt: "Test system prompt"
"#;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_config(TEST_CONFIG)
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

fn extract_app_data(body: &str) -> Value {
    const MARKER: &str = "<script id=\"app-data\" type=\"application/json\">";
    let start = body.find(MARKER).expect("app-data marker present");
    let json_start = start + MARKER.len();
    let end = body[json_start..]
        .find("</script>")
        .map(|rel| json_start + rel)
        .expect("closing script tag");
    let payload = body[json_start..end].trim();
    serde_json::from_str(payload).expect("app-data json")
}

#[tokio::test]
async fn home_route_guest_filters_premium_models() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"false\""));

    let app_data = extract_app_data(body);
    let models = app_data
        .get("availableModels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        models
            .iter()
            .all(|entry| entry.get("tier").and_then(|v| v.as_str()) != Some("premium")),
        "guest view should not expose premium models",
    );
}

#[tokio::test]
async fn auth_bootstrap_for_premium_user_includes_premium_models() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "premium-user";
    let auth_token = "Sup3rS3cret!";
    common::seed_user_with_profile(
        username,
        auth_token,
        "premium",
        Some("default"),
        Some("premium-model"),
        true,
        false,
    );

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), username, auth_token).await;

    let response = app
        .oneshot(
            client
                .request(axum::http::Method::GET, "/auth/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /auth/bootstrap");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read bootstrap body");
    let json: Value = serde_json::from_slice(&body).expect("bootstrap json");
    assert_eq!(json["logged_in"], true);
    assert_eq!(json["username"], username);

    let models = json["available_models"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        models
            .iter()
            .any(|entry| entry.get("tier").and_then(|v| v.as_str()) == Some("premium")),
        "premium bootstrap should include premium models",
    );
}
