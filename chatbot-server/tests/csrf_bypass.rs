use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

use std::sync::{Mutex, OnceLock};

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn chat_config(csrf: bool) -> String {
    format!(
        r#"
csrf: {csrf}
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#
    )
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

async fn chat_without_csrf(config: &str, guest_session: &str) -> axum::http::Response<Body> {
    let _workspace = common::TestWorkspace::with_config(config);
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["Bypassed".to_string()]).expect("chunk json"),
    );

    let app = build_app();
    let payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
    });

    let response = app
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

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    response
}

#[tokio::test]
async fn chat_endpoint_works_without_csrf_when_disabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");

    let response = chat_without_csrf(&chat_config(false), "csrf-off-guest").await;
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");
    assert!(body_text.contains("Bypassed"));
}

#[tokio::test]
async fn chat_endpoint_works_without_csrf_when_enabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");

    let response = chat_without_csrf(&chat_config(true), "csrf-on-guest").await;
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");
    assert!(body_text.contains("Bypassed"));
}

#[tokio::test]
async fn home_no_longer_sets_session_cookie_when_csrf_enabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_config(&chat_config(true));

    let app = build_app();
    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "home should not set session cookies anymore"
    );
}

#[tokio::test]
async fn login_plaintext_still_checks_credentials_when_csrf_disabled() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_config(&chat_config(false));

    let app = build_app();
    let form_body = "username=testuser&password=testpassword";

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

    assert_eq!(login_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_login_flow_with_csrf_disabled_bootstraps_user() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_config(&chat_config(false));

    const USERNAME: &str = "testuser";
    const AUTH_TOKEN: &str = "testpassword";
    common::seed_user(USERNAME, AUTH_TOKEN);

    let app = build_app();
    let client = common::AuthedClient::login(app.clone(), USERNAME, AUTH_TOKEN).await;

    let bootstrap = app
        .oneshot(
            client
                .request(Method::GET, "/auth/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /auth/bootstrap");

    assert_eq!(bootstrap.status(), StatusCode::OK);
    assert!(bootstrap.headers().get(header::SET_COOKIE).is_none());

    let body = to_bytes(bootstrap.into_body(), 64 * 1024)
        .await
        .expect("read bootstrap body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("bootstrap json");
    assert_eq!(json["username"], USERNAME);
    assert_eq!(json["logged_in"], true);
}
