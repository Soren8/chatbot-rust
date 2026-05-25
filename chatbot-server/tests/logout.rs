use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

#[tokio::test]
async fn logout_returns_success_json() {
    common::init_tracing();
    let _workspace = setup_workspace();

    let username = "testuser";
    let auth_token = "Sup3rS3cret!";
    common::seed_user(username, auth_token);

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let client = common::AuthedClient::login(app.clone(), username, auth_token).await;

    let logout_response = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("POST /logout");

    assert_eq!(logout_response.status(), StatusCode::OK);
    assert_eq!(
        logout_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    let body = to_bytes(logout_response.into_body(), 64 * 1024)
        .await
        .expect("read logout body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("logout json");
    assert_eq!(json["status"], "success");
}
