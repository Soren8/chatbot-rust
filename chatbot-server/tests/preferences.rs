use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{Method, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn preferences_persistence() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "pref_user";
    let auth_token = "password";
    common::seed_user(username, auth_token);

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let client = common::AuthedClient::login(app.clone(), username, auth_token).await;

    let update_resp = app
        .clone()
        .oneshot(
            client
                .request(Method::POST, "/update_preferences")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "last_set": "my-set",
                        "last_model": "gpt-4",
                        "render_markdown": false
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(update_resp.status(), StatusCode::OK);

    let bootstrap = app
        .clone()
        .oneshot(
            client
                .request(Method::GET, "/auth/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(bootstrap.status(), StatusCode::OK);
    let body = to_bytes(bootstrap.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["last_set"], "my-set");
    assert_eq!(json["last_model"], "gpt-4");
    assert_eq!(json["render_markdown"], false);
}
