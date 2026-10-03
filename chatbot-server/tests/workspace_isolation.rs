use std::{env, fs};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::resolve_static_root;
use serde_json::json;
use tower::ServiceExt;

mod common;

async fn create_saved_set(app: &axum::Router, username: &str, key: &str) {
    let login = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = common::extract_cookie(
        login.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap(),
    );
    let body = to_bytes(login.into_body(), 128 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).unwrap();
    let password = "Password123";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(format!(
                    "username={}&password={}&csrf_token={}&storage_key={}",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    urlencoding::encode(&csrf),
                    urlencoding::encode(key),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let session_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| common::extract_cookie(v.to_str().unwrap()))
        .unwrap_or(cookie);
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let home_html = std::str::from_utf8(&home_body).unwrap();
    let csrf = regex::Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#)
        .unwrap()
        .captures(home_html)
        .and_then(|captures| captures.get(1).map(|value| value.as_str()))
        .expect("home CSRF token");
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/create_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", key)
                .body(Body::from(serde_json::to_vec(&json!({"set_name":"isolated"})).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
}

fn prepare_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    fs::write(
        workspace.path().join("users.json"),
        serde_json::to_string(&json!({
            "workspace_user": { "password": hash("Password123", DEFAULT_COST).unwrap(), "tier": "free" }
        })).unwrap(),
    ).unwrap();
    workspace
}

#[tokio::test]
async fn separate_workspaces_persist_history_to_their_own_roots() {
    let first = prepare_workspace();
    let key = common::derive_encryption_key_header("workspace_user", "Password123");
    let (app, _services) = common::workspace_router(resolve_static_root());
    create_saved_set(&app, "workspace_user", &key).await;
    assert!(first.path().join("history/redb").exists());
    drop(app);
    drop(first);

    let second = prepare_workspace();
    let key = common::derive_encryption_key_header("workspace_user", "Password123");
    let (app, _services) = common::workspace_router(resolve_static_root());
    create_saved_set(&app, "workspace_user", &key).await;
    assert!(
        second.path().join("history/redb").exists(),
        "second workspace must own its durable history database"
    );
}
