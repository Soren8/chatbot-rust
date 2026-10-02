//! Set mutation rejection boundaries.
//!
//! Given invalid, duplicate, or missing set names, when mutation handlers run,
//! then each returns its exact rejection body.

mod common;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::{
    fs,
    sync::{Mutex, OnceLock},
};
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).unwrap());

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn setup() -> (axum::Router, String, String, String, common::TestWorkspace) {
    std::env::set_var("SECRET_KEY", "set_rejections_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    let username = "rejectuser";
    let password = "Sup3rS3cret!";
    let hashed = hash(password, DEFAULT_COST).unwrap();
    fs::write(
        workspace.path().join("users.json"),
        serde_json::to_string(&json!({username:{"password":hashed,"tier":"free"}})).unwrap(),
    )
    .unwrap();
    let app = build_router(resolve_static_root());
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut cookie = common::extract_cookie(
        login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
    );
    let body = to_bytes(login.into_body(), 128 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).unwrap();
    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );
    let logged = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    if let Some(value) = logged
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(value);
    }
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if let Some(value) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(value);
    }
    let body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&body).unwrap())
        .unwrap()[1]
        .to_owned();
    (
        app,
        cookie,
        csrf,
        common::derive_encryption_key_header(username, password),
        workspace,
    )
}

async fn post(
    app: &axum::Router,
    path: &str,
    cookie: &str,
    csrf: &str,
    key: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn create_rejects_invalid_and_existing_names() {
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let (app, cookie, csrf, key, _workspace) = setup().await;
    for name in ["bad/name", "default"] {
        let (status, body) = post(
            &app,
            "/create_set",
            &cookie,
            &csrf,
            &key,
            json!({"set_name":name}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            r#"{"error":"Set already exists or invalid name","status":"error"}"#
        );
    }
}

#[tokio::test]
async fn delete_rejects_unknown_default_and_invalid_names() {
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let (app, cookie, csrf, key, _workspace) = setup().await;
    for name in ["missing", "default", "bad/name"] {
        let (status, body) = post(
            &app,
            "/delete_set",
            &cookie,
            &csrf,
            &key,
            json!({"set_name":name}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            if name == "default" {
                r#"{"error":"Cannot delete set","status":"error"}"#
            } else {
                r#"{"error":"set not found","status":"error"}"#
            }
        );
    }
}

#[tokio::test]
async fn rename_rejects_invalid_existing_and_unknown_names() {
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let (app, cookie, csrf, key, _workspace) = setup().await;
    for (old, new) in [
        ("default", "bad/name"),
        ("default", "default"),
        ("missing", "other"),
    ] {
        let (status, body) = post(
            &app,
            "/rename_set",
            &cookie,
            &csrf,
            &key,
            json!({"old_name":old,"new_name":new}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            r#"{"error":"Invalid set name or set already exists","status":"error"}"#
        );
    }
}
