//! Chat route rejection boundaries.
//!
//! Given malformed or disallowed requests, when chat routes are called,
//! then they return their exact method and JSON parse errors.

mod common;

use std::sync::{Mutex, OnceLock};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).unwrap());

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = common::extract_cookie(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
    );
    let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&body).unwrap())
        .unwrap()[1]
        .to_owned();
    (cookie, csrf)
}

async fn send(
    app: &Router,
    method: Method,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn chat_and_regenerate_reject_methods_and_malformed_json() {
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let _workspace = common::TestWorkspace::with_openai_provider();
    std::env::set_var("SECRET_KEY", "chat_route_rejections_secret");
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    for path in ["/chat", "/regenerate"] {
        let (status, body) = send(&app, Method::GET, path, &cookie, &csrf, "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body, "");
    }
    for path in ["/chat", "/regenerate"] {
        let (status, body) = send(&app, Method::POST, path, &cookie, &csrf, "{\"message\":").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"Invalid JSON payload"}"#);
    }
}
