//! POST /client_logs authorizes with an expiry-aware session lookup; it must
//! not sweep the whole HTTP session store under its lock on every request.
//! Live, expired and missing sessions keep their authorization results.

mod common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::session_identity::HttpSessionStore;
use chatbot_server::{build_router_with_identity, identity::RequestIdentity, resolve_static_root};
use chatbot_test_support::TestWorkspace;
use tower::ServiceExt;

/// `HttpSessionStore` floors its timeout at 60 s.
const TIMEOUT_SECS: u64 = 60;
const LIVE_SESSIONS: usize = 5;

async fn post_logs(app: &axum::Router, cookie: Option<&str>) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/client_logs")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(r#"{"lines":["sweep check"]}"#)).unwrap())
        .await
        .expect("POST /client_logs")
        .status()
}

async fn new_session(app: &axum::Router) -> String {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie");
    common::extract_cookie(set_cookie)
}

#[tokio::test]
async fn client_logs_do_not_sweep_expired_sessions() {
    common::init_tracing();
    let _workspace = TestWorkspace::with_openai_provider();
    let store = Arc::new(HttpSessionStore::new(TIMEOUT_SECS));
    let app = build_router_with_identity(
        resolve_static_root(),
        RequestIdentity::with_store_and_csrf(store.clone(), true),
    );

    let expired = new_session(&app).await;
    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS + 1)).await;
    let mut live = Vec::new();
    for _ in 0..LIVE_SESSIONS {
        live.push(new_session(&app).await);
    }
    assert_eq!(store.record_count(), LIVE_SESSIONS + 1);

    assert_eq!(post_logs(&app, Some(&live[0])).await, StatusCode::NO_CONTENT);
    assert_eq!(
        store.record_count(),
        LIVE_SESSIONS + 1,
        "a /client_logs POST must not sweep expired records"
    );

    assert_eq!(post_logs(&app, Some(&expired)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        post_logs(&app, Some("session=missing-session-cookie")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(post_logs(&app, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(store.record_count(), LIVE_SESSIONS + 1);
}
