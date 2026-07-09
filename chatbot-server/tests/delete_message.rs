use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::session;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

async fn guest_session(app: &axum::Router) -> (String, String) {
    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");

    assert_eq!(home_response.status(), StatusCode::OK);

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();

    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let csrf_token = CSRF_META_RE
        .captures(std::str::from_utf8(&body_bytes).expect("home utf8"))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");

    (common::extract_cookie(&set_cookie), csrf_token)
}

#[tokio::test]
async fn delete_message_requires_index_and_matching_content() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let (session_cookie, csrf_token) = guest_session(&app).await;

    let session_context =
        session::session_context(Some(&session_cookie)).expect("session context for seeding");

    let seeded_history = vec![
        ("repeat".to_string(), "first answer".to_string()),
        ("repeat".to_string(), "second answer".to_string()),
    ];
    session::update_session_history(&session_context.session_id, &seeded_history);

    let delete_index_one = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 1,
                        "user_message": "repeat",
                        "ai_message": "second answer",
                        "set_name": "default",
                    }))
                    .expect("delete payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message index 1");

    assert_eq!(delete_index_one.status(), StatusCode::OK);

    let remaining = session::session_history(&session_context.session_id);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, "repeat");
    assert_eq!(remaining[0].1, "first answer");

    let mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 0,
                        "user_message": "wrong user",
                        "ai_message": "first answer",
                        "set_name": "default",
                    }))
                    .expect("mismatch payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message mismatch");

    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    assert_eq!(session::session_history(&session_context.session_id).len(), 1);

    let out_of_range = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 5,
                        "user_message": "repeat",
                        "ai_message": "first answer",
                        "set_name": "default",
                    }))
                    .expect("out of range payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message out of range");

    assert_eq!(out_of_range.status(), StatusCode::NOT_FOUND);

    let missing_index = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "user_message": "repeat",
                        "ai_message": "first answer",
                        "set_name": "default",
                    }))
                    .expect("missing index payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message missing index");

    assert_eq!(missing_index.status(), StatusCode::BAD_REQUEST);

    // New test case reproducing the bug: deleting a pair that was never saved
    // server-side (e.g. failed or stopped AI generation, only existed in client DOM).
    // Server correctly returns 404 "out of range". Client must still remove the
    // pair client-side instead of showing error (see static/chat.js).
    let client_only_pair = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 1,
                        "user_message": "user only",
                        "ai_message": "",
                        "set_name": "default",
                    }))
                    .expect("client only payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /delete_message client-only pair");

    assert_eq!(client_only_pair.status(), StatusCode::NOT_FOUND);
}
