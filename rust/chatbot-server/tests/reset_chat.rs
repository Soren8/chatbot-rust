use std::env;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::{bridge, session};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn reset_chat_clears_history() {
    if !common::ensure_flask_available() {
        eprintln!("skipping reset_chat_clears_history: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    bridge::initialize_python().expect("python bridge init");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();

    let body_bytes = axum::body::to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let cookie_value = common::extract_cookie(&set_cookie);

    let session_context =
        session::session_context(Some(&cookie_value)).expect("session context for seeding");

    let seeded_history = vec![
        ("user".to_string(), "assistant".to_string()),
        ("second".to_string(), "reply".to_string()),
    ];
    session::update_session_history(&session_context.session_id, &seeded_history);

    let reset_payload = json!({"set_name": "default"});

    let reset_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/reset_chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&reset_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /reset_chat response");

    assert_eq!(reset_response.status(), StatusCode::OK);

    let history_after = session::session_history(&session_context.session_id);
    assert!(
        history_after.is_empty(),
        "history not cleared by reset_chat"
    );
}
