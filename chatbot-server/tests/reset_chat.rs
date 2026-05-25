use std::env;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::session::{self, SessionRequest};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn reset_chat_clears_history() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let guest_session = "reset-chat-guest";

    let session_context = session::session_context(SessionRequest {
        authorization: None,
        auth_user: None,
        encryption_key: None,
        guest_session: Some(guest_session),
    })
    .expect("session context for seeding");

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
                .header("X-Guest-Session", guest_session)
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
