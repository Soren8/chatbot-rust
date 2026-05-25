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
async fn delete_message_requires_index_and_matching_content() {
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);
    let guest_session = "delete-message-guest";

    let session_context = session::session_context(SessionRequest {
        authorization: None,
        auth_user: None,
        encryption_key: None,
        guest_session: Some(guest_session),
    })
    .expect("session context for seeding");

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
                .header("X-Guest-Session", guest_session)
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
                .header("X-Guest-Session", guest_session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 0,
                        "user_message": "repeat",
                        "ai_message": "wrong answer",
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
                .header("X-Guest-Session", guest_session)
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
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header("X-Guest-Session", guest_session)
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
}
