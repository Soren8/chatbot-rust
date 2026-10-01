//! Read-only data lookups must not persist HTTP session records: a request
//! without a valid session cookie never receives a Set-Cookie from these
//! routes, so any record minted for it would be unreachable.

use std::{env, sync::Arc};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use chatbot_core::session_identity::HttpSessionStore;
use chatbot_server::{build_router_with_identity, identity::RequestIdentity, resolve_static_root};
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn cookieless_and_unknown_cookie_activity_lookups_do_not_grow_store() {
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let store = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(store.clone(), true);
    let app = build_router_with_identity(resolve_static_root(), identity);
    let before = store.record_count();

    for i in 0..100 {
        let mut builder = Request::builder().uri("/activity?set_id=x");
        if i % 2 == 1 {
            builder = builder.header(header::COOKIE, format!("session=unknown-{i}"));
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("GET /activity");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    assert_eq!(store.record_count(), before);
}
