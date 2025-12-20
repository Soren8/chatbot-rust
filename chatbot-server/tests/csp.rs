use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;
use std::env;

mod common;

#[tokio::test]
async fn test_csp_headers() {
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    
    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    
    let csp = response
        .headers()
        .get("Content-Security-Policy")
        .expect("CSP header present")
        .to_str()
        .expect("CSP header is valid string");

    // Check for img-src blob:
    assert!(
        csp.contains("img-src 'self' data: blob:") || csp.contains("img-src 'self' blob: data:"),
        "CSP should allow blob: for img-src. Current CSP: {}",
        csp
    );

    // Check for connect-src https://cdn.jsdelivr.net
    assert!(
        csp.contains("connect-src 'self' https://cdn.jsdelivr.net"),
        "CSP should allow https://cdn.jsdelivr.net for connect-src. Current CSP: {}",
        csp
    );
}
