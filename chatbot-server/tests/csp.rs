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

    assert!(
        csp.contains("img-src 'self' data: blob:") || csp.contains("img-src 'self' blob: data:"),
        "CSP should allow blob: for img-src. Current CSP: {}",
        csp
    );
    assert!(
        csp.contains("connect-src 'self';") || csp.contains("connect-src 'self' "),
        "CSP connect-src should be first-party only. Current CSP: {}",
        csp
    );
    for host in [
        "cdn.jsdelivr.net",
        "code.jquery.com",
        "cdnjs.cloudflare.com",
    ] {
        assert!(
            !csp.contains(host),
            "CSP must not allow {host}. Current CSP: {csp}"
        );
    }
    assert!(
        csp.contains("require-trusted-types-for 'script'"),
        "CSP must require Trusted Types for script. Current CSP: {csp}"
    );
    assert!(
        csp.contains("trusted-types chatbot default"),
        "CSP must allow chatbot and default TT policies. Current CSP: {csp}"
    );
}
