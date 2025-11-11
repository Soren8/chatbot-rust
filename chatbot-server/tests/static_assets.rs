use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chatbot_server::build_router;
use tower::ServiceExt;

#[tokio::test]
async fn serves_static_files_from_configured_root() {
    let temp_dir = tempfile::tempdir().unwrap();
    let css_path = temp_dir.path().join("style.css");
    std::fs::write(&css_path, "body { color: red; }").unwrap();

    let app = build_router(temp_dir.path().to_path_buf());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("static file request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    assert!(body.starts_with(b"body"));
}

#[tokio::test]
async fn serves_placeholder_favicon() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.ico")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("favicon request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn rejects_dotfiles_and_sensitive_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    for path in ["/.env", "/.config.yml"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .expect("dotfile request");

        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
            ),
            "{path} should not be served (status was {})",
            response.status()
        );
    }
}

#[tokio::test]
async fn blocks_static_directory_traversal() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    for path in [
        "/static/../.env",
        "/static/../.config.yml",
        "/static/%2e%2e/.env",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .expect("traversal request");

        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
            ),
            "Traversal path {path} should be blocked (status was {})",
            response.status()
        );
    }
}
