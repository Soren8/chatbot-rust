//! STT API tests with a provider-accurate voice-service stub (no live backend).

mod common;

use std::{net::SocketAddr, sync::Arc, thread::JoinHandle};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json, Router,
};
use chatbot_server::{build_router, resolve_static_root};
use chatbot_test_support::TestWorkspace;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};
use tower::ServiceExt;

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

static STT_TEST_MUTEX: Lazy<std::sync::Mutex<()>> = Lazy::new(|| std::sync::Mutex::new(()));

fn stt_test_config(voice_host: &str, voice_port: u16) -> String {
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
tts_provider: kokoro
voice_service_host: "{voice_host}"
voice_service_port: {voice_port}
"#
    )
}

async fn spawn_voice_stub(router: Router) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind voice stub");
    let addr = listener.local_addr().expect("stub addr");
    let std_listener = listener.into_std().expect("listener into std");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("listener from std");
            let server = axum::serve(listener, router).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
    });

    (addr, shutdown_tx, handle)
}

fn stt_error_router() -> (Router, Arc<std::sync::Mutex<bool>>) {
    let hit = Arc::new(std::sync::Mutex::new(false));
    let route_hit = hit.clone();
    (
        Router::new().route(
            "/v1/stt",
            post(move || {
                let hit = route_hit.clone();
                async move {
                    *hit.lock().unwrap() = true;
                    let body = serde_json::to_vec(&json!({
                        "detail": "ffmpeg conversion failed: invalid audio stream"
                    }))
                    .unwrap();
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }
            }),
        ),
        hit,
    )
}

#[tokio::test]
async fn stt_returns_clean_error_when_voice_service_fails() {
    common::init_tracing();
    let _lock = STT_TEST_MUTEX.lock().unwrap();

    let (router, hit) = stt_error_router();
    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = TestWorkspace::with_config(&stt_test_config(
        &addr.ip().to_string(),
        addr.port(),
    ));

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
        .expect("GET /");

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();
    let body_bytes = axum::body::to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("utf8");
    let csrf = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    let cookie = common::extract_cookie(&set_cookie);

    // Minimal valid multipart body with an "audio" field.
    let boundary = "----sttboundary";
    let multipart_body = format!(
        "--{b}\r\ncontent-disposition: form-data; name=\"audio\"; filename=\"a.webm\"\r\ncontent-type: audio/webm\r\n\r\nfakeaudio\r\n--{b}--\r\n",
        b = boundary
    );

    let stt_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/stt")
                .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
                .header("X-CSRF-Token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::from(multipart_body))
                .unwrap(),
        )
        .await
        .expect("POST /stt response");

    assert!(*hit.lock().unwrap(), "voice service stub must be reached");
    assert_eq!(stt_response.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = axum::body::to_bytes(stt_response.into_body(), 128 * 1024)
        .await
        .expect("read error body");
    let payload: Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "STT backend provider error");
    let error_text = payload["error"].as_str().expect("error is a string");
    assert!(
        !error_text.contains("ffmpeg"),
        "raw upstream detail must stay in server logs, not the client body: {error_text}"
    );

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}
