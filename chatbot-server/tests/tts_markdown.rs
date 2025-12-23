use std::{env, net::SocketAddr, sync::Arc, thread::JoinHandle};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json,
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex as AsyncMutex},
};
use tower::ServiceExt;

mod common;

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

static TTS_TEST_MUTEX: Lazy<std::sync::Mutex<()>> = Lazy::new(|| std::sync::Mutex::new(()));

#[tokio::test]
async fn tts_strips_markdown_formatting() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    // Mock PCM data (valid WAV requires minimal data)
    let pcm = Arc::new(vec![0_u8; 100]);

    let router = Router::new()
        .route(
            "/api/tts",
            post({
                let captured = captured.clone();
                let pcm = pcm.clone();
                move |Json(payload): Json<Value>| {
                    let captured = captured.clone();
                    let pcm = pcm.clone();
                    async move {
                        captured.lock().await.push(payload);
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            pcm.as_slice().to_vec(),
                        )
                    }
                }
            }),
        )
        .route(
            "/api/tts/stream",
            post({
                let captured = captured.clone();
                let pcm = pcm.clone();
                move |Json(payload): Json<Value>| {
                    let captured = captured.clone();
                    let pcm = pcm.clone();
                    async move {
                        captured.lock().await.push(payload);
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            pcm.as_slice().to_vec(),
                        )
                    }
                }
            }),
        );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    // Get CSRF token
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
    let csrf_token = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let cookie_value = common::extract_cookie(&set_cookie);

    // Markdown input
    let input_text = "This is **bold** and *italic* text with [a link](http://example.com).";
    let expected_text = "This is bold and italic text with a link.";

    let tts_payload = json!({"text": input_text});

    let tts_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&tts_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts response");

    assert_eq!(tts_response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(tts_response.into_body(), 128 * 1024)
        .await
        .expect("read tts token body");
    let tts_data: Value = serde_json::from_slice(&body_bytes).expect("valid json token");
    let token = tts_data["token"].as_str().expect("token field present");

    // Trigger Step 2: GET /tts_stream/{token}
    let _stream_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream response");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("backend payload captured");
    
    assert_eq!(payload["text"], expected_text, "Markdown should be stripped");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

async fn spawn_tts_backend(router: Router) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tts stub");
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
