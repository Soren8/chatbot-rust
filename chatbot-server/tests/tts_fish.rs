use std::{env, net::SocketAddr, sync::Arc, thread::JoinHandle};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json, Router,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex as AsyncMutex},
};
use tower::ServiceExt;

mod common;

static TTS_TEST_MUTEX: Lazy<std::sync::Mutex<()>> = Lazy::new(|| std::sync::Mutex::new(()));

#[tokio::test]
async fn fish_speech_provider_uses_correct_format() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    // Fish speech returns WAV directly, so let's simulate a WAV file
    let wav_data = Arc::new(vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'A', b'V', b'E']);

    let router = Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let wav_data = wav_data.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let wav_data = wav_data.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        wav_data.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    // Configure for Fish Speech
    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("TTS_PROVIDER", "fish");
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let tts_payload = json!({"text": "Hello Fish"});

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&tts_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /api/tts response");

    assert_eq!(response.status(), StatusCode::OK);
    
    // Check if we received the WAV data back
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(body_bytes.as_ref(), wav_data.as_slice());

    // Verify the request sent to the backend
    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("backend payload captured");
    
    assert_eq!(payload["text"], "Hello Fish");
    assert_eq!(payload["reference_id"], "default");
    assert_eq!(payload["format"], "wav");
    // streaming defaults to false in handle_fish_speech used by handle_tts/handle_api_tts
    // Wait, handle_api_tts calls handle_fish_speech which sets streaming: false
    // handle_api_tts_stream calls handle_fish_speech_stream which sets streaming: true
    assert_eq!(payload["streaming"], false);

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn fish_speech_stream_uses_correct_format() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let wav_data = Arc::new(vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'A', b'V', b'E']);

    let router = Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let wav_data = wav_data.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let wav_data = wav_data.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        wav_data.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("TTS_PROVIDER", "fish");
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let tts_payload = json!({"text": "Hello Stream"});

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tts/stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&tts_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /api/tts/stream response");

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the request sent to the backend
    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("backend payload captured");
    
    assert_eq!(payload["text"], "Hello Stream");
    assert_eq!(payload["reference_id"], "default");
    assert_eq!(payload["format"], "wav");
    assert_eq!(payload["streaming"], true);

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
