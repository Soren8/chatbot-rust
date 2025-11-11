use std::{env, net::SocketAddr, sync::Arc, thread::JoinHandle};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    response::Response,
    routing::post,
    Json, Router,
};
use bytes::Bytes;
use chatbot_server::{build_router, resolve_static_root};
use futures_util::stream;
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
async fn tts_returns_wav_audio() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8, 1, 2, 3]);

    let router = Router::new().route(
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
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

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
    let csrf_token = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let cookie_value = common::extract_cookie(&set_cookie);

    let tts_payload = json!({"text": "Hello <think>ignore</think>"});

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
    assert_eq!(
        tts_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav"),
    );

    let disposition = tts_response
        .headers()
        .get("Content-Disposition")
        .and_then(|value| value.to_str().ok())
        .expect("content disposition header");
    assert!(disposition.contains("tts.wav"));

    let wav_bytes = axum::body::to_bytes(tts_response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert!(!wav_bytes.is_empty(), "wav body should not be empty");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("backend payload captured");
    assert_eq!(payload["text"], "Hello");
    assert_eq!(payload["voice_file"], "voices/default.wav");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn tts_returns_error_when_service_fails() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let router = Router::new().route(
        "/api/tts",
        post(|Json(_payload): Json<Value>| async move {
            let body = serde_json::to_vec(&json!({"error": "backend unavailable"})).unwrap();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
        }),
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

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

    let tts_payload = json!({"text": "Failure case"});

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

    assert_eq!(tts_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let content_type = tts_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content type");
    assert!(content_type.contains("application/json"));

    let body_bytes = axum::body::to_bytes(tts_response.into_body(), 128 * 1024)
        .await
        .expect("read error body");
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "TTS generation failed");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn tts_rejects_empty_text() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    env::set_var("TTS_HOST", "127.0.0.1");
    env::set_var("TTS_PORT", "65535");
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "    "})).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body_bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read error body");
    let payload: Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "TTS generation failed");
}

#[tokio::test]
async fn api_tts_generates_wav_audio() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8, 1, 2, 3, 4, 5]);

    let router = Router::new().route(
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
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let tts_payload = json!({"text": "Hello <think>skip</think>"});

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

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("audio content type");
    assert_eq!(content_type, "audio/wav");

    let wav_bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert!(wav_bytes.len() > 44, "expected WAV header plus data");
    assert_eq!(&wav_bytes[..4], b"RIFF");
    assert_eq!(&wav_bytes[8..12], b"WAVE");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("backend payload recorded");
    assert_eq!(payload["text"], "Hello");
    assert_eq!(payload["voice_file"], "voices/default.wav");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn api_tts_returns_backend_error() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let router = Router::new().route(
        "/api/tts",
        post(|Json(_payload): Json<Value>| async move {
            let body = serde_json::to_vec(&json!({"error": "backend offline"})).unwrap();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
        }),
    );

    let (addr, shutdown, handle) = spawn_tts_backend(router).await;

    env::set_var("TTS_HOST", addr.ip().to_string());
    env::set_var("TTS_PORT", addr.port().to_string());
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "Hello"})).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /api/tts response");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("read error body");
    let payload: Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "backend offline");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn api_tts_stream_proxies_audio() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let chunks: Arc<Vec<Bytes>> = Arc::new(vec![
        Bytes::from_static(b"chunk-1"),
        Bytes::from_static(b"chunk-2"),
    ]);

    let router = Router::new().route(
        "/api/tts/stream",
        post({
            let captured = captured.clone();
            let chunks = chunks.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let chunks = chunks.clone();
                async move {
                    captured.lock().await.push(payload);
                    let chunk_items = chunks.iter().cloned().collect::<Vec<_>>();
                    let stream = stream::iter(
                        chunk_items
                            .into_iter()
                            .map(Result::<_, std::convert::Infallible>::Ok),
                    );
                    let mut response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .body(Body::from_stream(stream))
                        .unwrap();
                    response.headers_mut().insert(
                        header::CONTENT_DISPOSITION,
                        header::HeaderValue::from_static("inline; filename=backend.wav"),
                    );
                    response
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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tts/stream")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "text": "Streaming example",
                        "voice_file": "voices/alt.wav"
                    }))
                    .expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /api/tts/stream response");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav")
    );
    assert_eq!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok()),
        Some("inline; filename=tts-stream.wav")
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("read streaming body");
    assert_eq!(body_bytes.as_ref(), b"chunk-1chunk-2");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("stream backend payload");
    assert_eq!(payload["text"], "Streaming example");
    assert_eq!(payload["voice_file"], "voices/alt.wav");

    shutdown.send(()).ok();
    handle.join().expect("join backend thread");
}

#[tokio::test]
async fn api_tts_rejects_empty_text() {
    common::init_tracing();
    let _lock = TTS_TEST_MUTEX.lock().expect("tts mutex");

    env::set_var("TTS_HOST", "127.0.0.1");
    env::set_var("TTS_PORT", "65535");
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "   "})).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /api/tts response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .expect("read error body");
    let payload: Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "No text provided");
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
