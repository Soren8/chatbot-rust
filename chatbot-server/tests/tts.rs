//! TTS API tests with provider-accurate HTTP stubs (no live voice-service).

mod common;

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
use chatbot_test_support::TestWorkspace;
use futures_util::stream;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex as AsyncMutex},
};
use tower::ServiceExt;

static TTS_TEST_MUTEX: Lazy<std::sync::Mutex<()>> = Lazy::new(|| std::sync::Mutex::new(()));

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

const KOKORO_DEFAULT_VOICE: &str = "af_heart";
const VOICE_SERVICE_SAMPLE_RATE: &str = "24000";

fn tts_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TTS_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn kokoro_test_config(voice_host: &str, voice_port: u16) -> String {
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

fn fish_test_config() -> &'static str {
    r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
tts_provider: fish
"#
}

fn begin_kokoro_workspace(voice_host: &str, voice_port: u16) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    TestWorkspace::with_config(&kokoro_test_config(voice_host, voice_port))
}

fn begin_fish_workspace(tts_host: &str, tts_port: u16) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::set_var("TTS_HOST", tts_host);
    env::set_var("TTS_PORT", tts_port.to_string());
    TestWorkspace::with_config(fish_test_config())
}

fn kokoro_voice_router(captured: Arc<AsyncMutex<Vec<Value>>>, pcm: Arc<Vec<u8>>) -> Router {
    Router::new().route(
        "/v1/tts/kokoro",
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
                        [
                            (header::CONTENT_TYPE, "application/octet-stream"),
                            (
                                header::HeaderName::from_static("x-sample-rate"),
                                VOICE_SERVICE_SAMPLE_RATE,
                            ),
                        ],
                        pcm.as_slice().to_vec(),
                    )
                }
            }
        }),
    )
}

fn kokoro_voice_router_with_stream(
    captured: Arc<AsyncMutex<Vec<Value>>>,
    pcm: Arc<Vec<u8>>,
    stream_chunks: Arc<Vec<Bytes>>,
) -> Router {
    Router::new()
        .route(
            "/v1/tts/kokoro",
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
                            [
                                (header::CONTENT_TYPE, "application/octet-stream"),
                                (
                                    header::HeaderName::from_static("x-sample-rate"),
                                    VOICE_SERVICE_SAMPLE_RATE,
                                ),
                            ],
                            pcm.as_slice().to_vec(),
                        )
                    }
                }
            }),
        )
        .route(
            "/v1/tts/kokoro/stream",
            post({
                let captured = captured.clone();
                let stream_chunks = stream_chunks.clone();
                move |Json(payload): Json<Value>| {
                    let captured = captured.clone();
                    let stream_chunks = stream_chunks.clone();
                    async move {
                        captured.lock().await.push(payload);
                        let chunk_items = stream_chunks.iter().cloned().collect::<Vec<_>>();
                        let body_stream = stream::iter(
                            chunk_items
                                .into_iter()
                                .map(Result::<_, std::convert::Infallible>::Ok),
                        );
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/octet-stream")
                            .header("x-sample-rate", VOICE_SERVICE_SAMPLE_RATE)
                            .body(Body::from_stream(body_stream))
                            .unwrap()
                    }
                }
            }),
        )
}

fn fish_speech_router(captured: Arc<AsyncMutex<Vec<Value>>>, wav_body: Arc<Vec<u8>>) -> Router {
    Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let wav_body = wav_body.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let wav_body = wav_body.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        wav_body.as_slice().to_vec(),
                    )
                }
            }
        }),
    )
}

fn kokoro_error_router() -> Router {
    Router::new().route(
        "/v1/tts/kokoro",
        post(|Json(_payload): Json<Value>| async move {
            let body = serde_json::to_vec(&json!({"error": "voice service unavailable"})).unwrap();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
        }),
    )
}

fn kokoro_offline_router() -> Router {
    Router::new().route(
        "/v1/tts/kokoro",
        post(|Json(_payload): Json<Value>| async move {
            let body = serde_json::to_vec(&json!({"error": "backend offline"})).unwrap();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
        }),
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

// --- Kokoro (default voice-service provider) ---

#[tokio::test]
async fn kokoro_tts_returns_wav_audio() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8, 1, 2, 3]);
    let router = kokoro_voice_router(captured.clone(), pcm);

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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
        Some("application/json"),
    );

    let body_bytes = axum::body::to_bytes(tts_response.into_body(), 256 * 1024)
        .await
        .expect("read tts token body");
    let tts_data: Value = serde_json::from_slice(&body_bytes).expect("valid json token");
    let token = tts_data["token"].as_str().expect("token field present");

    let stream_response = app
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

    assert_eq!(stream_response.status(), StatusCode::OK);
    assert_eq!(
        stream_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav"),
    );

    let disposition = stream_response
        .headers()
        .get("Content-Disposition")
        .and_then(|value| value.to_str().ok())
        .expect("content disposition header");
    assert!(disposition.contains("tts.wav"));

    let wav_bytes = axum::body::to_bytes(stream_response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert!(!wav_bytes.is_empty(), "wav body should not be empty");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("kokoro payload captured");
    assert_eq!(payload["text"], "Hello");
    assert_eq!(payload["voice"], KOKORO_DEFAULT_VOICE);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_tts_returns_error_when_service_fails() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let router = kokoro_error_router();
    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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

    assert_eq!(tts_response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(tts_response.into_body(), 128 * 1024)
        .await
        .expect("read tts token body");
    let tts_data: Value = serde_json::from_slice(&body_bytes).expect("valid json token");
    let token = tts_data["token"].as_str().expect("token field present");

    let stream_response = app
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

    assert_eq!(stream_response.status(), StatusCode::BAD_GATEWAY);

    let content_type = stream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content type");
    assert!(content_type.contains("application/json"));

    let body_bytes = axum::body::to_bytes(stream_response.into_body(), 128 * 1024)
        .await
        .expect("read error body");
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "voice service unavailable");

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_tts_rejects_empty_text() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let _workspace = begin_kokoro_workspace("127.0.0.1", 65535);

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
async fn kokoro_api_tts_generates_wav_audio() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8, 1, 2, 3, 4, 5]);
    let router = kokoro_voice_router(captured.clone(), pcm);

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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
    let payload = captured_payloads.first().expect("kokoro payload recorded");
    assert_eq!(payload["text"], "Hello");
    assert_eq!(payload["voice"], KOKORO_DEFAULT_VOICE);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_api_tts_returns_backend_error() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let router = kokoro_offline_router();
    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_api_tts_stream_proxies_audio() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8; 4]);
    let chunks: Arc<Vec<Bytes>> = Arc::new(vec![
        Bytes::from_static(b"chunk-1"),
        Bytes::from_static(b"chunk-2"),
    ]);
    let router = kokoro_voice_router_with_stream(captured.clone(), pcm, chunks);

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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
    assert!(body_bytes.len() > 44);
    assert_eq!(&body_bytes[0..4], b"RIFF");
    assert_eq!(&body_bytes[8..12], b"WAVE");
    assert_eq!(&body_bytes[44..], b"chunk-1chunk-2");

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("kokoro stream payload");
    assert_eq!(payload["text"], "Streaming example");
    assert_eq!(payload["voice"], KOKORO_DEFAULT_VOICE);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_api_tts_rejects_empty_text() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let _workspace = begin_kokoro_workspace("127.0.0.1", 65535);

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

#[tokio::test]
async fn kokoro_strips_markdown_formatting() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8; 100]);
    let router = kokoro_voice_router(captured.clone(), pcm);

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_workspace(&addr.ip().to_string(), addr.port());

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

    let input_text = "This is **bold** and *italic* text.";
    let expected_text = "This is bold and italic text.";

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
    let payload = captured_payloads.first().expect("kokoro payload captured");

    assert_eq!(payload["text"], expected_text, "Markdown should be stripped");
    assert_eq!(payload["voice"], KOKORO_DEFAULT_VOICE);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

// --- Fish Speech (deprecated provider) ---

#[tokio::test]
async fn fish_api_tts_generates_wav_audio() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let wav_data = Arc::new(vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'A', b'V', b'E']);
    let router = fish_speech_router(captured.clone(), wav_data.clone());

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_fish_workspace(&addr.ip().to_string(), addr.port());

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

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("read body");
    assert_eq!(body_bytes.as_ref(), wav_data.as_slice());

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("fish payload captured");

    assert_eq!(payload["text"], "Hello Fish");
    assert_eq!(payload["reference_id"], "default");
    assert_eq!(payload["format"], "wav");
    assert_eq!(payload["streaming"], false);

    shutdown.send(()).ok();
    handle.join().expect("join fish stub thread");
}

#[tokio::test]
async fn fish_api_tts_stream_uses_correct_format() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let wav_data = Arc::new(vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'A', b'V', b'E']);
    let router = fish_speech_router(captured.clone(), wav_data);

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_fish_workspace(&addr.ip().to_string(), addr.port());

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

    let captured_payloads = captured.lock().await;
    let payload = captured_payloads.first().expect("fish stream payload captured");

    assert_eq!(payload["text"], "Hello Stream");
    assert_eq!(payload["reference_id"], "default");
    assert_eq!(payload["format"], "wav");
    assert_eq!(payload["streaming"], true);

    shutdown.send(()).ok();
    handle.join().expect("join fish stub thread");
}
