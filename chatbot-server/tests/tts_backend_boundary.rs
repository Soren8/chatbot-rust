//! HTTP characterization of the TTS backend-result boundary (MOD-011).
//!
//! Given a provider stub, when a clip is synthesized and streamed with
//! `tts_codec: wav`, then the wire bytes must carry the backend-declared
//! sample rate, the backend PCM payload, WAV headers, and a bounded replay
//! cache; oversize encoded clips must be rejected without burning the token.
//! These tests pin the observable contract before the synthesis code moves
//! out of `tts.rs` into a backend module that returns owned PCM plus rate.

mod common;

use std::{env, net::SocketAddr, sync::Arc, thread::JoinHandle};

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
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex as AsyncMutex},
};
use tower::ServiceExt;

static TTS_BOUNDARY_MUTEX: Lazy<std::sync::Mutex<()>> =
    Lazy::new(|| std::sync::Mutex::new(()));

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

const KOKORO_DEFAULT_VOICE: &str = "af_heart";

fn tts_boundary_lock() -> std::sync::MutexGuard<'static, ()> {
    TTS_BOUNDARY_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn kokoro_wav_config(voice_host: &str, voice_port: u16) -> String {
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
tts_codec: wav
voice_service_host: "{voice_host}"
voice_service_port: {voice_port}
"#
    )
}

fn fish_wav_config() -> &'static str {
    r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${OPENAI_API_KEY}"
    context_size: 4096
tts_provider: fish
tts_codec: wav
"#
}

fn begin_kokoro_wav_workspace(voice_host: &str, voice_port: u16) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    TestWorkspace::with_config(&kokoro_wav_config(voice_host, voice_port))
}

fn begin_fish_wav_workspace(tts_host: &str, tts_port: u16) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::set_var("TTS_HOST", tts_host);
    env::set_var("TTS_PORT", tts_port.to_string());
    TestWorkspace::with_config(fish_wav_config())
}

async fn guest_session(app: &axum::Router) -> (String, String) {
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
    let csrf_token = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf_token)
}

async fn post_tts_token(app: &axum::Router, cookie: &str, csrf: &str, text: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(
                    serde_json::to_vec(&json!({ "text": text })).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read token body");
    serde_json::from_slice::<Value>(&body)
        .expect("valid json token")["token"]
        .as_str()
        .expect("token field present")
        .to_owned()
}

async fn get_stream(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream response")
}

/// Mono 16-bit WAV with a nonzero ramp payload so edge fades are observable.
fn ramp_wav(rate: u32, samples: u32) -> Vec<u8> {
    let mut wav = Vec::with_capacity(44 + samples as usize * 2);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&((36 + samples * 2) as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&rate.to_le_bytes());
    wav.extend_from_slice(&(rate * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(samples * 2).to_le_bytes());
    for i in 0..samples {
        let sample = (1 + (u64::from(i) * 7919) % 20000) as i16 - 10000;
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    wav
}

fn wav_rate(body: &[u8]) -> u32 {
    u32::from_le_bytes([body[24], body[25], body[26], body[27]])
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

#[tokio::test]
async fn fish_wav_preserves_backend_rate_bytes_and_replays_from_cache() {
    common::init_tracing();
    let _lock = tts_boundary_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let stub_wav = Arc::new(ramp_wav(16_000, 960));
    let router = Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let stub_wav = stub_wav.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let stub_wav = stub_wav.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        stub_wav.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_fish_wav_workspace(&addr.ip().to_string(), addr.port());
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello Fish WAV").await;
    let response = get_stream(&app, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav"),
    );
    let disposition = response
        .headers()
        .get("Content-Disposition")
        .and_then(|value| value.to_str().ok())
        .expect("content disposition header");
    assert!(disposition.contains("tts.wav"));

    let first_clip = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert_eq!(first_clip.len(), stub_wav.len());
    assert_eq!(&first_clip[0..4], b"RIFF");
    assert_eq!(wav_rate(&first_clip), 16_000);
    assert_eq!(
        &first_clip[44..],
        &stub_wav[44..],
        "fish PCM must pass through unfaded, including edge samples"
    );

    let retry = get_stream(&app, &token).await;
    assert_eq!(retry.status(), StatusCode::OK);
    let retry_clip = axum::body::to_bytes(retry.into_body(), 512 * 1024)
        .await
        .expect("read retry wav body");
    assert_eq!(retry_clip, first_clip, "retry must reuse the cached clip");

    let captured_payloads = captured.lock().await;
    assert_eq!(captured_payloads.len(), 1, "replay must not resynthesize");
    assert_eq!(captured_payloads[0]["text"], "Hello Fish WAV");
    assert_eq!(captured_payloads[0]["reference_id"], "default");
    assert_eq!(captured_payloads[0]["format"], "wav");
    assert_eq!(captured_payloads[0]["streaming"], false);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_wav_uses_voice_service_rate_with_edge_fade_and_replays() {
    common::init_tracing();
    let _lock = tts_boundary_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    // 2400 samples at 24 kHz: the 5 ms edge fade touches the first/last 120
    // samples only, so the middle must match the backend bytes exactly.
    let stub_pcm = Arc::new(
        (0..2400u32)
            .flat_map(|i| (((1 + (u64::from(i) * 7919) % 20000) as i16) - 10000).to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    assert_ne!(&stub_pcm[0..2], &[0, 0], "ramp must start nonzero for the fade pin");
    let router = Router::new().route(
        "/v1/tts/kokoro",
        post({
            let captured = captured.clone();
            let stub_pcm = stub_pcm.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let stub_pcm = stub_pcm.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/octet-stream"),
                            (
                                header::HeaderName::from_static("x-sample-rate"),
                                "24000",
                            ),
                        ],
                        stub_pcm.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_wav_workspace(&addr.ip().to_string(), addr.port());
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello Kokoro WAV").await;
    let response = get_stream(&app, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav"),
    );

    let first_clip = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert_eq!(first_clip.len(), 44 + stub_pcm.len());
    assert_eq!(&first_clip[0..4], b"RIFF");
    assert_eq!(wav_rate(&first_clip), 24_000);
    assert_eq!(
        &first_clip[44..46],
        &[0, 0],
        "kokoro fade-in must scale the first sample to silence"
    );
    assert_eq!(
        &first_clip[44 + 480..44 + stub_pcm.len() - 480],
        &stub_pcm[480..stub_pcm.len() - 480],
        "fade must leave the middle of the clip untouched"
    );

    let retry = get_stream(&app, &token).await;
    assert_eq!(retry.status(), StatusCode::OK);
    let retry_clip = axum::body::to_bytes(retry.into_body(), 512 * 1024)
        .await
        .expect("read retry wav body");
    assert_eq!(retry_clip, first_clip, "retry must reuse the cached clip");

    let captured_payloads = captured.lock().await;
    assert_eq!(captured_payloads.len(), 1, "replay must not resynthesize");
    assert_eq!(captured_payloads[0]["text"], "Hello Kokoro WAV");
    assert_eq!(captured_payloads[0]["voice"], KOKORO_DEFAULT_VOICE);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn kokoro_wav_defaults_to_24k_without_sample_rate_header() {
    common::init_tracing();
    let _lock = tts_boundary_lock();

    // 100 samples at 24 kHz is below twice the 5 ms fade window, so the fade
    // is skipped and the backend bytes must pass through exactly.
    let stub_pcm = Arc::new(vec![3u8; 200]);
    let router = Router::new().route(
        "/v1/tts/kokoro",
        post({
            let stub_pcm = stub_pcm.clone();
            move |Json(_payload): Json<Value>| {
                let stub_pcm = stub_pcm.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        stub_pcm.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_kokoro_wav_workspace(&addr.ip().to_string(), addr.port());
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello default rate").await;
    let response = get_stream(&app, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    let clip = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert_eq!(clip.len(), 44 + stub_pcm.len());
    assert_eq!(wav_rate(&clip), 24_000);
    assert_eq!(&clip[44..], &stub_pcm[..]);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn oversize_encoded_clip_is_rejected_but_token_stays_retryable() {
    common::init_tracing();
    let _lock = tts_boundary_lock();

    // 8.4 MB of WAV encodes to 8.4 MB of wire WAV, over the 8 MB encoded
    // cache cap. The token must stay usable so a retry can re-synthesize.
    let stub_wav = Arc::new(ramp_wav(16_000, 4_200_000));
    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let router = Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let stub_wav = stub_wav.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let stub_wav = stub_wav.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        stub_wav.as_slice().to_vec(),
                    )
                }
            }
        }),
    );

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_fish_wav_workspace(&addr.ip().to_string(), addr.port());
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello oversize").await;

    for attempt in 1..=2 {
        let response = get_stream(&app, &token).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "oversize attempt {attempt} must be rejected"
        );
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read error body");
        let payload: Value = serde_json::from_slice(&body).expect("json error body");
        assert_eq!(payload["error"], "Invalid request body");
    }
    assert_eq!(
        captured.lock().await.len(),
        2,
        "the rejected token must allow a retry to re-synthesize, not stick at 429 or 404"
    );

    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}
