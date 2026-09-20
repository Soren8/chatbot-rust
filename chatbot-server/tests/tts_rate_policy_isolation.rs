//! Live-config characterization for MOD-003 TTS/rate policy ownership.
//!
//! Given the global router, when `TTS_ACCESS` / `TTS_CODEC` / `TTS_PROVIDER` /
//! `RATE_LIMIT_*` change mid-process, then the next request follows the new
//! value with no router rebuild. Custom `tts_voice` reaches the Kokoro
//! backend as-is; the global 429 shape carries the scope message plus
//! `retry_after` JSON and a `Retry-After` header.
//!
//! These tests pin the exact live-lookup timing the split owners
//! (`RatePolicy`, `TtsPolicy`) preserve: one `app_config()` capture per
//! request in the rate middleware, per-call reads at the TTS access / codec /
//! synthesis sites, no early snapshot or env capture. Owned handles never
//! read ambient config; production stays on the live-global path.
//!
//! Owned-policy isolation (second half): two routers built with separate
//! [`RatePolicy`] / [`TtsPolicy`] handles share no budgets, gates, codecs or
//! synthesis backends, and owned values override live config without reading
//! it. The live-global router keeps the behavior pinned above.
//!
//! Already pinned elsewhere and not duplicated here:
//! - `tts.rs`: presign token/stream/cancel, opus default, 4-retry replay,
//!   silence path, `authenticated`/`premium` gates, error sanitization,
//!   markdown strip, no `/api/tts*`.
//! - `tts_backend_boundary.rs`: wav rate/bytes/fade/replay, oversize retryable.
//! - `rate_limit.rs`: per-user 429 with `Retry-After`, `/health` exempt.
//! - `router_resource_isolation.rs`: owned token/counter isolation, compat
//!   shared counters.
//!
//!
//! Two-router owned-policy isolation lives in the second half of this file.

mod common;

use std::{
    env,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    thread::JoinHandle,
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json, Router,
};
use chatbot_core::{config::TtsAccess, session_identity::HttpSessionStore};
use chatbot_server::{
    build_router, build_router_with_services,
    identity::RequestIdentity,
    policy::{RatePolicy, TtsPolicy},
    resolve_static_root,
    services::AppServices,
};
use chatbot_test_support::TestWorkspace;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex as AsyncMutex},
};
use tower::ServiceExt;
use std::sync::Arc;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn clear_policy_env() {
    for key in [
        "TTS_ACCESS",
        "TTS_CODEC",
        "TTS_PROVIDER",
        "TTS_HOST",
        "TTS_PORT",
        "RATE_LIMIT_PER_USER_PER_MINUTE",
        "RATE_LIMIT_GLOBAL_PER_MINUTE",
    ] {
        env::remove_var(key);
    }
}

fn disable_rate_limits() {
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
}

fn kokoro_config(voice_host: &str, voice_port: u16) -> String {
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

fn kokoro_config_with_voice(voice_host: &str, voice_port: u16, voice: &str) -> String {
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
tts_voice: {voice}
voice_service_host: "{voice_host}"
voice_service_port: {voice_port}
"#
    )
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("session cookie")
        .to_owned();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let html = std::str::from_utf8(&body).expect("utf8");
    let csrf = META_TOKEN_RE
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf)
}

async fn post_tts(app: &Router, cookie: &str, csrf: &str, text: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(
                    serde_json::to_vec(&json!({ "text": text })).expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts")
}

async fn post_tts_token(app: &Router, cookie: &str, csrf: &str, text: &str) -> String {
    let response = post_tts(app, cookie, csrf, text).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("token body");
    serde_json::from_slice::<Value>(&body).expect("json token")["token"]
        .as_str()
        .expect("token field")
        .to_owned()
}

async fn get_stream(app: &Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/tts_stream/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream")
}

async fn post_client_logs(app: &Router, cookie: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/client_logs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(r#"{"lines":["hello"]}"#))
                .unwrap(),
        )
        .await
        .expect("POST /client_logs")
}

fn kokoro_stub(captured: Arc<AsyncMutex<Vec<Value>>>, pcm: Arc<Vec<u8>>) -> Router {
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
                                "24000",
                            ),
                        ],
                        pcm.as_slice().to_vec(),
                    )
                }
            }
        }),
    )
}

fn tiny_silence_wav(rate: u32, samples: u32) -> Vec<u8> {
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
    wav.extend(std::iter::repeat(0).take(samples as usize * 2));
    wav
}

fn fish_stub(captured: Arc<AsyncMutex<Vec<Value>>>, wav: Arc<Vec<u8>>) -> Router {
    Router::new().route(
        "/v1/tts",
        post({
            let captured = captured.clone();
            let wav = wav.clone();
            move |Json(payload): Json<Value>| {
                let captured = captured.clone();
                let wav = wav.clone();
                async move {
                    captured.lock().await.push(payload);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "audio/wav")],
                        wav.as_slice().to_vec(),
                    )
                }
            }
        }),
    )
}

async fn spawn_stub(router: Router) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let std_listener = listener.into_std().expect("into std");
    let (tx, rx) = oneshot::channel();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("from std");
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
    });
    (addr, tx, handle)
}

#[tokio::test]
async fn live_rate_budgets_apply_without_router_rebuild_and_global_shape() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();

    let app = build_router(resolve_static_root());
    let client = "session=policy-live-rate-per-user";

    assert_eq!(
        post_client_logs(&app, client).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app, client).await.status(),
        StatusCode::NO_CONTENT
    );

    let limited = post_client_logs(&app, client).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = limited
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .expect("Retry-After header")
        .to_owned();
    assert!(
        retry_after.parse::<u64>().unwrap_or(0) >= 1,
        "Retry-After >= 1, got {retry_after}"
    );
    let body = axum::body::to_bytes(limited.into_body(), 16 * 1024)
        .await
        .expect("error body");
    let payload: Value = serde_json::from_slice(&body).expect("json error");
    assert!(
        payload["error"]
            .as_str()
            .unwrap_or("")
            .contains("Rate limit exceeded for this user"),
        "per-user message, got {payload}"
    );
    assert!(payload["retry_after"].as_u64().unwrap_or(0) >= 1);

    // Same router, limits disabled live: the next request passes.
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    assert_eq!(
        post_client_logs(&app, client).await.status(),
        StatusCode::NO_CONTENT,
        "disabled budgets must apply without a rebuild"
    );

    // Same router, global budget live: scope message differs but shape matches.
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "2");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    assert_eq!(
        post_client_logs(&app, "session=policy-live-global-1")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app, "session=policy-live-global-2")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let limited = post_client_logs(&app, "session=policy-live-global-3").await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(limited.into_body(), 16 * 1024)
        .await
        .expect("global error body");
    let payload: Value = serde_json::from_slice(&body).expect("json error");
    assert_eq!(payload["error"], "Server is busy (global rate limit). Please try again later.");
    assert!(payload["retry_after"].as_u64().unwrap_or(0) >= 1);

    clear_policy_env();
    disable_rate_limits();
}

#[tokio::test]
async fn live_tts_access_flip_applies_without_router_rebuild() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();
    let _workspace =
        TestWorkspace::with_config(&kokoro_config("127.0.0.1", 65535));
    disable_rate_limits();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    assert_eq!(
        post_tts(&app, &cookie, &csrf, "Hello").await.status(),
        StatusCode::OK,
        "default anyone allows guests"
    );

    env::set_var("TTS_ACCESS", "authenticated");
    chatbot_core::config::reset();
    let denied = post_tts(&app, &cookie, &csrf, "Hello").await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(denied.into_body(), 16 * 1024)
        .await
        .expect("deny body");
    let payload: Value = serde_json::from_slice(&body).expect("json deny");
    assert_eq!(payload["error"], "TTS requires login");

    env::set_var("TTS_ACCESS", "anyone");
    chatbot_core::config::reset();
    assert_eq!(
        post_tts(&app, &cookie, &csrf, "Hello").await.status(),
        StatusCode::OK,
        "flipping back must apply without a rebuild"
    );

    clear_policy_env();
    disable_rate_limits();
}

#[tokio::test]
async fn live_tts_codec_flip_applies_without_router_rebuild() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8; 4800]);
    let (addr, shutdown, handle) = spawn_stub(kokoro_stub(captured, pcm)).await;
    let _workspace =
        TestWorkspace::with_config(&kokoro_config(&addr.ip().to_string(), addr.port()));
    disable_rate_limits();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello opus").await;
    let first = get_stream(&app, &token).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("audio/ogg;codecs=opus"),
    );
    let first_bytes = axum::body::to_bytes(first.into_body(), 512 * 1024)
        .await
        .expect("opus body");
    assert_eq!(&first_bytes[0..4], b"OggS");

    env::set_var("TTS_CODEC", "wav");
    chatbot_core::config::reset();

    let token = post_tts_token(&app, &cookie, &csrf, "Hello wav").await;
    let second = get_stream(&app, &token).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("audio/wav"),
    );
    let second_bytes = axum::body::to_bytes(second.into_body(), 512 * 1024)
        .await
        .expect("wav body");
    assert_eq!(&second_bytes[0..4], b"RIFF");
    assert_eq!(
        u32::from_le_bytes([
            second_bytes[24],
            second_bytes[25],
            second_bytes[26],
            second_bytes[27]
        ]),
        24_000
    );

    clear_policy_env();
    disable_rate_limits();
    shutdown.send(()).ok();
    handle.join().expect("join stub");
}

#[tokio::test]
async fn custom_tts_voice_reaches_kokoro_backend() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8; 4800]);
    let (addr, shutdown, handle) =
        spawn_stub(kokoro_stub(captured.clone(), pcm)).await;
    let _workspace = TestWorkspace::with_config(&kokoro_config_with_voice(
        &addr.ip().to_string(),
        addr.port(),
        "test-custom-voice",
    ));
    disable_rate_limits();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello custom").await;
    let response = get_stream(&app, &token).await;
    assert_eq!(response.status(), StatusCode::OK);

    let payloads = captured.lock().await;
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["voice"], "test-custom-voice");

    clear_policy_env();
    disable_rate_limits();
    shutdown.send(()).ok();
    handle.join().expect("join stub");
}

#[tokio::test]
async fn live_tts_provider_flip_routes_to_other_backend_without_rebuild() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();

    let kokoro_captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let (kaddr, kshutdown, khandle) = spawn_stub(kokoro_stub(
        kokoro_captured.clone(),
        Arc::new(vec![0_u8; 4800]),
    ))
    .await;
    let fish_captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let fish_wav = Arc::new(tiny_silence_wav(25_200, 480));
    let (faddr, fshutdown, fhandle) =
        spawn_stub(fish_stub(fish_captured.clone(), fish_wav)).await;

    env::set_var("TTS_HOST", faddr.ip().to_string());
    env::set_var("TTS_PORT", faddr.port().to_string());
    let _workspace =
        TestWorkspace::with_config(&kokoro_config(&kaddr.ip().to_string(), kaddr.port()));
    disable_rate_limits();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let token = post_tts_token(&app, &cookie, &csrf, "Hello kokoro").await;
    assert_eq!(get_stream(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(kokoro_captured.lock().await.len(), 1);
    assert_eq!(fish_captured.lock().await.len(), 0);

    env::set_var("TTS_PROVIDER", "fish");
    chatbot_core::config::reset();

    let token = post_tts_token(&app, &cookie, &csrf, "Hello fish").await;
    assert_eq!(get_stream(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(
        kokoro_captured.lock().await.len(),
        1,
        "flipped synthesis must not hit kokoro"
    );
    assert_eq!(fish_captured.lock().await.len(), 1);
    assert_eq!(fish_captured.lock().await[0]["reference_id"], "default");

    clear_policy_env();
    disable_rate_limits();
    kshutdown.send(()).ok();
    fshutdown.send(()).ok();
    khandle.join().expect("join kokoro stub");
    fhandle.join().expect("join fish stub");
}

// --- Owned-policy isolation (separate RatePolicy / TtsPolicy owners) ---

/// Fully owned services with explicit policies and an explicit CSRF stance,
/// so the test never depends on ambient config. Each call backs one router.
fn owned_services(rate: RatePolicy, tts: TtsPolicy) -> AppServices {
    let store = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(store, true);
    AppServices::with_owned_stores(identity)
        .with_rate_policy(rate)
        .with_tts_policy(tts)
}

#[tokio::test]
async fn owned_rate_budgets_override_live_config_per_router() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    // Owned budgets enforce while live config disables limits ...
    let app_enforced = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::new(1, 0), TtsPolicy::global()),
    );
    // ... and owned-disabled bypasses even after live config enables them.
    let app_bypass = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::new(0, 0), TtsPolicy::global()),
    );

    let client = "session=policy-owned-rate-a";
    assert_eq!(
        post_client_logs(&app_enforced, client).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_enforced, client).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "owned budgets must enforce despite disabled live config"
    );

    assert_eq!(
        post_client_logs(&app_bypass, client).await.status(),
        StatusCode::NO_CONTENT,
        "same key on the sibling starts from its own empty window"
    );
    assert_eq!(
        post_client_logs(&app_bypass, "session=policy-owned-rate-b")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "1");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    assert_eq!(
        post_client_logs(&app_bypass, "session=policy-owned-rate-c")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_bypass, "session=policy-owned-rate-c")
            .await
            .status(),
        StatusCode::NO_CONTENT,
        "owned-disabled must keep bypassing enabled live config"
    );

    clear_policy_env();
    disable_rate_limits();
}

#[tokio::test]
async fn owned_tts_access_isolates_per_router_without_touching_live() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();
    let _workspace = TestWorkspace::with_config(&kokoro_config("127.0.0.1", 65535));
    disable_rate_limits();

    // POST /tts never synthesizes, so unreachable endpoints stay uncalled.
    let gated = TtsPolicy::new(
        TtsAccess::Authenticated,
        "opus".to_string(),
        "kokoro".to_string(),
        None,
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:9".to_string(),
    );
    let open = TtsPolicy::new(
        TtsAccess::Anyone,
        "opus".to_string(),
        "kokoro".to_string(),
        None,
        "http://127.0.0.1:9".to_string(),
        "http://127.0.0.1:9".to_string(),
    );
    let app_gated = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), gated),
    );
    let app_open = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), open),
    );

    let (cookie_gated, csrf_gated) = guest_session(&app_gated).await;
    let (cookie_open, csrf_open) = guest_session(&app_open).await;

    let denied = post_tts(&app_gated, &cookie_gated, &csrf_gated, "Hello").await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(denied.into_body(), 16 * 1024)
        .await
        .expect("deny body");
    let payload: Value = serde_json::from_slice(&body).expect("json deny");
    assert_eq!(payload["error"], "TTS requires login");

    assert_eq!(
        post_tts(&app_open, &cookie_open, &csrf_open, "Hello")
            .await
            .status(),
        StatusCode::OK,
        "the sibling keeps its own gate"
    );

    // The live-global router is unaffected by either owned gate.
    let app_live = build_router(resolve_static_root());
    let (cookie_live, csrf_live) = guest_session(&app_live).await;
    assert_eq!(
        post_tts(&app_live, &cookie_live, &csrf_live, "Hello")
            .await
            .status(),
        StatusCode::OK
    );

    clear_policy_env();
    disable_rate_limits();
}

#[tokio::test]
async fn owned_tts_codec_isolates_per_router() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8; 4800]);
    let (addr, shutdown, handle) = spawn_stub(kokoro_stub(captured, pcm)).await;
    let voice_base = format!("http://{}:{}", addr.ip(), addr.port());
    let _workspace = TestWorkspace::with_config(&kokoro_config(
        &addr.ip().to_string(),
        addr.port(),
    ));
    disable_rate_limits();

    let wav_policy = TtsPolicy::new(
        TtsAccess::Anyone,
        "wav".to_string(),
        "kokoro".to_string(),
        None,
        "http://127.0.0.1:9".to_string(),
        voice_base.clone(),
    );
    let opus_policy = TtsPolicy::new(
        TtsAccess::Anyone,
        "opus".to_string(),
        "kokoro".to_string(),
        None,
        "http://127.0.0.1:9".to_string(),
        voice_base,
    );
    let app_wav = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), wav_policy),
    );
    let app_opus = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), opus_policy),
    );

    let (cookie_wav, csrf_wav) = guest_session(&app_wav).await;
    let (cookie_opus, csrf_opus) = guest_session(&app_opus).await;

    let token = post_tts_token(&app_wav, &cookie_wav, &csrf_wav, "Hello wav").await;
    let wav_response = get_stream(&app_wav, &token).await;
    assert_eq!(wav_response.status(), StatusCode::OK);
    assert_eq!(
        wav_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("audio/wav"),
    );
    let wav_bytes = axum::body::to_bytes(wav_response.into_body(), 512 * 1024)
        .await
        .expect("wav body");
    assert_eq!(&wav_bytes[0..4], b"RIFF");

    let token = post_tts_token(&app_opus, &cookie_opus, &csrf_opus, "Hello opus").await;
    let opus_response = get_stream(&app_opus, &token).await;
    assert_eq!(opus_response.status(), StatusCode::OK);
    assert_eq!(
        opus_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("audio/ogg;codecs=opus"),
    );

    // The live-global router (opus default) is unaffected by the owned wav.
    let app_live = build_router(resolve_static_root());
    let (cookie_live, csrf_live) = guest_session(&app_live).await;
    let token = post_tts_token(&app_live, &cookie_live, &csrf_live, "Hello live").await;
    let live_response = get_stream(&app_live, &token).await;
    assert_eq!(live_response.status(), StatusCode::OK);
    assert_eq!(
        live_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("audio/ogg;codecs=opus"),
    );

    clear_policy_env();
    disable_rate_limits();
    shutdown.send(()).ok();
    handle.join().expect("join stub");
}

#[tokio::test]
async fn owned_tts_synthesis_ignores_live_config_and_routes_to_explicit_backend() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    clear_policy_env();

    let kokoro_captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let (kaddr, kshutdown, khandle) = spawn_stub(kokoro_stub(
        kokoro_captured.clone(),
        Arc::new(vec![0_u8; 4800]),
    ))
    .await;
    let fish_captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let fish_wav = Arc::new(tiny_silence_wav(25_200, 480));
    let (faddr, fshutdown, fhandle) =
        spawn_stub(fish_stub(fish_captured.clone(), fish_wav)).await;

    // Live config says fish, yet the owned kokoro router must still reach
    // kokoro with its explicit voice: owned synthesis never reads ambient.
    env::set_var("TTS_HOST", faddr.ip().to_string());
    env::set_var("TTS_PORT", faddr.port().to_string());
    let _workspace =
        TestWorkspace::with_config(&kokoro_config(&kaddr.ip().to_string(), kaddr.port()));
    env::set_var("TTS_PROVIDER", "fish");
    disable_rate_limits();

    let kokoro_owned = TtsPolicy::new(
        TtsAccess::Anyone,
        "opus".to_string(),
        "kokoro".to_string(),
        Some("owned-voice".to_string()),
        "http://127.0.0.1:9".to_string(),
        format!("http://{}:{}", kaddr.ip(), kaddr.port()),
    );
    let fish_owned = TtsPolicy::new(
        TtsAccess::Anyone,
        "opus".to_string(),
        "fish".to_string(),
        None,
        format!("http://{}:{}", faddr.ip(), faddr.port()),
        "http://127.0.0.1:9".to_string(),
    );
    let app_kokoro = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), kokoro_owned),
    );
    let app_fish = build_router_with_services(
        resolve_static_root(),
        owned_services(RatePolicy::global(), fish_owned),
    );

    let (cookie_k, csrf_k) = guest_session(&app_kokoro).await;
    let (cookie_f, csrf_f) = guest_session(&app_fish).await;

    let token = post_tts_token(&app_kokoro, &cookie_k, &csrf_k, "Hello owned kokoro").await;
    assert_eq!(get_stream(&app_kokoro, &token).await.status(), StatusCode::OK);
    assert_eq!(kokoro_captured.lock().await.len(), 1);
    assert_eq!(kokoro_captured.lock().await[0]["voice"], "owned-voice");
    assert_eq!(
        fish_captured.lock().await.len(),
        0,
        "owned kokoro must not touch the live fish backend"
    );

    let token = post_tts_token(&app_fish, &cookie_f, &csrf_f, "Hello owned fish").await;
    assert_eq!(get_stream(&app_fish, &token).await.status(), StatusCode::OK);
    assert_eq!(fish_captured.lock().await.len(), 1);
    assert_eq!(fish_captured.lock().await[0]["reference_id"], "default");
    assert_eq!(
        kokoro_captured.lock().await.len(),
        1,
        "owned fish must not touch kokoro"
    );

    clear_policy_env();
    disable_rate_limits();
    kshutdown.send(()).ok();
    fshutdown.send(()).ok();
    khandle.join().expect("join kokoro stub");
    fhandle.join().expect("join fish stub");
}
