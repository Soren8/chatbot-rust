//! TTS API tests with provider-accurate HTTP stubs (no live voice-service).

mod common;

use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread::JoinHandle,
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json, Router,
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::user_store::{CreateOutcome, UserStore};
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

fn kokoro_test_config_with_access(voice_host: &str, voice_port: u16, tts_access: &str) -> String {
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
tts_access: {tts_access}
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

fn begin_kokoro_workspace_with_access(
    voice_host: &str,
    voice_port: u16,
    tts_access: &str,
) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    TestWorkspace::with_config(&kokoro_test_config_with_access(
        voice_host,
        voice_port,
        tts_access,
    ))
}

fn begin_fish_workspace(tts_host: &str, tts_port: u16) -> TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    env::set_var("TTS_HOST", tts_host);
    env::set_var("TTS_PORT", tts_port.to_string());
    TestWorkspace::with_config(fish_test_config())
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

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("create user: {err}"),
    }
}

fn set_user_tier(username: &str, tier: &str) {
    let path = env::var("HOST_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"))
        .join("users.json");
    let raw = fs::read_to_string(&path).expect("read users.json");
    let mut users: Value = serde_json::from_str(&raw).expect("parse users.json");
    users[username]["tier"] = json!(tier);
    fs::write(&path, serde_json::to_vec_pretty(&users).expect("serialize")).expect("write users");
}

async fn login_session(app: &axum::Router, username: &str, password: &str) -> (String, String) {
    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    let set_cookie = get_response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = axum::body::to_bytes(get_response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).unwrap();
    let cookie = common::extract_cookie(&set_cookie);

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
    );

    let post_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let cookie_header = common::extract_cookie(&login_cookie);

    // Home after login for a chat-page CSRF token.
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / after login");
    let body = axum::body::to_bytes(home.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body_text = std::str::from_utf8(&body).unwrap();
    let csrf = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf meta token after login");
    (cookie_header, csrf)
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
async fn kokoro_tts_returns_wav_audio_and_allows_retry_after_transport_failure() {
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
    assert!(
        tts_response.headers().get("X-TTS-Token").is_some(),
        "token response must expose the token before its body can be aborted"
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
    assert_eq!(
        stream_response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
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

    // NativeVoiceTts retries the same GET when a spotty link truncates an
    // otherwise successful response. The token must remain replayable for a
    // bounded retry window instead of turning the sentence into a silent gap.
    let retry_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream retry response");
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_wav = axum::body::to_bytes(retry_response.into_body(), 512 * 1024)
        .await
        .expect("read retry wav body");
    assert_eq!(retry_wav, wav_bytes, "retry should reuse the generated clip");

    let cancel_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "cancel me"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts cancellation token response");
    assert_eq!(cancel_response.status(), StatusCode::OK);
    let cancel_body = axum::body::to_bytes(cancel_response.into_body(), 256 * 1024)
        .await
        .expect("read cancellation token body");
    let cancel_data: Value = serde_json::from_slice(&cancel_body)
        .expect("valid cancellation token body");
    let cancel_token = cancel_data["token"]
        .as_str()
        .expect("cancellation token present")
        .to_string();

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/tts_stream/{cancel_token}"))
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("DELETE /tts_stream cancellation response");
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let canceled_stream = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{cancel_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET canceled /tts_stream response");
    assert_eq!(canceled_stream.status(), StatusCode::NOT_FOUND);

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

    let retry_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream retry");
    assert_ne!(
        retry_response.status(),
        StatusCode::NOT_FOUND,
        "failed generation must not burn the TTS token"
    );

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
async fn tts_access_authenticated_rejects_guest() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let _workspace = begin_kokoro_workspace_with_access("127.0.0.1", 65535, "authenticated");
    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "Hello"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "TTS requires login");
}

#[tokio::test]
async fn tts_access_premium_rejects_free_user() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let _workspace = begin_kokoro_workspace_with_access("127.0.0.1", 65535, "premium");
    let app = build_router(resolve_static_root());

    seed_user("freeuser", "password123");
    let (cookie, csrf) = login_session(&app, "freeuser", "password123").await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "Hello"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "TTS requires a Premium account");
}

#[tokio::test]
async fn tts_access_premium_allows_premium_user() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let pcm = Arc::new(vec![0_u8, 1, 2, 3]);
    let router = kokoro_voice_router(captured.clone(), pcm);
    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace =
        begin_kokoro_workspace_with_access(&addr.ip().to_string(), addr.port(), "premium");
    let app = build_router(resolve_static_root());

    seed_user("premuser", "password123");
    set_user_tier("premuser", "premium");
    let (cookie, csrf) = login_session(&app, "premuser", "password123").await;

    let tts_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "Hello premium"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts");
    assert_eq!(tts_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(tts_response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let stream_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream");
    assert_eq!(stream_response.status(), StatusCode::OK);

    shutdown.send(()).ok();
    handle.join().expect("join voice stub");
}

#[tokio::test]
async fn unauthenticated_api_tts_routes_are_gone() {
    common::init_tracing();
    let _lock = tts_test_lock();
    let _workspace = begin_kokoro_workspace("127.0.0.1", 65535);
    let app = build_router(resolve_static_root());

    for uri in ["/api/tts", "/api/tts/stream"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"text": "nope"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{uri} should not be registered"
        );
    }
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
async fn fish_tts_via_presign_generates_wav_audio() {
    common::init_tracing();
    let _lock = tts_test_lock();

    let captured = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let wav_data = Arc::new(vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'A', b'V', b'E']);
    let router = fish_speech_router(captured.clone(), wav_data.clone());

    let (addr, shutdown, handle) = spawn_voice_stub(router).await;
    let _workspace = begin_fish_workspace(&addr.ip().to_string(), addr.port());

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    let tts_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    serde_json::to_vec(&json!({"text": "Hello Fish"})).expect("payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts");
    assert_eq!(tts_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(tts_response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let stream_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/tts_stream/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream");
    assert_eq!(stream_response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(stream_response.into_body(), 1024)
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
