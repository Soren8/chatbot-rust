//! Voice requests must use their initiating set's durable privacy policy.

mod common;

use std::{env, fs, net::SocketAddr, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex, OnceLock}};

use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, routing::post, Router};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{account_service::AccountService, session::{ChatService, ChatSessionStore}, session_identity::HttpSessionStore, user_store::UserStore};
use chatbot_server::{build_router_with_services, identity::RequestIdentity, resolve_static_root, services::AppServices};
use chatbot_test_support::TestWorkspace;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};
use tower::ServiceExt;

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|err| err.into_inner())
}

fn home_csrf(html: &[u8]) -> String {
    let html = std::str::from_utf8(html).unwrap();
    regex::Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#)
        .unwrap().captures(html).unwrap()[1].to_owned()
}

struct Session { cookie: String, csrf: String, key: String }

async fn guest(app: &Router) -> Session {
    let page = app.clone().oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = common::extract_cookie(page.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let html = to_bytes(page.into_body(), 256 * 1024).await.unwrap();
    let csrf = home_csrf(&html);
    Session { cookie, csrf, key: String::new() }
}

async fn login(app: &Router, user: &str, password: &str) -> Session {
    let page = app.clone().oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = common::extract_cookie(page.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let html = to_bytes(page.into_body(), 64 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&html).unwrap()).unwrap();
    let form = format!("username={}&password={}&csrf_token={}", urlencoding::encode(user), urlencoding::encode(password), urlencoding::encode(&csrf));
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/login")
        .header(header::COOKIE, cookie).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = common::extract_cookie(response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let page = app.clone().oneshot(Request::builder().uri("/").header(header::COOKIE, &cookie).body(Body::empty()).unwrap()).await.unwrap();
    let html = to_bytes(page.into_body(), 256 * 1024).await.unwrap();
    let csrf = home_csrf(&html);
    Session { cookie, csrf, key: common::derive_encryption_key_header(user, password) }
}

async fn json_post(app: &Router, session: &Session, uri: &str, payload: Value) -> (StatusCode, Value) {
    let request = Request::builder().method(Method::POST).uri(uri).header(header::COOKIE, &session.cookie)
        .header("X-CSRF-Token", &session.csrf).header("X-Enc-Key", &session.key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap())).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn multipart(set_id: Option<&str>, first: bool) -> String {
    let audio = "--voiceprivacy\r\ncontent-disposition: form-data; name=\"audio\"; filename=\"a.webm\"\r\ncontent-type: audio/webm\r\n\r\nfakeaudio\r\n";
    let set = set_id.map(|id| format!("--voiceprivacy\r\ncontent-disposition: form-data; name=\"set_id\"\r\n\r\n{id}\r\n")).unwrap_or_default();
    if first { format!("{set}{audio}--voiceprivacy--\r\n") } else { format!("{audio}{set}--voiceprivacy--\r\n") }
}

async fn stt(app: &Router, session: &Session, set_id: Option<&str>, set_first: bool) -> (StatusCode, Value) {
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/stt")
        .header(header::COOKIE, &session.cookie).header("X-CSRF-Token", &session.csrf)
        .header("X-Enc-Key", &session.key)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=voiceprivacy")
        .body(Body::from(multipart(set_id, set_first))).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn voice_stub() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let stt_hits = Arc::new(AtomicUsize::new(0));
    let tts_hits = Arc::new(AtomicUsize::new(0));
    let stt_counter = stt_hits.clone();
    let tts_counter = tts_hits.clone();
    let router = Router::new().route("/v1/stt", post(move |mut form: axum::extract::Multipart| {
        let hits = stt_counter.clone();
        async move {
            let mut audio = None;
            while let Some(field) = form.next_field().await.unwrap() {
                if field.name() == Some("audio") { audio = Some(field.bytes().await.unwrap()); }
            }
            assert_eq!(audio.as_deref(), Some(&b"fakeaudio"[..]));
            hits.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({"text":"stub transcript"}))
        }
    })).route("/v1/tts/kokoro", post(move |axum::Json(payload): axum::Json<Value>| {
        let hits = tts_counter.clone();
        async move {
            assert!(payload["text"].is_string());
            hits.fetch_add(1, Ordering::SeqCst);
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/octet-stream"),
                (header::HeaderName::from_static("x-sample-rate"), "24000")], vec![0_u8; 480])
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, done) = oneshot::channel();
    let server = tokio::spawn(async move { axum::serve(listener, router).with_graceful_shutdown(async { let _ = done.await; }).await.unwrap(); });
    (address, stt_hits, tts_hits, shutdown, server)
}

async fn paused_tts_stub() -> (SocketAddr, Arc<AtomicUsize>, oneshot::Receiver<()>, oneshot::Sender<()>, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let gate = Arc::new(tokio::sync::Mutex::new(Some((started_tx, release_rx))));
    let router = Router::new().route("/v1/tts/kokoro", post(move |axum::Json(payload): axum::Json<Value>| {
        let hits = counter.clone();
        let gate = gate.clone();
        async move {
            assert_eq!(payload["text"], "Hold synthesis open");
            hits.fetch_add(1, Ordering::SeqCst);
            let (started, release) = gate.lock().await.take().expect("one synthesis request");
            started.send(()).unwrap();
            release.await.unwrap();
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/octet-stream"),
                (header::HeaderName::from_static("x-sample-rate"), "24000")], vec![0_u8; 480])
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, done) = oneshot::channel();
    let server = tokio::spawn(async move { axum::serve(listener, router).with_graceful_shutdown(async { let _ = done.await; }).await.unwrap(); });
    (address, hits, started_rx, release_tx, shutdown, server)
}

fn app_config(address: SocketAddr) -> String {
    app_config_with_voice_level(address, "non_private")
}

fn app_config_with_voice_level(address: SocketAddr, voice_level: &str) -> String {
    format!(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-test
    base_url: https://api.openai.com/v1
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
tts_provider: kokoro
tts_codec: wav
stt_privacy_level: {voice_level}
tts_privacy_level: {voice_level}
voice_service_host: "{}"
voice_service_port: {}
"#, address.ip(), address.port())
}

async fn setup(address: SocketAddr) -> (TestWorkspace, Router, Session, Session, Session, String, u64) {
    setup_with_voice_level(address, "non_private").await
}

async fn setup_with_voice_level(address: SocketAddr, voice_level: &str) -> (TestWorkspace, Router, Session, Session, Session, String, u64) {
    env::set_var("SECRET_KEY", "voice_privacy_test_secret");
    let workspace = TestWorkspace::with_config(&app_config_with_voice_level(address, voice_level));
    let user = "voice-policy-owner";
    let password = "VoicePassword!42";
    UserStore::new().unwrap().create_user(user, &hash(password, DEFAULT_COST).unwrap()).unwrap();
    let root = env::var("HOST_DATA_DIR").unwrap().into();
    let accounts = AccountService::with_root_and_secret(root, "voice_privacy_test_secret");
    let chat = ChatService::with_storage_and_accounts(Arc::new(ChatSessionStore::new(3600, String::new())),
        env::var("HOST_DATA_DIR").unwrap().into(), accounts.clone());
    let identity = RequestIdentity::with_store(Arc::new(HttpSessionStore::new(3600)));
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat).with_account_service(accounts);
    let app = build_router_with_services(resolve_static_root(), services);
    let first = login(&app, user, password).await;
    let second = login(&app, user, password).await;
    let visitor = guest(&app).await;
    let (status, created) = json_post(&app, &first, "/create_set", json!({"set_name":"voice privacy"})).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    (workspace, app, first, second, visitor, created["set_id"].as_str().unwrap().to_owned(), created["version"].as_u64().unwrap())
}

#[tokio::test]
async fn standard_set_can_use_standard_stt_and_tts_with_upstream_synthesis() {
    let _guard = test_lock();
    let (addr, stt_hits, tts_hits, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, second, _, set_id, version) = setup_with_voice_level(addr, "standard").await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"standard"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["privacy_level"], "standard");

    let (status, transcript) = stt(&app, &first, Some(&set_id), true).await;
    assert_eq!(status, StatusCode::OK, "{transcript}");
    assert_eq!(transcript["text"], "stub transcript");
    assert_eq!(stt_hits.load(Ordering::SeqCst), 1);

    let (status, issued) = json_post(&app, &first, "/tts", json!({"text":"Standard voice","set_id":set_id})).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(tts_hits.load(Ordering::SeqCst), 0, "POST only queues synthesis");
    let token = issued["token"].as_str().unwrap();
    let response = app.clone().oneshot(Request::builder().uri(format!("/tts_stream/{token}"))
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "audio/wav");
    let audio = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(&audio[..4], b"RIFF");
    assert_eq!(tts_hits.load(Ordering::SeqCst), 1);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn standard_set_denies_non_private_stt_and_tts_without_upstream() {
    let _guard = test_lock();
    let (addr, stt_hits, tts_hits, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, second, _, set_id, version) = setup(addr).await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"standard"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["privacy_level"], "standard");

    let (status, denied) = stt(&app, &first, Some(&set_id), false).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(denied["destination"], "stt");
    assert_eq!(stt_hits.load(Ordering::SeqCst), 0);

    let (status, denied) = json_post(&app, &first, "/tts", json!({"text":"Denied voice","set_id":set_id})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(denied["destination"], "tts");
    assert!(denied.get("token").is_none(), "denial must not issue a token: {denied}");
    assert_eq!(tts_hits.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn private_set_denies_standard_stt_and_tts_without_upstream() {
    let _guard = test_lock();
    let (addr, stt_hits, tts_hits, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, _, _, set_id, _) = setup_with_voice_level(addr, "standard").await;

    let (status, denied) = stt(&app, &first, Some(&set_id), true).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(denied["destination"], "stt");
    assert_eq!(stt_hits.load(Ordering::SeqCst), 0);

    let (status, denied) = json_post(&app, &first, "/tts", json!({"text":"Private voice","set_id":set_id})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(denied["destination"], "tts");
    assert!(denied.get("token").is_none(), "denial must not issue a token: {denied}");
    assert_eq!(tts_hits.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn stt_bound_non_private_allows_both_field_orders_but_private_denies_without_upstream() {
    let _guard = test_lock();
    let (addr, stt_hits, _, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, second, _, set_id, version) = setup(addr).await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"non_private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    for set_first in [true, false] {
        let (status, body) = stt(&app, &first, Some(&set_id), set_first).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["text"], "stub transcript");
    }
    assert_eq!(stt_hits.load(Ordering::SeqCst), 2);
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":changed["version"],"privacy_level":"private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let (status, denied) = stt(&app, &first, Some(&set_id), false).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(stt_hits.load(Ordering::SeqCst), 2);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn stt_legacy_hint_and_guest_set_rejection_never_contact_upstream() {
    let _guard = test_lock();
    let (addr, hits, _, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, _, visitor, set_id, _) = setup(addr).await;
    let (status, denied) = stt(&app, &first, None, false).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["hint"], "bind_set_id");
    let (status, denied) = stt(&app, &visitor, Some(&set_id), true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["error"], "set_id requires login");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn queued_non_private_tts_token_is_invalidated_before_private_switch_can_synthesize() {
    let _guard = test_lock();
    let (addr, _, hits, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, second, _, set_id, version) = setup(addr).await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"non_private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let (status, issued) = json_post(&app, &first, "/tts", json!({"text":"Do not synthesize after switch","set_id":set_id})).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["token"].as_str().unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0, "POST only queues synthesis");
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":changed["version"],"privacy_level":"private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let response = app.clone().oneshot(Request::builder().uri(format!("/tts_stream/{token}"))
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "invalidated token must never reach voice service");
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn active_tts_synthesis_blocks_mode_change_until_completion() {
    let _guard = test_lock();
    let (addr, hits, started, release, shutdown, server) = paused_tts_stub().await;
    let (_workspace, app, first, second, _, set_id, version) = setup(addr).await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"non_private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let admitted_version = changed["version"].as_u64().unwrap();
    let (status, issued) = json_post(&app, &first, "/tts", json!({"text":"Hold synthesis open","set_id":set_id})).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["token"].as_str().unwrap().to_owned();
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let streaming_app = app.clone();
    let stream = tokio::spawn(async move {
        streaming_app.oneshot(Request::builder().uri(format!("/tts_stream/{token}"))
            .body(Body::empty()).unwrap()).await.unwrap()
    });
    started.await.expect("backend received synthesis before mode change");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let (status, busy) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":admitted_version,"privacy_level":"private"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{busy}");
    assert_eq!(busy["error"], "privacy_busy");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    release.send(()).unwrap();
    let response = stream.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "audio/wav");
    let audio = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(&audio[..4], b"RIFF");
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":admitted_version,"privacy_level":"private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["privacy_level"], "private");
    assert_eq!(changed["version"], admitted_version + 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    shutdown.send(()).unwrap(); server.await.unwrap();
}

#[tokio::test]
async fn tts_backend_config_change_between_post_and_get_fails_closed() {
    let _guard = test_lock();
    let (original, _, original_hits, original_shutdown, original_server) = voice_stub().await;
    let (replacement, _, replacement_hits, replacement_shutdown, replacement_server) = voice_stub().await;
    let (workspace, app, first, second, _, set_id, version) = setup(original).await;
    let (status, changed) = json_post(&app, &second, "/set_privacy", json!({"set_id":set_id,"expected_version":version,"privacy_level":"non_private"})).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let (status, issued) = json_post(&app, &first, "/tts", json!({"text":"Must not reach either backend","set_id":set_id})).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let token = issued["token"].as_str().unwrap();
    assert_eq!(original_hits.load(Ordering::SeqCst), 0);
    assert_eq!(replacement_hits.load(Ordering::SeqCst), 0);

    fs::write(workspace.path().join(".config.yml"), format!("{}tts_voice: alternate_test_voice\n", app_config(replacement))).unwrap();
    chatbot_core::config::reset();
    let response = app.clone().oneshot(Request::builder().uri(format!("/tts_stream/{token}"))
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"], "tts_config_changed");
    assert_eq!(original_hits.load(Ordering::SeqCst), 0, "captured backend must not synthesize");
    assert_eq!(replacement_hits.load(Ordering::SeqCst), 0, "replacement backend must not synthesize");
    let replay = app.clone().oneshot(Request::builder().uri(format!("/tts_stream/{token}"))
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::NOT_FOUND, "invalidated token must not retry");
    original_shutdown.send(()).unwrap(); original_server.await.unwrap();
    replacement_shutdown.send(()).unwrap(); replacement_server.await.unwrap();
}

#[tokio::test]
async fn tts_legacy_hint_and_guest_set_rejection_never_issue_tokens_or_synthesize() {
    let _guard = test_lock();
    let (addr, _, hits, shutdown, server) = voice_stub().await;
    let (_workspace, app, first, _, visitor, set_id, _) = setup(addr).await;
    let (status, denied) = json_post(&app, &first, "/tts", json!({"text":"old client"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["error"], "privacy_restricted");
    assert_eq!(denied["hint"], "bind_set_id");
    let (status, denied) = json_post(&app, &visitor, "/tts", json!({"text":"guest","set_id":set_id})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["error"], "set_id requires login");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    shutdown.send(()).unwrap(); server.await.unwrap();
}
