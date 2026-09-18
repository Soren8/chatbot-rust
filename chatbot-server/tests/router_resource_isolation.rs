//! MOD-003 router resource isolation through production endpoints.
//!
//! Fully owned [`AppServices`] routers share no TTS tokens or rate-limit
//! counters. Compatibility [`build_router_with_identity`] routers keep the
//! established shared-other-stores semantics (owned identity, global tokens
//! and counters). Rate windows are verified by exhausting budgets, never by
//! sleeping.

use std::{
    env,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Json, Router,
};
use chatbot_core::session_identity::HttpSessionStore;
use chatbot_server::{
    build_router_with_identity, build_router_with_services,
    identity::RequestIdentity,
    resolve_static_root,
    services::AppServices,
};
use regex::Regex;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};
use tower::ServiceExt;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    test_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn disable_rate_limits() {
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
}

/// Fresh fully owned services with an explicit CSRF policy, so the test
/// never depends on ambient config. Each call backs an independent router.
fn owned_services() -> AppServices {
    let store = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(store, true);
    AppServices::with_owned_stores(identity)
}

fn owned_router() -> Router {
    build_router_with_services(resolve_static_root(), owned_services())
}

/// Compatibility router: owned identity, shared global tokens and counters.
fn compat_router() -> Router {
    let store = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(store, true);
    build_router_with_identity(resolve_static_root(), identity)
}

fn session_pair(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .find(|pair| pair.starts_with("session="))
        .expect("session cookie present")
}

fn csrf_from_home(html: &str) -> String {
    let re = Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).expect("csrf regex");
    re.captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("home csrf token present")
}

async fn home_session(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_pair(&response);
    let body = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let html = std::str::from_utf8(&body).expect("utf8 home");
    (cookie, csrf_from_home(html))
}

async fn post_tts(app: &Router, cookie: &str, csrf: &str, text: &str) -> (StatusCode, Option<String>) {
    let response = app
        .clone()
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
        .expect("POST /tts");
    let status = response.status();
    if status != StatusCode::OK {
        return (status, None);
    }
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read token body");
    let token = serde_json::from_slice::<Value>(&body)
        .expect("json token")["token"]
        .as_str()
        .expect("token field")
        .to_owned();
    (status, Some(token))
}

async fn get_stream(app: &Router, token: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/tts_stream/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /tts_stream");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read stream body")
        .to_vec();
    (status, bytes)
}

async fn delete_token(app: &Router, token: &str, cookie: &str, csrf: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/tts_stream/{token}"))
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("DELETE /tts_stream")
        .status()
}

async fn post_client_logs(app: &Router, cookie: &str) -> StatusCode {
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
        .status()
}

fn kokoro_stub_router(calls: Arc<AtomicUsize>, pcm: Arc<Vec<u8>>) -> Router {
    Router::new().route(
        "/v1/tts/kokoro",
        post({
            let pcm = pcm.clone();
            move |Json(_payload): Json<Value>| {
                let pcm = pcm.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
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

async fn spawn_voice_stub(
    router: Router,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
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
async fn owned_routers_do_not_replay_or_cancel_each_others_tts_tokens() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    disable_rate_limits();

    let calls = Arc::new(AtomicUsize::new(0));
    let pcm = Arc::new(vec![0_u8; 4800]);
    let (addr, shutdown, handle) =
        spawn_voice_stub(kokoro_stub_router(calls.clone(), pcm)).await;
    let _workspace = common::TestWorkspace::with_config(&format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
tts_provider: kokoro
voice_service_host: "{}"
voice_service_port: {}
"#,
        addr.ip(),
        addr.port()
    ));
    disable_rate_limits();

    let app_a = owned_router();
    let app_b = owned_router();
    let (cookie_a, csrf_a) = home_session(&app_a).await;
    let (cookie_b, csrf_b) = home_session(&app_b).await;

    // Presign gate preserved on owned routers: no CSRF means no token.
    let (status, _) = post_tts(&app_a, &cookie_a, "bogus-token", "Hello").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "owned router must keep the TTS CSRF gate"
    );

    let (status, token_a) = post_tts(&app_a, &cookie_a, &csrf_a, "Hello isolation").await;
    assert_eq!(status, StatusCode::OK);
    let token_a = token_a.expect("token admitted on router A");

    // First playback synthesizes once through the voice-service stub.
    let (status, first_audio) = get_stream(&app_a, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&first_audio[0..4], b"OggS", "wire codec stays Ogg-Opus");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Cached replay serves identical bytes without resynthesizing.
    let (status, replay_audio) = get_stream(&app_a, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        replay_audio, first_audio,
        "replay must reuse the cached clip"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "replay must not resynthesize"
    );

    // The sibling router never saw this admission.
    let (status, _) = get_stream(&app_b, &token_a).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "router B must not replay router A's token"
    );

    // Cancelling through the sibling is a harmless no-op for the owner.
    assert_eq!(
        delete_token(&app_b, &token_a, &cookie_b, &csrf_b).await,
        StatusCode::NO_CONTENT
    );
    let (status, still_cached) = get_stream(&app_a, &token_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(still_cached, first_audio);

    // Cancelling through the owner removes the token there only.
    assert_eq!(
        delete_token(&app_a, &token_a, &cookie_a, &csrf_a).await,
        StatusCode::NO_CONTENT
    );
    let (status, _) = get_stream(&app_a, &token_a).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_stream(&app_b, &token_a).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Admission is symmetric: B's token stays unknown on A.
    let (status, token_b) = post_tts(&app_b, &cookie_b, &csrf_b, "Hello back").await;
    assert_eq!(status, StatusCode::OK);
    let token_b = token_b.expect("token admitted on router B");
    let (status, _) = get_stream(&app_a, &token_b).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "router A must not replay router B's token"
    );
    let (status, _) = get_stream(&app_b, &token_b).await;
    assert_eq!(status, StatusCode::OK);

    disable_rate_limits();
    shutdown.send(()).ok();
    handle.join().expect("join voice stub thread");
}

#[tokio::test]
async fn owned_routers_keep_per_client_rate_counters_independent() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();

    let app_a = owned_router();
    let app_b = owned_router();
    // Presented-but-unknown cookies map to a stable per-cookie key without
    // creating a session, so both routers see the same logical client.
    let client = "session=mod003-per-client-isolation";
    let other_client = "session=mod003-per-client-other";

    assert_eq!(post_client_logs(&app_a, client).await, StatusCode::NO_CONTENT);
    assert_eq!(post_client_logs(&app_a, client).await, StatusCode::NO_CONTENT);
    assert_eq!(
        post_client_logs(&app_a, client).await,
        StatusCode::TOO_MANY_REQUESTS,
        "router A must enforce its own per-client window"
    );

    // Same client key on the sibling starts from an empty window.
    assert_eq!(post_client_logs(&app_b, client).await, StatusCode::NO_CONTENT);
    assert_eq!(post_client_logs(&app_b, client).await, StatusCode::NO_CONTENT);
    assert_eq!(
        post_client_logs(&app_b, client).await,
        StatusCode::TOO_MANY_REQUESTS,
        "router B must enforce its own per-client window"
    );

    // A different client on A is unaffected by the first client's budget.
    assert_eq!(
        post_client_logs(&app_a, other_client).await,
        StatusCode::NO_CONTENT,
        "per-client windows must isolate keys within a router"
    );

    disable_rate_limits();
}

#[tokio::test]
async fn owned_routers_keep_global_rate_counters_independent() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "2");
    chatbot_core::config::reset();

    let app_a = owned_router();
    let app_b = owned_router();

    assert_eq!(
        post_client_logs(&app_a, "session=mod003-global-a1").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_a, "session=mod003-global-a2").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_a, "session=mod003-global-a3").await,
        StatusCode::TOO_MANY_REQUESTS,
        "router A must enforce its own global window"
    );

    // The sibling's global window starts empty despite A's exhaustion.
    assert_eq!(
        post_client_logs(&app_b, "session=mod003-global-b1").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_b, "session=mod003-global-b2").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app_b, "session=mod003-global-b3").await,
        StatusCode::TOO_MANY_REQUESTS,
        "router B must enforce its own global window"
    );

    disable_rate_limits();
}

#[tokio::test]
async fn compat_identity_routers_still_share_global_rate_counters() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();

    // `build_router_with_identity` keeps the established compatibility
    // semantics: the identity is owned, counters stay process-global.
    let app_a = compat_router();
    let app_b = compat_router();
    let client = "session=mod003-compat-shared-client";

    assert_eq!(post_client_logs(&app_a, client).await, StatusCode::NO_CONTENT);
    assert_eq!(post_client_logs(&app_a, client).await, StatusCode::NO_CONTENT);

    assert_eq!(
        post_client_logs(&app_b, client).await,
        StatusCode::TOO_MANY_REQUESTS,
        "compat routers must share the global per-client budget"
    );

    disable_rate_limits();
}
