//! MOD006 preprepare error ownership: saved error turns must not steal locks.
//!
//! Given a session locked by another generation, when a preprepare failure
//! (unknown model) arrives with a nonempty message, then the handler must
//! still return the 200 error turn but must neither persist it nor unlock the
//! other generation. Persisting without holding the lock races, and unlocking
//! another entry breaks mutual exclusion.

mod common;

use std::{
    env,
    fs,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

use axum::{
    body::Body,
    http::{header, Method, Request, Response, StatusCode},
    routing::post,
    Router,
};
use chatbot_core::session::ChatService;
use chatbot_server::{build_router, resolve_static_root};
use serde_json::{json, Value};
use tower::ServiceExt;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    test_mutex().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clear_generation_env() {
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::remove_var("XAI_API_KEY");
}

fn set_chunks(chunks: &[&str]) {
    let owned: Vec<String> = chunks.iter().map(|s| s.to_string()).collect();
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&owned).unwrap(),
    );
}

fn openai_config(base_url: &str) -> String {
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "{base_url}"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
"#
    )
}

/// Local mock OpenAI-compatible upstream with hit-count-switched behavior and
/// no production test hooks. Hits before `fail_on_hit` answer `delta_before`,
/// exactly that hit fails with `failure_status`, and later hits answer
/// `delta_after`. A failing hit exercises the real post-lease provider-error
/// path through the router (first-poll stream failure renders the error turn
/// without persisting and releases the lease); no
/// `CHATBOT_TEST_OPENAI_CHUNKS` fake is involved.
async fn spawn_switching_openai_mock(
    hits: std::sync::Arc<AtomicUsize>,
    fail_on_hit: usize,
    delta_before: &str,
    delta_after: &str,
    failure_status: StatusCode,
    failure_body: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (delta_before, delta_after, failure_body) = (
        delta_before.to_owned(),
        delta_after.to_owned(),
        failure_body.to_owned(),
    );
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let hits = hits.clone();
            let (delta_before, delta_after, failure_body) = (
                delta_before.clone(),
                delta_after.clone(),
                failure_body.clone(),
            );
            async move {
                let n = hits.fetch_add(1, Ordering::SeqCst);
                let delta = if n < fail_on_hit {
                    delta_before
                } else if n == fail_on_hit {
                    return (
                        failure_status,
                        [(header::CONTENT_TYPE, "application/json")],
                        failure_body,
                    );
                } else {
                    delta_after
                };
                let body = format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{delta}\"}}}}]}}\n\ndata: [DONE]\n\n"
                );
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind openai mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
}

fn seed_user(workspace_path: &std::path::Path, username: &str, password: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash");
    fs::write(
        workspace_path.join("users.json"),
        serde_json::to_string_pretty(&json!({
            username: { "password": hashed, "tier": "free" }
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn login_user(app: &Router, username: &str, password: &str) -> AuthCtx {
    let login_page = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    let mut cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("cookie");
    let body = axum::body::to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .unwrap();
    let csrf_login =
        common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).expect("csrf");

    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf_login),
    );
    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    if let Some(v) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let _ = axum::body::to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .unwrap();

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    if let Some(v) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let home_body = axum::body::to_bytes(home.into_body(), 512 * 1024)
        .await
        .unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&home_body).unwrap())
        .or_else(|| {
            regex::Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#)
                .ok()
                .and_then(|re| {
                    re.captures(std::str::from_utf8(&home_body).unwrap())
                        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
                })
        })
        .expect("csrf meta");
    let enc_key = common::derive_encryption_key_header(username, password);
    AuthCtx {
        cookie,
        csrf,
        enc_key,
    }
}

fn chat_request(cookie: &str, csrf: &str, enc_key: &str, payload: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
        .header("X-Enc-Key", enc_key)
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap()
}

fn regenerate_request(cookie: &str, csrf: &str, enc_key: &str, payload: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/regenerate")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
        .header("X-Enc-Key", enc_key)
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap()
}

async fn read_body(response: Response<Body>) -> (StatusCode, String) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("response body");
    (
        status,
        std::str::from_utf8(&bytes).unwrap().to_owned(),
    )
}

async fn load_history(app: &Router, auth: &AuthCtx) -> Vec<Value> {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 512 * 1024)
        .await
        .unwrap();
    let loaded: Value = serde_json::from_slice(&body).unwrap();
    loaded["history"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn chat_preprepare_error_skips_save_and_keeps_lock_when_busy() {
    common::init_tracing();
    let _guard = test_guard();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_busy_chat", "LeaseBusyChat1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_busy_chat", "LeaseBusyChat1!").await;

    set_chunks(&["first answer"]);
    let (first_status, _) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "first", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    clear_generation_env();

    assert!(
        ChatService::global().try_acquire_generation("lease_busy_chat"),
        "test must hold the generation lock"
    );

    let (status, body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({
                    "message": "second attempt",
                    "set_name": "default",
                    "model_name": "no-such-model",
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("requested model not found"),
        "preprepare error must still return its turn, got: {body}"
    );

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        1,
        "busy preprepare error must not persist another turn"
    );

    assert!(
        !ChatService::global().try_acquire_generation("lease_busy_chat"),
        "busy preprepare error must never unlock the other generation"
    );

    ChatService::global().release_session_lock("lease_busy_chat");
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_preprepare_error_skips_save_and_keeps_lock_when_busy() {
    common::init_tracing();
    let _guard = test_guard();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_busy_regen", "LeaseBusyRegen1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_busy_regen", "LeaseBusyRegen1!").await;

    set_chunks(&["v1 answer"]);
    let (chat_status, _) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "original", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);
    clear_generation_env();

    assert!(
        ChatService::global().try_acquire_generation("lease_busy_regen"),
        "test must hold the generation lock"
    );

    let (status, body) = read_body(
        app.clone()
            .oneshot(regenerate_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({
                    "message": "original",
                    "set_name": "default",
                    "pair_index": 0,
                    "model_name": "no-such-model",
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("requested model not found"),
        "preprepare error must still return its turn, got: {body}"
    );

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        1,
        "busy regenerate preprepare error must not persist another turn"
    );

    assert!(
        !ChatService::global().try_acquire_generation("lease_busy_regen"),
        "busy regenerate preprepare error must never unlock the other generation"
    );

    ChatService::global().release_session_lock("lease_busy_regen");
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_upstream_500_renders_error_without_persisting_and_releases_lease() {
    common::init_tracing();
    let _guard = test_guard();

    // Actual provider error after a successful prepare (no test-chunks fake):
    // the mock fails the first upstream call with HTTP 500, then answers.
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) = spawn_switching_openai_mock(
        hits.clone(),
        0,
        "unused before answer",
        "recovered answer",
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":{"message":"mock upstream failure"}}"#,
    )
    .await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_lease_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let workspace = common::TestWorkspace::with_config(&openai_config(&base_url));
    seed_user(workspace.path(), "lease_setup_chat", "LeaseSetupChat1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_setup_chat", "LeaseSetupChat1!").await;

    let (status, body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "trigger upstream failure", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("[Error]") && body.contains("backend LLM provider"),
        "upstream failure must render its error turn, got: {body}"
    );

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        0,
        "upstream stream failure must persist nothing, not even partial text"
    );

    let (follow_status, follow_body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "after error", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;

    mock_handle.abort();
    clear_generation_env();

    assert_eq!(
        follow_status,
        StatusCode::OK,
        "lease must be released exactly once after upstream failure: {follow_body}"
    );
    assert!(
        follow_body.contains("recovered answer"),
        "follow-up must stream after upstream failure, got: {follow_body}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_upstream_500_preserves_pair_and_releases_lease() {
    common::init_tracing();
    let _guard = test_guard();

    // Hit 0 streams the seed pair, hit 1 fails the regenerate upstream call
    // with HTTP 500, later hits answer replacements. No test-chunks fake.
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (mock_addr, mock_handle) = spawn_switching_openai_mock(
        hits.clone(),
        1,
        "v1 answer",
        "v2 answer",
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":{"message":"mock upstream failure"}}"#,
    )
    .await;

    clear_generation_env();
    env::set_var("SECRET_KEY", "generation_lease_secret");
    let base_url = format!("http://{mock_addr}/v1");
    let workspace = common::TestWorkspace::with_config(&openai_config(&base_url));
    seed_user(workspace.path(), "lease_setup_regen", "LeaseSetupRegen1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_setup_regen", "LeaseSetupRegen1!").await;

    let (chat_status, _) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "original", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(chat_status, StatusCode::OK);

    let (status, body) = read_body(
        app.clone()
            .oneshot(regenerate_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({
                    "message": "original",
                    "set_name": "default",
                    "pair_index": 0,
                }),
            ))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("[Error]") && body.contains("backend LLM provider"),
        "regenerate upstream failure must render its error turn, got: {body}"
    );

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        1,
        "failed regenerate must keep one pair"
    );
    assert_eq!(history[0][0], "original");
    assert_eq!(
        history[0][1], "v1 answer",
        "upstream stream failure must preserve the original pair, got: {}",
        history[0][1]
    );

    let (follow_status, follow_body) = read_body(
        app.clone()
            .oneshot(regenerate_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({
                    "message": "original",
                    "set_name": "default",
                    "pair_index": 0,
                }),
            ))
            .await
            .unwrap(),
    )
    .await;

    mock_handle.abort();
    clear_generation_env();

    assert_eq!(
        follow_status,
        StatusCode::OK,
        "lease must be released exactly once after regenerate failure: {follow_body}"
    );
    assert!(
        follow_body.contains("v2 answer"),
        "follow-up regenerate must stream after failure, got: {follow_body}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}
