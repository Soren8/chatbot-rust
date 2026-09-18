//! Characterization of generation lease settlement (MOD-006).
//!
//! Given a `/chat` or `/regenerate` request, when the stream succeeds, fails
//! in the provider, is cancelled before its first poll, is cancelled
//! mid-stream, or fails before preparation, then exactly one settlement must
//! run: success and any post-poll cancel persist (even an empty partial),
//! provider errors and pre-poll cancels release without persisting, and
//! pre-prepare failures save an error turn without ever holding the lock.
//!
//! These tests pin the current route behavior before lease extraction; they
//! must pass unchanged before and after.

mod common;

use std::{
    env,
    fs,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::Body,
    http::{header, Method, Request, Response, StatusCode},
    Router,
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
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

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
}

fn seed_user(workspace_path: &std::path::Path, username: &str, password: &str) {
    let hashed = hash(password, DEFAULT_COST).expect("hash");
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
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).unwrap())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
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

fn regenerate_request(
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: Value,
) -> Request<Body> {
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

/// A follow-up generation must succeed (200 with streamed content): the
/// previous settlement released the generation lock exactly once.
async fn assert_lock_released(app: &Router, auth: &AuthCtx) {
    set_chunks(&["follow-up answer"]);
    let (status, body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "follow-up", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "lock must be released: {body}");
    assert!(
        body.contains("follow-up answer"),
        "follow-up must stream after release, got: {body}"
    );
}

#[tokio::test]
async fn chat_success_persists_pair_and_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_success", "LeaseSuccess1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_success", "LeaseSuccess1!").await;

    set_chunks(&["hello there"]);
    let (status, body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "greet me", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hello there"), "got: {body}");

    let history = load_history(&app, &auth).await;
    assert_eq!(history.len(), 1, "success must persist one pair");
    assert_eq!(history[0][0], "greet me");
    assert_eq!(history[0][1], "hello there");

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_provider_error_persists_nothing_and_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_provider_error", "LeaseProvider1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_provider_error", "LeaseProvider1!").await;

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        r#"["partial","__STREAM_ERROR__"]"#,
    );
    let (status, body) = read_body(
        app.clone()
            .oneshot(chat_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "should-not-save", "set_name": "default"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("[Error]"), "got: {body}");

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        0,
        "provider error must never persist, even partial text"
    );

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_cancel_before_first_poll_releases_without_persisting() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_cancel_early", "LeaseCancel1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_cancel_early", "LeaseCancel1!").await;

    set_chunks(&["never read"]);
    let response = app
        .clone()
        .oneshot(chat_request(
            &auth.cookie,
            &auth.csrf,
            &auth.enc_key,
            json!({"message": "cancelled early", "set_name": "default"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Drop the response without ever polling its body: the stream guard is
    // never created, so settlement must release the lock and persist nothing.
    drop(response);
    clear_generation_env();

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        0,
        "pre-poll cancel must persist nothing"
    );

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_cancel_midstream_persists_partial_and_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_cancel_mid", "LeaseCancelMid1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_cancel_mid", "LeaseCancelMid1!").await;

    set_chunks(&["part-one ", "part-two"]);
    let response = app
        .clone()
        .oneshot(chat_request(
            &auth.cookie,
            &auth.csrf,
            &auth.enc_key,
            json!({"message": "cancel me midstream", "set_name": "default"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Poll exactly one body frame (guard created, first chunk pushed), then
    // drop: settlement must persist the partial text and release the lock.
    let mut data_stream = response.into_body().into_data_stream();
    let first = data_stream.next().await;
    assert!(
        first.is_some(),
        "first stream frame must be polled before cancel"
    );
    drop(data_stream);
    clear_generation_env();

    let history = load_history(&app, &auth).await;
    assert_eq!(history.len(), 1, "mid-stream cancel must persist one pair");
    assert_eq!(history[0][0], "cancel me midstream");
    assert_eq!(history[0][1], "part-one ");

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_cancel_after_poll_before_first_chunk_persists_empty_partial() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_cancel_empty", "LeaseCancelEmpty1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_cancel_empty", "LeaseCancelEmpty1!").await;

    // A large per-chunk delay keeps the first chunk pending so one manual poll
    // creates the stream guard without pushing any text.
    set_chunks(&["too late"]);
    env::set_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS", "30000");
    let response = app
        .clone()
        .oneshot(chat_request(
            &auth.cookie,
            &auth.csrf,
            &auth.enc_key,
            json!({"message": "cancel while empty", "set_name": "default"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Poll (with a short timeout against the 30s chunk delay) so the stream
    // guard is created while no chunk is available yet, then drop: the guard
    // must persist the empty partial and release the lock. The stream is an
    // owned binding so `drop` settles it immediately (a `pin!` temporary
    // would live until the end of the block instead).
    let mut data_stream = response.into_body().into_data_stream();
    let timed_out = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        data_stream.next(),
    )
    .await
    .is_err();
    assert!(
        timed_out,
        "first chunk must still be pending under the 30s delay"
    );
    // Guard was polled with no chunk yet: dropping must persist the empty
    // partial (so Stop followed by Edit still finds the pair) and release.
    drop(data_stream);
    clear_generation_env();

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        1,
        "post-poll cancel must persist even an empty partial"
    );
    assert_eq!(history[0][0], "cancel while empty");
    assert_eq!(history[0][1], "");

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn chat_unknown_model_saves_error_turn_without_holding_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_unknown_model", "LeaseUnknown1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_unknown_model", "LeaseUnknown1!").await;

    // A prior success creates the session entry so the saved error turn has a
    // store row to persist into (finalize never creates rows).
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

    set_chunks(&["unused"]);
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
        "got: {body}"
    );

    let history = load_history(&app, &auth).await;
    assert_eq!(history.len(), 2, "setup failure must save an error turn");
    assert_eq!(history[1][0], "second attempt");
    assert!(
        history[1][1]
            .as_str()
            .unwrap()
            .contains("requested model not found"),
        "got: {}",
        history[1][1]
    );

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_success_persists_replacement_and_releases_lock() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_regen_success", "LeaseRegen1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_regen_success", "LeaseRegen1!").await;

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

    set_chunks(&["v2 answer"]);
    let (status, body) = read_body(
        app.clone()
            .oneshot(regenerate_request(
                &auth.cookie,
                &auth.csrf,
                &auth.enc_key,
                json!({"message": "original", "set_name": "default", "pair_index": 0}),
            ))
            .await
            .unwrap(),
    )
    .await;
    clear_generation_env();

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("v2 answer"), "got: {body}");

    let history = load_history(&app, &auth).await;
    assert_eq!(history.len(), 1, "regenerate must replace, not append");
    assert_eq!(history[0][0], "original");
    assert_eq!(history[0][1], "v2 answer");

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn regenerate_cancel_midstream_persists_partial_replacement() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "generation_lease_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    clear_generation_env();
    seed_user(workspace.path(), "lease_regen_cancel", "LeaseRegenCancel1!");

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "lease_regen_cancel", "LeaseRegenCancel1!").await;

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

    set_chunks(&["partial-v2 ", "rest"]);
    let response = app
        .clone()
        .oneshot(regenerate_request(
            &auth.cookie,
            &auth.csrf,
            &auth.enc_key,
            json!({"message": "original", "set_name": "default", "pair_index": 0}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut data_stream = response.into_body().into_data_stream();
    let first = data_stream.next().await;
    assert!(
        first.is_some(),
        "first regenerate frame must be polled before cancel"
    );
    drop(data_stream);
    clear_generation_env();

    let history = load_history(&app, &auth).await;
    assert_eq!(
        history.len(),
        1,
        "cancelled regenerate must keep one replaced pair"
    );
    assert_eq!(history[0][0], "original");
    assert_eq!(history[0][1], "partial-v2 ");

    assert_lock_released(&app, &auth).await;
    clear_generation_env();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}
