//! MOD-003 router chat/history service isolation through production endpoints.
//!
//! Two routers built with distinct owned [`ChatService`]s (separate session
//! mirrors, redb roots, account roots, and verifier secrets) share no chat
//! history, memory, reset, regenerate, or saved-error-turn state, even for
//! the same username. Compatibility constructors keep the process-global chat
//! service; account HTTP paths (login/signup/home/preferences) stay global
//! until the next batch, so tests bootstrap identity via the production login
//! pages and enroll the explicit owned account roots through the user-store
//! API.

use std::{
    env,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::get,
    Router,
};
use chatbot_core::{
    history::HistoryService,
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
    user_store::UserStore,
};
use chatbot_server::{
    build_router_with_services, identity::RequestIdentity, resolve_static_root,
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

fn clear_generation_env() {
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::remove_var("XAI_API_KEY");
}

fn set_chunks(chunks: &[&str]) {
    let owned: Vec<String> = chunks.iter().map(|s| s.to_string()).collect();
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&owned).expect("chunk json"),
    );
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

struct OwnedSetup {
    _temp: tempfile::TempDir,
    app: Router,
    account_root: PathBuf,
}

/// Build an owned router with an explicit chat service. Call after the
/// `TestWorkspace` is installed so timeout/prompt resolve from the same
/// config the production `run()` captures. Chat stays fully isolated;
/// TTS tokens and rate counters are also owned. Account HTTP paths stay
/// global (next batch).
fn make_owned_setup(secret: &str) -> OwnedSetup {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg = chatbot_core::config::app_config();
    let timeout = cfg.session_timeout;
    let prompt = cfg.default_system_prompt.clone();

    let legacy_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&legacy_dir).expect("legacy dir");
    let redb_path = temp.path().join("history.redb");
    let history =
        HistoryService::open_with_data_dir(&redb_path, &legacy_dir, prompt.clone())
            .expect("open owned history");
    let sessions = Arc::new(ChatSessionStore::new(timeout, prompt));
    let account_root = temp.path().join("accounts");
    std::fs::create_dir_all(&account_root).expect("account root");
    let chat = ChatService::new(
        sessions,
        Arc::new(history),
        account_root.clone(),
        secret.to_owned(),
    );

    let identity = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat);
    let app = build_router_with_services(resolve_static_root(), services);
    OwnedSetup {
        _temp: temp,
        app,
        account_root,
    }
}

fn enroll_owned_root(account_root: &std::path::Path, username: &str, key_header: &str, secret: &str) {
    UserStore::open(account_root)
        .expect("open owned account store")
        .ensure_key_verifier_with_secret(
            username,
            key_header.as_bytes(),
            secret.as_bytes(),
        )
        .expect("enroll owned verifier");
}

fn seed_global_user(username: &str, password: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    let mut store = UserStore::new().expect("global user store");
    match store.create_user(username, &hashed) {
        Ok(_) => {}
        Err(err) => panic!("seed global user: {err}"),
    }
}

async fn login_owned(app: &Router, username: &str, password: &str) -> (String, String) {
    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let mut cookie = session_pair(&login_get);
    let body = axum::body::to_bytes(login_get.into_body(), 128 * 1024)
        .await
        .expect("read login");
    let form_csrf =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8")).expect("login csrf");
    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&form_csrf),
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
    assert_eq!(login_post.status(), StatusCode::FOUND);
    if let Some(raw) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(raw);
    }
    let _ = axum::body::to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .expect("drain login");

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    if let Some(raw) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        let rotated = common::extract_cookie(raw);
        if rotated.starts_with("session=") {
            cookie = rotated;
        }
    }
    let home_body = axum::body::to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));
    (cookie, csrf)
}

async fn post_chat(
    app: &Router,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

async fn post_load_set(
    app: &Router,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read load_set");
    let payload: Value = serde_json::from_slice(&bytes).expect("load_set json");
    (status, payload)
}

async fn post_json(
    app: &Router,
    uri: &str,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap_or_else(|_| panic!("POST {uri}"));
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read json body");
    let payload: Value = serde_json::from_slice(&bytes).expect("json body");
    (status, payload)
}

async fn post_regenerate(
    app: &Router,
    cookie: &str,
    csrf: &str,
    enc_key: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .header("X-Enc-Key", enc_key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /regenerate");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read regenerate");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn owned_routers_isolate_chat_history_for_same_username() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_chat_user";
    const PASSWORD: &str = "Sup3rS3cret!";
    const SECRET_A: &str = "router-chat-secret-a";
    const SECRET_B: &str = "router-chat-secret-b";

    seed_global_user(USERNAME, PASSWORD);
    // Valid Fernet keys (32-byte base64) so session sealing succeeds; distinct
    // per owner with distinct verifier secrets to pin scoped validation.
    let key_a = common::derive_encryption_key_header(USERNAME, PASSWORD);
    let key_b = {
        let store = UserStore::new().expect("global store");
        let bytes = store
            .derive_encryption_key(USERNAME, "DifferentPassForB123!")
            .expect("derive B key");
        String::from_utf8(bytes).expect("utf8 key")
    };

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);
    enroll_owned_root(&setup_a.account_root, USERNAME, &key_a, SECRET_A);
    enroll_owned_root(&setup_b.account_root, USERNAME, &key_b, SECRET_B);

    let (cookie_a, csrf_a) = login_owned(&setup_a.app, USERNAME, PASSWORD).await;
    let (cookie_b, csrf_b) = login_owned(&setup_b.app, USERNAME, PASSWORD).await;

    // CSRF gate preserved per router.
    let (status, _) = post_chat(
        &setup_a.app,
        &cookie_a,
        "bogus-token",
        &key_a,
        json!({"message": "hello", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Cross-key rejected without touching the other owner's history.
    set_chunks(&["should not matter"]);
    let (status, _) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_b,
        json!({"message": "cross key attempt", "set_name": "default"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "router A must reject router B's key"
    );

    set_chunks(&["answer from A"]);
    let (status, body) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "hello from A", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("answer from A"), "got: {body}");

    let (status, loaded_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    let history_a = loaded_a["history"].as_array().expect("history array");
    assert_eq!(history_a.len(), 1);
    assert_eq!(history_a[0][0], "hello from A");
    assert!(history_a[0][1].as_str().unwrap().contains("answer from A"));

    // Sibling with the same username sees none of A's history.
    let (status, loaded_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    let history_b = loaded_b["history"].as_array().expect("history array");
    assert_eq!(history_b.len(), 0, "router B must not see router A's chat");

    set_chunks(&["answer from B"]);
    let (status, body) = post_chat(
        &setup_b.app,
        &cookie_b,
        &csrf_b,
        &key_b,
        json!({"message": "hello from B", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("answer from B"), "got: {body}");

    let (status, reloaded_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reloaded_a["history"].as_array().unwrap().len(), 1);
    assert_eq!(reloaded_a["history"][0][0], "hello from A");

    let (status, reloaded_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    let history_b = reloaded_b["history"].as_array().unwrap();
    assert_eq!(history_b.len(), 1);
    assert_eq!(history_b[0][0], "hello from B");

    // Scoped durable check: the global history database was never opened.
    assert!(
        !workspace.path().join("history").exists(),
        "owned chat must not initialize the global history database"
    );

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn owned_routers_isolate_memory_reset_and_regenerate() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_chat_memory_user";
    const PASSWORD: &str = "Sup3rS3cret!";
    const SECRET_A: &str = "router-memory-secret-a";
    const SECRET_B: &str = "router-memory-secret-b";

    seed_global_user(USERNAME, PASSWORD);
    let key_a = common::derive_encryption_key_header(USERNAME, PASSWORD);
    let key_b = {
        let store = UserStore::new().expect("global store");
        let bytes = store
            .derive_encryption_key(USERNAME, "DifferentMemoryB123!")
            .expect("derive B key");
        String::from_utf8(bytes).expect("utf8 key")
    };

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);
    enroll_owned_root(&setup_a.account_root, USERNAME, &key_a, SECRET_A);
    enroll_owned_root(&setup_b.account_root, USERNAME, &key_b, SECRET_B);

    let (cookie_a, csrf_a) = login_owned(&setup_a.app, USERNAME, PASSWORD).await;
    let (cookie_b, csrf_b) = login_owned(&setup_b.app, USERNAME, PASSWORD).await;

    set_chunks(&["memory answer A"]);
    let (status, _) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "memory seed A", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    set_chunks(&["memory answer B"]);
    let (status, _) = post_chat(
        &setup_b.app,
        &cookie_b,
        &csrf_b,
        &key_b,
        json!({"message": "memory seed B", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Memory update on A is invisible on B.
    let (status, payload) = post_json(
        &setup_a.app,
        "/update_memory",
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"memory": "remember A", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");

    let (status, loaded_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(loaded_a["memory"], "remember A");

    let (status, loaded_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        loaded_b["memory"], "",
        "router B memory must not reflect router A"
    );

    // Regenerate on A replaces only A's pair.
    set_chunks(&["regenerated A"]);
    let (status, body) = post_regenerate(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "memory seed A", "set_name": "default", "pair_index": 0}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("regenerated A"), "got: {body}");

    let (status, reloaded_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reloaded_a["history"][0][1]
        .as_str()
        .unwrap()
        .contains("regenerated A"));

    let (status, reloaded_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reloaded_b["history"][0][1]
        .as_str()
        .unwrap()
        .contains("memory answer B"));

    // Reset on A clears only A.
    let (status, payload) = post_json(
        &setup_a.app,
        "/reset_chat",
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");

    let (status, reset_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset_a["history"].as_array().unwrap().len(), 0);

    let (status, kept_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept_b["history"].as_array().unwrap().len(), 1);

    assert!(
        !workspace.path().join("history").exists(),
        "owned memory/reset/regenerate must not initialize global history"
    );

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn scoped_saved_error_turn_persists_only_correct_owner() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_chat_error_user";
    const PASSWORD: &str = "Sup3rS3cret!";
    const SECRET_A: &str = "router-error-secret-a";
    const SECRET_B: &str = "router-error-secret-b";

    seed_global_user(USERNAME, PASSWORD);
    let key_a = common::derive_encryption_key_header(USERNAME, PASSWORD);
    let key_b = {
        let store = UserStore::new().expect("global store");
        let bytes = store
            .derive_encryption_key(USERNAME, "DifferentErrorB123!")
            .expect("derive B key");
        String::from_utf8(bytes).expect("utf8 key")
    };

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);
    enroll_owned_root(&setup_a.account_root, USERNAME, &key_a, SECRET_A);
    enroll_owned_root(&setup_b.account_root, USERNAME, &key_b, SECRET_B);

    let (cookie_a, csrf_a) = login_owned(&setup_a.app, USERNAME, PASSWORD).await;
    let (cookie_b, csrf_b) = login_owned(&setup_b.app, USERNAME, PASSWORD).await;

    // A prior success creates the session entry so the saved error turn has a
    // store row to persist into (finalize never creates rows).
    set_chunks(&["first answer"]);
    let (status, _) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "first", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    set_chunks(&["unused"]);
    let (status, body) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({
            "message": "second attempt",
            "set_name": "default",
            "model_name": "no-such-model",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("requested model not found"),
        "saved error turn must render the model error, got: {body}"
    );

    let (status, loaded_a) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    let history_a = loaded_a["history"].as_array().expect("history array");
    assert_eq!(history_a.len(), 2);
    assert_eq!(history_a[0][0], "first");
    assert_eq!(history_a[1][0], "second attempt");
    assert!(history_a[1][1]
        .as_str()
        .unwrap()
        .contains("requested model not found"));

    let (status, loaded_b) = post_load_set(&setup_b.app, &cookie_b, &csrf_b, &key_b).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        loaded_b["history"].as_array().unwrap().len(),
        0,
        "scoped error turn must not leak to the sibling owner"
    );

    // The lock was never held for the pre-prepare failure: a follow-up works.
    set_chunks(&["follow-up answer"]);
    let (status, body) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "follow-up", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("follow-up answer"), "got: {body}");

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn owned_chat_cancel_before_first_poll_releases_without_persisting() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_chat_cancel_user";
    const PASSWORD: &str = "Sup3rS3cret!";
    const SECRET_A: &str = "router-cancel-secret-a";

    seed_global_user(USERNAME, PASSWORD);
    let key_a = common::derive_encryption_key_header(USERNAME, PASSWORD);

    let setup_a = make_owned_setup(SECRET_A);
    enroll_owned_root(&setup_a.account_root, USERNAME, &key_a, SECRET_A);
    let (cookie_a, csrf_a) = login_owned(&setup_a.app, USERNAME, PASSWORD).await;

    set_chunks(&["never read"]);
    let response = setup_a
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie_a)
                .header("X-CSRF-Token", &csrf_a)
                .header("X-Enc-Key", key_a.as_str())
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "cancelled early",
                        "set_name": "default",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    clear_generation_env();

    let (status, loaded) = post_load_set(&setup_a.app, &cookie_a, &csrf_a, &key_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        loaded["history"].as_array().unwrap().len(),
        0,
        "pre-poll cancel must persist nothing on the owned service"
    );

    set_chunks(&["follow-up answer"]);
    let (status, body) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"message": "follow-up", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("follow-up answer"), "got: {body}");

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn owned_services_purge_leaves_global_chat_uninitialized() {
    common::init_tracing();
    let _guard = lock_tests();

    {
        env::set_var("SECRET_KEY", "integration_test_secret");
        let _workspace = common::TestWorkspace::with_config(
            "\nllms:\n  - provider_name: \"default\"\n    type: \"openai\"\n    model_name: \"gpt-test\"\n    base_url: \"https://api.openai.com/v1\"\n    api_key: \"${OPENAI_API_KEY}\"\n    context_size: 4096\nsession_timeout: 3600\ndefault_system_prompt: \"prompt-A-isolation\"\n",
        );
        disable_rate_limits();
        let temp = tempfile::tempdir().expect("tempdir");
        let legacy = temp.path().join("legacy");
        std::fs::create_dir_all(&legacy).expect("legacy");
        let history = HistoryService::open_with_data_dir(
            temp.path().join("history.redb"),
            &legacy,
            "prompt-A-isolation",
        )
        .expect("owned history");
        let sessions = Arc::new(ChatSessionStore::new(3600, "prompt-A-isolation".to_owned()));
        let chat = ChatService::new(
            sessions,
            Arc::new(history),
            temp.path().join("accounts"),
            "purge-secret-a".to_owned(),
        );
        let identity = RequestIdentity::with_store_and_csrf(
            Arc::new(HttpSessionStore::new(3600)),
            true,
        );
        let services = AppServices::with_owned_stores(identity).with_chat_service(chat);
        let (http_removed, chat_removed) = services.purge_for_background();
        assert_eq!(http_removed, 0);
        assert_eq!(chat_removed, 0);
    }

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_config(
        "\nllms:\n  - provider_name: \"default\"\n    type: \"openai\"\n    model_name: \"gpt-test\"\n    base_url: \"https://api.openai.com/v1\"\n    api_key: \"${OPENAI_API_KEY}\"\n    context_size: 4096\nsession_timeout: 7200\ndefault_system_prompt: \"prompt-B-isolation\"\n",
    );
    disable_rate_limits();
    let prompt = ChatService::global()
        .sessions()
        .default_prompt()
        .to_owned();
    assert_eq!(
        prompt, "prompt-B-isolation",
        "global chat store must freeze at first real use under the second config"
    );

    chatbot_core::config::reset();
    disable_rate_limits();
}

async fn spawn_health_stub() -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let router = Router::new().route("/health", get(|| async { StatusCode::OK }));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind health stub");
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

async fn get_deep_health(app: &Router) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health?deep=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /health?deep=true");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read health body");
    let payload: Value = serde_json::from_slice(&bytes).expect("health json");
    (status, payload)
}

#[tokio::test]
async fn owned_deep_health_uses_scoped_history_with_stub_voice() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");

    let (addr, shutdown, handle) = spawn_health_stub().await;
    let _workspace = common::TestWorkspace::with_config(&format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
voice_service_host: "{}"
voice_service_port: {}
"#,
        addr.ip(),
        addr.port()
    ));
    disable_rate_limits();

    let setup_a = make_owned_setup("health-secret-a");
    let setup_b = make_owned_setup("health-secret-b");

    for app in [&setup_a.app, &setup_b.app] {
        let (status, payload) = get_deep_health(app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["status"], "healthy");
        assert_eq!(payload["checks"]["history"], "ok");
        assert_eq!(payload["checks"]["voice_service"], "ok");
    }

    // Broken lazy history on the same service reports degraded without
    // touching the global database; repairing lets the same service retry.
    let temp = tempfile::tempdir().expect("tempdir");
    let blocked = temp.path().join("blocked");
    std::fs::write(&blocked, b"regular file where a directory is needed").expect("block");
    let cfg = chatbot_core::config::app_config();
    let sessions = Arc::new(ChatSessionStore::new(
        cfg.session_timeout,
        cfg.default_system_prompt.clone(),
    ));
    let chat = ChatService::with_storage(
        sessions,
        blocked.clone(),
        temp.path().join("accounts"),
        "health-secret-broken".to_owned(),
    );
    let identity = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat);
    let broken_app = build_router_with_services(resolve_static_root(), services);

    let (status, payload) = get_deep_health(&broken_app).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(payload["status"], "degraded");
    assert_eq!(payload["checks"]["history"], "unavailable");
    assert_eq!(payload["checks"]["voice_service"], "ok");

    std::fs::remove_file(&blocked).expect("repair");
    std::fs::create_dir_all(&blocked).expect("repair dir");
    let (status, payload) = get_deep_health(&broken_app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "healthy");
    assert_eq!(payload["checks"]["history"], "ok");

    disable_rate_limits();
    shutdown.send(()).ok();
    handle.join().expect("join health stub");
}
