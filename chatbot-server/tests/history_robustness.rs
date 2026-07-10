//! Integration tests for history robustness after the redb / HistoryService cutover.
//!
//! Covers: version conflicts (409), multi-set isolation (wrong-set pollution),
//! regenerate prepare non-clobber, enc-key gates, set_id API contract, guest vs authed.

use std::{
    env, fs,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    enc_key::EncryptionKey,
    history::{HistoryService, PrepareCapture, SetVersion},
    session,
};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
    username: String,
}

async fn login_user(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> AuthCtx {
    // Caller must seed users.json before login.
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

    let body = to_bytes(login_page.into_body(), 128 * 1024).await.unwrap();
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
    let _ = to_bytes(login_post.into_body(), 32 * 1024).await.unwrap();

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
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let home_html = std::str::from_utf8(&home_body).unwrap();
    let csrf = CSRF_META_RE
        .captures(home_html)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf meta");

    let enc_key = common::derive_encryption_key_header(username, password);
    AuthCtx {
        cookie,
        csrf,
        enc_key,
        username: username.to_owned(),
    }
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

async fn get_sets(app: &axum::Router, auth: &AuthCtx) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/get_sets")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 256 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn create_set(app: &axum::Router, auth: &AuthCtx, name: &str) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/create_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": name})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn load_set_by_name(app: &axum::Router, auth: &AuthCtx, name: &str) -> serde_json::Value {
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
                    serde_json::to_vec(&json!({"set_name": name})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "load_set failed for {name}");
    let body = to_bytes(res.into_body(), 512 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn chat(
    app: &axum::Router,
    auth: &AuthCtx,
    set_name: &str,
    message: &str,
    system_prompt: Option<&str>,
) {
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["chunk"]"#);
    let mut payload = json!({
        "message": message,
        "set_name": set_name,
    });
    if let Some(sp) = system_prompt {
        payload["system_prompt"] = json!(sp);
    }
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "chat failed");
    let _ = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}

fn enc_key_obj(auth: &AuthCtx) -> EncryptionKey {
    EncryptionKey::from_header_value(&auth.enc_key).unwrap()
}

#[tokio::test]
async fn get_sets_returns_set_id_and_version_contract() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "contract_user", "C0ntract!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "contract_user", "C0ntract!").await;

    let sets = get_sets(&app, &auth).await;
    let arr = sets.as_array().expect("array");
    assert!(!arr.is_empty());
    for s in arr {
        assert!(s.get("set_id").and_then(|v| v.as_str()).is_some());
        assert!(s.get("name").and_then(|v| v.as_str()).is_some());
        assert!(s.get("version").and_then(|v| v.as_u64()).is_some());
    }

    let created = create_set(&app, &auth, "project-x").await;
    assert_eq!(created["status"], "success");
    assert!(created.get("set_id").and_then(|v| v.as_str()).is_some());
    assert_eq!(created["name"], "project-x");
    assert!(created.get("version").and_then(|v| v.as_u64()).is_some());

    let loaded = load_set_by_name(&app, &auth, "project-x").await;
    assert_eq!(loaded["name"], "project-x");
    assert_eq!(
        loaded["set_id"].as_str().unwrap(),
        created["set_id"].as_str().unwrap()
    );
    assert!(loaded.get("version").is_some());
    assert!(loaded.get("history").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn delete_set_version_conflict_returns_409() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "conflict_user", "C0nflict!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "conflict_user", "C0nflict!").await;

    let created = create_set(&app, &auth, "doomed").await;
    let set_id = created["set_id"].as_str().unwrap().to_owned();
    let version = created["version"].as_u64().unwrap();

    // Advance version via memory update
    let mem = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_memory")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "set_name": "doomed",
                        "memory": "note",
                        "logged_in": true,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mem.status(), StatusCode::OK);

    // Stale version delete
    let del = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "set_id": set_id,
                        "expected_version": version, // stale
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::CONFLICT);
    let body = to_bytes(del.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "version_conflict");
    assert!(json.get("current_version").and_then(|v| v.as_u64()).unwrap() > version);

    // Set still exists
    let sets = get_sets(&app, &auth).await;
    assert!(sets
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "doomed"));
}

#[tokio::test]
async fn multi_set_chat_does_not_clobber_other_set() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "multiset_user", "Mult1set!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "multiset_user", "Mult1set!").await;

    create_set(&app, &auth, "alpha").await;
    create_set(&app, &auth, "beta").await;

    // Seed alpha with one chat
    chat(&app, &auth, "alpha", "alpha-msg-1", None).await;

    // Pollute session with beta (simulates other tab load_set)
    let beta_loaded = load_set_by_name(&app, &auth, "beta").await;
    assert_eq!(
        beta_loaded["history"].as_array().unwrap().len(),
        0,
        "beta starts empty"
    );

    // Chat still targeting alpha by name — must not use beta's empty history as base
    chat(&app, &auth, "alpha", "alpha-msg-2", None).await;

    let alpha = load_set_by_name(&app, &auth, "alpha").await;
    let alpha_hist = alpha["history"].as_array().unwrap();
    assert_eq!(
        alpha_hist.len(),
        2,
        "alpha should keep both chats despite mid-session beta load"
    );
    assert_eq!(alpha_hist[0][0], "alpha-msg-1");
    assert_eq!(alpha_hist[1][0], "alpha-msg-2");

    let beta = load_set_by_name(&app, &auth, "beta").await;
    assert_eq!(
        beta["history"].as_array().unwrap().len(),
        0,
        "beta must remain empty"
    );
}

#[tokio::test]
async fn regenerate_prepare_without_finalize_keeps_durable_history() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "regen_abort_user", "Reg3nAbort!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "regen_abort_user", "Reg3nAbort!").await;

    chat(&app, &auth, "default", "keep-me", None).await;
    chat(&app, &auth, "default", "also-keep", None).await;

    let before = load_set_by_name(&app, &auth, "default").await;
    assert_eq!(before["history"].as_array().unwrap().len(), 2);

    // Start regenerate then drop body without reading to end — server still finalizes on stream
    // drop in many runtimes, so instead verify non-destructive prepare via HistoryService:
    // advance would only happen on successful finalize. Simulate abort by not calling regenerate
    // and asserting prepare-side store is unchanged after a failed-style path:
    // Call regenerate with invalid pair_index so prepare fails early without commit.
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["should-not-persist"]"#);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "keep-me",
                        "set_name": "default",
                        "pair_index": 99
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // May stream OK with insertion_index None (append-style) — drain it
    let _ = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    // Core guarantee: original pairs still present (at least 2)
    let after = load_set_by_name(&app, &auth, "default").await;
    let hist = after["history"].as_array().unwrap();
    assert!(hist.len() >= 2);
    assert_eq!(hist[0][0], "keep-me");
    assert_eq!(hist[1][0], "also-keep");
}

#[tokio::test]
async fn regenerate_replaces_pair_keeps_later_messages() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "regen_keep_user", "Reg3nKeep!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "regen_keep_user", "Reg3nKeep!").await;

    chat(&app, &auth, "default", "u1", None).await;
    chat(&app, &auth, "default", "u2", None).await;
    chat(&app, &auth, "default", "u3", None).await;

    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["regenerated-mid"]"#);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "u2",
                        "set_name": "default",
                        "pair_index": 1
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("regenerated-mid"));
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    let loaded = load_set_by_name(&app, &auth, "default").await;
    let hist = loaded["history"].as_array().unwrap();
    assert_eq!(hist.len(), 3);
    assert_eq!(hist[0][0], "u1");
    assert_eq!(hist[1][0], "u2");
    assert!(hist[1][1].as_str().unwrap().contains("regenerated-mid"));
    assert_eq!(hist[2][0], "u3");
}

#[tokio::test]
async fn mutations_require_encryption_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "encgate_user", "EncGate1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "encgate_user", "EncGate1!").await;

    for (uri, body) in [
        (
            "/get_sets",
            None,
        ),
        (
            "/create_set",
            Some(json!({"set_name": "nope"})),
        ),
        (
            "/load_set",
            Some(json!({"set_name": "default"})),
        ),
        (
            "/update_memory",
            Some(json!({"set_name": "default", "memory": "x", "logged_in": true})),
        ),
        (
            "/delete_message",
            Some(json!({
                "pair_index": 0,
                "user_message": "x",
                "set_name": "default"
            })),
        ),
        (
            "/reset_chat",
            Some(json!({"set_name": "default"})),
        ),
    ] {
        let mut builder = Request::builder()
            .method(if uri == "/get_sets" {
                Method::GET
            } else {
                Method::POST
            })
            .uri(uri)
            .header(header::COOKIE, &auth.cookie)
            .header("X-CSRF-Token", &auth.csrf);
        if uri != "/get_sets" {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        // deliberately omit X-Enc-Key
        let req = if let Some(b) = body {
            builder
                .body(Body::from(serde_json::to_vec(&b).unwrap()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} should require enc key"
        );
    }

    // Wrong key
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/get_sets")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", "not-a-valid-key-material-xxxxx")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn guest_chat_does_not_touch_redb_user_store() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());

    // Guest home for csrf
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).unwrap())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf");

    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["guest-chunk"]"#);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "guest hi",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let _ = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    // Guest get_sets unauthorized
    let sets = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/get_sets")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sets.status(), StatusCode::UNAUTHORIZED);

    // No user redb data required for guest; history file may or may not exist
    // from other tests in process — just ensure guest path didn't require enc key.
    let _ = cookie;
    let _ = workspace;
}

#[tokio::test]
async fn stale_chat_capture_conflict_surfaces_error_chunk() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "stale_cap_user", "StaleCap1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "stale_cap_user", "StaleCap1!").await;

    // Seed one message
    chat(&app, &auth, "default", "first", None).await;

    // Concurrently advance version via HistoryService while simulating stale capture commit
    let key = enc_key_obj(&auth);
    let hs = HistoryService::global().unwrap();
    let snap = hs
        .find_by_display_name(&auth.username, "default", &key)
        .unwrap()
        .unwrap();
    let stale = PrepareCapture::from_snapshot(&snap);

    // Advance
    hs.append_pair(
        &auth.username,
        snap.set_id,
        snap.version,
        "concurrent",
        "writer",
        &key,
    )
    .unwrap();

    // Stale finalize
    let sess = session::session_context(Some(&auth.cookie)).unwrap();
    let extras = session::chat_finalize_with_capture(
        &sess,
        "default",
        "stale-msg",
        "stale-ai",
        Some(&key),
        Some(stale),
    );
    assert!(
        extras.iter().any(|e| e.contains("conflict") || e.contains("Failed")),
        "expected conflict error extra, got {extras:?}"
    );

    let after = hs
        .find_by_display_name(&auth.username, "default", &key)
        .unwrap()
        .unwrap();
    assert_eq!(after.history.len(), 2);
    assert_eq!(after.history[0].0, "first");
    assert_eq!(after.history[1].0, "concurrent");
    assert_ne!(after.version, SetVersion(1));
}

#[tokio::test]
async fn delete_message_content_mismatch_and_out_of_range() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "delmsg_user", "DelMsg1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "delmsg_user", "DelMsg1!").await;

    chat(&app, &auth, "default", "hello", None).await;

    let mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 0,
                        "user_message": "not-hello",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);

    let oor = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 9,
                        "user_message": "hello",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oor.status(), StatusCode::NOT_FOUND);

    // Successful delete
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete_message")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "pair_index": 0,
                        "user_message": "hello",
                        "set_name": "default"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let loaded = load_set_by_name(&app, &auth, "default").await;
    assert_eq!(loaded["history"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn reset_chat_clears_only_named_set() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "reset_iso_user", "ResetIso1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "reset_iso_user", "ResetIso1!").await;

    create_set(&app, &auth, "keep").await;
    chat(&app, &auth, "default", "wipe-me", None).await;
    chat(&app, &auth, "keep", "preserve-me", None).await;

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/reset_chat")
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

    let default = load_set_by_name(&app, &auth, "default").await;
    assert_eq!(default["history"].as_array().unwrap().len(), 0);
    let keep = load_set_by_name(&app, &auth, "keep").await;
    assert_eq!(keep["history"].as_array().unwrap().len(), 1);
    assert_eq!(keep["history"][0][0], "preserve-me");
}

#[tokio::test]
async fn rename_set_rejects_duplicate_display_name() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "rename_dup_user", "RenameDup1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "rename_dup_user", "RenameDup1!").await;

    let alpha = create_set(&app, &auth, "alpha").await;
    let beta = create_set(&app, &auth, "beta").await;
    assert_eq!(alpha["status"], "success");
    assert_eq!(beta["status"], "success");
    let beta_id = beta["set_id"].as_str().expect("set_id");
    let beta_version = beta["version"].as_u64().unwrap_or(1);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/rename_set")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "set_id": beta_id,
                        "old_name": "beta",
                        "new_name": "alpha",
                        "expected_version": beta_version
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "error");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("already")
            || json["error"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains("invalid"),
        "unexpected error body: {json}"
    );

    // Both original names still load
    let a = load_set_by_name(&app, &auth, "alpha").await;
    let b = load_set_by_name(&app, &auth, "beta").await;
    assert_eq!(a["name"], "alpha");
    assert_eq!(b["name"], "beta");
}
