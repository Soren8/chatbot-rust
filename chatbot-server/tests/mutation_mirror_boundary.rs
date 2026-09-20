//! MOD006 durable-mutation plus session-mirror ownership.
//!
//! Given an authenticated or guest session, when memory / system-prompt /
//! delete / reset routes run, then durable writes happen first with CAS and
//! the session mirror follows with no rollback: authed successes report
//! disk versions, guest memory stays session-only, stale versions conflict
//! with the current version, invalid names fail before key checks while bad
//! keys fail before bad set IDs, and a mirror failure after durable success
//! still persists while counting exactly one 500.

use std::{
    env, fs,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::enc_key::EncryptionKey;
use chatbot_server::{build_router, resolve_static_root, test_instrumentation::take_error_count};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
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

async fn login_user_with_storage_key(
    app: &axum::Router,
    username: &str,
    password: &str,
    storage_key: Option<&str>,
) -> AuthCtx {
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
    assert_eq!(login_page.status(), StatusCode::OK);
    let mut cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("login cookie");
    let body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("login body");
    let csrf_login =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("login utf8"))
            .expect("login csrf");
    let mut form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf_login),
    );
    if let Some(key) = storage_key {
        form.push_str(&format!("&storage_key={}", urlencoding::encode(key)));
    }
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
    assert!(
        login_post.status() == StatusCode::FOUND
            || login_post.status() == StatusCode::SEE_OTHER,
        "login redirect, got {}",
        login_post.status()
    );
    if let Some(raw) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(raw);
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024)
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
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).expect("home utf8"))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("home csrf");
    AuthCtx {
        cookie,
        csrf,
        enc_key: storage_key.map(str::to_owned).unwrap_or_else(|| {
            common::derive_encryption_key_header(username, password)
        }),
        username: username.to_owned(),
    }
}

async fn login_user(app: &axum::Router, username: &str, password: &str) -> AuthCtx {
    login_user_with_storage_key(app, username, password, None).await
}

fn seed_user(workspace: &common::TestWorkspace, username: &str, password: &str) {
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    fs::write(
        workspace.path().join("users.json"),
        serde_json::to_string_pretty(&json!({
            username: { "password": hashed, "tier": "free" }
        }))
        .expect("users json"),
    )
    .expect("write users.json");
}

async fn post_json(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    enc_key: Option<&str>,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).expect("payload")))
                .unwrap(),
        )
        .await
        .expect("POST response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("response body");
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        json!({"_raw": String::from_utf8_lossy(&bytes)})
    });
    (status, payload)
}

#[tokio::test]
async fn memory_update_commits_durable_and_reports_version() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_mem", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_mem", "Sup3rS3cret!").await;

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({"memory": "remember the lake house", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");
    assert_eq!(body["storage"], "disk");
    let set_id = body["set_id"].as_str().expect("set_id").to_owned();
    assert!(body["version"].as_u64().is_some());

    let (status, loaded) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/load_set",
        json!({"set_id": set_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    assert_eq!(loaded["memory"], "remember the lake house");
}

#[tokio::test]
async fn system_prompt_update_commits_durable() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_prompt", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_prompt", "Sup3rS3cret!").await;

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_system_prompt",
        json!({"system_prompt": "You are a lake guide", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["storage"], "disk");
    let set_id = body["set_id"].as_str().expect("set_id").to_owned();

    let (status, loaded) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/load_set",
        json!({"set_id": set_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    assert_eq!(loaded["system_prompt"], "You are a lake guide");
}

#[tokio::test]
async fn delete_pair_commits_durable() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_del", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_del", "Sup3rS3cret!").await;

    let key = EncryptionKey::from_header_value(&auth.enc_key).expect("valid key");
    let history = chatbot_core::history::HistoryService::global()
        .expect("global history");
    let default = history
        .ensure_default_set(&auth.username, &key)
        .expect("ensure default");
    let version = history
        .append_pair(
            &auth.username,
            default.set_id,
            default.version,
            "hello lake",
            "hi there",
            &key,
        )
        .expect("seed pair")
        .get();

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/delete_message",
        json!({
            "pair_index": 0,
            "user_message": "hello lake",
            "set_id": default.set_id.to_string(),
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");

    let (status, loaded) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/load_set",
        json!({"set_id": default.set_id.to_string()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    assert_eq!(loaded["history"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn reset_history_clears_durable() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_reset", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_reset", "Sup3rS3cret!").await;

    let key = EncryptionKey::from_header_value(&auth.enc_key).expect("valid key");
    let history = chatbot_core::history::HistoryService::global()
        .expect("global history");
    let default = history
        .ensure_default_set(&auth.username, &key)
        .expect("ensure default");
    history
        .append_pair(
            &auth.username,
            default.set_id,
            default.version,
            "u1",
            "a1",
            &key,
        )
        .expect("seed pair");

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/reset_chat",
        json!({"set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");

    let (status, loaded) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/load_set",
        json!({"set_id": default.set_id.to_string()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    assert_eq!(loaded["history"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn guest_memory_update_uses_session_storage() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());

    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("session cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).expect("utf8"))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf");

    let (status, body) = post_json(
        &app,
        &cookie,
        &csrf,
        None,
        "/update_memory",
        json!({"memory": "guest note", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "success");
    assert_eq!(body["storage"], "session");
    assert!(body.get("version").is_none());
    assert!(body.get("set_id").is_none());
}

#[tokio::test]
async fn guest_load_set_rejects_with_not_authenticated() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    let app = build_router(resolve_static_root());

    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let cookie = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("session cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).expect("utf8"))
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf");

    let (status, body) = post_json(
        &app,
        &cookie,
        &csrf,
        None,
        "/load_set",
        json!({"set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "Not authenticated");
}

#[tokio::test]
async fn stale_expected_version_conflicts_with_current_version() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_cas", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_cas", "Sup3rS3cret!").await;

    let (status, first) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({"memory": "v1", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let set_id = first["set_id"].as_str().expect("set_id").to_owned();
    let v1 = first["version"].as_u64().expect("version");

    let (status, second) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({
            "memory": "v2",
            "set_id": set_id,
            "expected_version": v1,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let v2 = second["version"].as_u64().expect("v2");
    assert_ne!(v1, v2);

    let (status, conflict) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({
            "memory": "stale",
            "set_id": set_id,
            "expected_version": v1,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["error"], "version_conflict");
    assert_eq!(conflict["set_id"], set_id);
    assert_eq!(conflict["current_version"], v2);
}

#[tokio::test]
async fn invalid_set_name_returns_400_before_key_check() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_nameprec", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_nameprec", "Sup3rS3cret!").await;

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        None,
        "/update_memory",
        json!({"memory": "x", "set_name": "bad/name"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid set name");
}

#[tokio::test]
async fn invalid_key_precedes_invalid_set_id() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(&workspace, "mod006_mut_keyprec", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "mod006_mut_keyprec", "Sup3rS3cret!").await;

    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        None,
        "/update_memory",
        json!({"memory": "x", "set_id": "not-a-uuid"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "Encryption key required. Please unlock.");
}

#[tokio::test]
async fn mirror_failure_after_durable_success_persists_and_counts_once() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    // Distinct account whose verifier is first enrolled for the short,
    // Fernet-invalid key via the real client-derivation login path
    // (`storage_key`); re-enrolling the password-bootstrap account would hit
    // the verifier-mismatch guard instead.
    seed_user(&workspace, "mod006_mut_mirror_short", "Sup3rS3cret!");
    let app = build_router(resolve_static_root());
    let auth =
        login_user_with_storage_key(&app, "mod006_mut_mirror_short", "Sup3rS3cret!", Some("short"))
            .await;

    // First write lands the durable set under the short key; the session has
    // no active set yet so the mirror is left alone.
    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({"memory": "setup memory", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Loading records the active set in the session cipher; the seal fails
    // for the Fernet-invalid key, which is the initialized-mirror
    // precondition for the write below.
    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/load_set",
        json!({"set_name": "default"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "load mirror seal with a non-Fernet key must 500, got {body}"
    );

    // Now the durable write succeeds and the mirror seal fails after it.
    let _ = take_error_count();
    let (status, body) = post_json(
        &app,
        &auth.cookie,
        &auth.csrf,
        Some(auth.enc_key.as_str()),
        "/update_memory",
        json!({"memory": "durable despite mirror", "set_name": "default"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "mirror seal with a non-Fernet key must 500, got {body}"
    );
    assert_eq!(
        body["error"],
        "internal error while accessing chat history"
    );
    assert_eq!(
        take_error_count(),
        1,
        "mirror 500 must record the counter exactly once"
    );

    let short_key = EncryptionKey::from_header_value(&auth.enc_key).expect("short key");
    let history = chatbot_core::history::HistoryService::global()
        .expect("global history");
    let snap = history
        .find_by_display_name(&auth.username, "default", &short_key)
        .expect("find default")
        .expect("default exists");
    let loaded = history
        .load(&auth.username, snap.set_id, &short_key)
        .expect("durable must persist despite mirror failure");
    assert_eq!(loaded.memory, "durable despite mirror");
}
