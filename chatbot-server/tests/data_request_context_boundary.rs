//! MOD008 boundary: bounded data request context adapter.
//!
//! Given the established data-route order (body, then CSRF, then key
//! selection, then session, then guest policy, then key validation), when
//! handlers resolve through `DataRequestContext`, then guest resolution
//! never eagerly validates, required routes reject guests with the exact
//! `Not authenticated` 401, authenticated routes validate through the
//! router's `ChatService`, header/account/generic precedence is preserved,
//! CSRF still precedes key errors, and chat/regenerate still save model
//! errors as 200 turns before invalid-key errors.
//!
//! `preferences` intentionally stays explicit (session-first, key only
//! inside the authenticated branch) and is covered as a distinct policy
//! below rather than forced through the shared adapter.

use std::{
    env,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Request, StatusCode},
};
use chatbot_core::{
    history::HistoryService,
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
    user_store::UserStore,
};
use chatbot_server::{
    build_router, build_router_with_services,
    identity::RequestIdentity,
    request_context::{DataRequestContext, VerifiedDataContext},
    resolve_static_root,
    services::AppServices,
};
use regex::Regex;
use serde_json::{json, Value};
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

fn setup() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn disable_rate_limits() {
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
}

struct OwnedSetup {
    _temp: tempfile::TempDir,
    identity: RequestIdentity,
    chat: ChatService,
    account_root: PathBuf,
}

fn make_owned_setup(secret: &str) -> OwnedSetup {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg = chatbot_core::config::app_config();
    let legacy = temp.path().join("legacy");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    let history = HistoryService::open_with_data_dir(
        temp.path().join("history.redb"),
        &legacy,
        cfg.default_system_prompt.clone(),
    )
    .expect("owned history");
    let sessions = Arc::new(ChatSessionStore::new(
        cfg.session_timeout,
        cfg.default_system_prompt.clone(),
    ));
    let account_root = temp.path().join("accounts");
    std::fs::create_dir_all(&account_root).expect("account root");
    let chat = ChatService::new(
        sessions,
        Arc::new(history),
        account_root.clone(),
        secret.to_owned(),
    );
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    OwnedSetup {
        _temp: temp,
        identity,
        chat,
        account_root,
    }
}

fn enroll_owned(account_root: &std::path::Path, username: &str, key: &str, secret: &str) {
    UserStore::open(account_root)
        .expect("open owned store")
        .ensure_key_verifier_with_secret(username, key.as_bytes(), secret.as_bytes())
        .expect("enroll verifier");
}

fn headers_for(cookie_header: &str, enc_header: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        cookie_header.parse().expect("cookie header"),
    );
    if let Some(key) = enc_header {
        headers.insert("X-Enc-Key", key.parse().expect("enc header"));
    }
    headers
}

fn login_cookie(identity: &RequestIdentity, username: &str) -> String {
    let finalize = identity
        .finalize_login(None, username)
        .expect("finalize login");
    common::extract_cookie(&finalize.set_cookie)
}

fn seed_global_user(username: &str, password: &str) {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash");
    let mut store = UserStore::new().expect("global store");
    match store.create_user(username, &hashed) {
        Ok(_) => {}
        Err(err) => panic!("seed user: {err}"),
    }
}

fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("session="))
        .map(|c| common::extract_cookie(c))
}

fn csrf_from_home(html: &str) -> String {
    let re = Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).expect("csrf regex");
    re.captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("home csrf")
}

async fn login_session(app: &axum::Router, username: &str, password: &str) -> (String, String) {
    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let mut cookie = session_cookie_value(login_get.headers()).expect("login cookie");
    let body = to_bytes(login_get.into_body(), 128 * 1024)
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
    if let Some(raw) = session_cookie_value(login_post.headers()) {
        cookie = raw;
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024).await;

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
        .expect("read home");
    let csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));
    (cookie, csrf)
}

async fn read_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&bytes).expect("json body");
    (status, payload)
}

#[test]
fn guest_context_resolves_without_eager_validation() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given a guest identity with no presented key, when resolving, then the
    // session is a guest and no validation error is raised.
    let setup = make_owned_setup("data-ctx-guest-secret");
    let headers = HeaderMap::new();
    let ctx =
        DataRequestContext::resolve(&setup.identity, &headers, None, "sets::get_sets::session")
            .expect("guest resolve");
    assert!(
        ctx.session().username.is_none(),
        "guest session must carry no username"
    );
    assert!(
        ctx.unverified_encryption_key().is_none(),
        "no presented key must resolve to None"
    );
    // Guest branch stays without key validation; requiring auth rejects.
    assert!(
        ctx.session().username.is_none(),
        "guest check precedes validation"
    );
    let err = ctx
        .require_authenticated(&setup.chat)
        .expect_err("guest must not authenticate");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);

    // Given a guest presenting a wrong-looking key, when resolving, then the
    // key is still carried unverified (no eager validation).
    let mut guest_headers = HeaderMap::new();
    guest_headers.insert("X-Enc-Key", "definitely-not-enrolled".parse().unwrap());
    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &guest_headers,
        None,
        "sets::get_sets::session",
    )
    .expect("guest with key resolves");
    assert!(
        ctx.unverified_encryption_key().is_some(),
        "presented key must be carried for later core validation"
    );
    assert!(
        ctx.session().username.is_none(),
        "guest key must still be ignored, not validated"
    );
    let (session, key) = ctx.into_unverified_parts();
    assert!(session.username.is_none());
    assert!(key.is_some(), "unverified parts must keep the raw key");
}

#[test]
fn authenticated_context_proves_pair_through_chat_service() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given an enrolled key for a logged-in session, when requiring auth,
    // then the caller receives the proven username/session/key triple with no
    // scattered expect. Verified construction is only reachable through the
    // adapter (fields stay private; this test uses the public accessors).
    let setup = make_owned_setup("data-ctx-proven-secret");
    let username = "data_ctx_proven_user";
    let key = "proven-account-key-abc123";
    enroll_owned(&setup.account_root, username, key, "data-ctx-proven-secret");
    let session_pair = login_cookie(&setup.identity, username);
    let cookie_header = format!("{session_pair}; enc_key={key}");
    let headers = headers_for(&cookie_header, None);

    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &headers,
        Some(&cookie_header),
        "sets::get_sets::session",
    )
    .expect("resolve authed");
    let verified: VerifiedDataContext<'_> =
        ctx.require_authenticated(&setup.chat).expect("verified");
    assert_eq!(verified.username(), username);
    assert_eq!(
        std::str::from_utf8(verified.key().as_bytes()).expect("utf8"),
        key
    );
    assert_eq!(
        verified.session().username.as_deref(),
        Some(username),
        "verified session must carry the same user"
    );
}

#[test]
fn account_cookie_preferred_over_generic_via_adapter() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given both cookies presented, when the account key verifies, then the
    // adapter resolves it even though the generic decoy differs.
    let setup = make_owned_setup("data-ctx-acct-secret");
    let username = "data_ctx_acct_user";
    let account_key = "account-correct-111";
    enroll_owned(
        &setup.account_root,
        username,
        account_key,
        "data-ctx-acct-secret",
    );
    let session_pair = login_cookie(&setup.identity, username);
    let cookie_header =
        format!("{session_pair}; enc_key=generic-decoy-222; enc_key-{username}={account_key}");
    let headers = headers_for(&cookie_header, None);
    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &headers,
        Some(&cookie_header),
        "sets::get_sets::session",
    )
    .expect("resolve");
    let verified = ctx
        .require_authenticated(&setup.chat)
        .expect("account key verifies");
    assert_eq!(
        std::str::from_utf8(verified.key().as_bytes()).expect("utf8"),
        account_key,
        "account cookie must win over generic"
    );

    // Given a mismatched account cookie plus a valid generic fallback, when
    // resolving, then validation fails (the account mismatch blocks fallback).
    let bad_header =
        format!("{session_pair}; enc_key={account_key}; enc_key-{username}=mismatched-key");
    let bad_headers = headers_for(&bad_header, None);
    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &bad_headers,
        Some(&bad_header),
        "sets::get_sets::session",
    )
    .expect("resolve");
    let err = ctx
        .require_authenticated(&setup.chat)
        .expect_err("mismatched account must not fall back");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

#[test]
fn header_key_takes_precedence_over_cookies_via_adapter() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given a verified header key plus decoy cookies, when resolving, then
    // the header wins.
    let setup = make_owned_setup("data-ctx-header-secret");
    let username = "data_ctx_header_user";
    let header_key = "header-correct-999";
    enroll_owned(
        &setup.account_root,
        username,
        header_key,
        "data-ctx-header-secret",
    );
    let session_pair = login_cookie(&setup.identity, username);
    let cookie_header =
        format!("{session_pair}; enc_key=cookie-decoy-111; enc_key-{username}=cookie-decoy-222");
    let headers = headers_for(&cookie_header, Some(header_key));
    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &headers,
        Some(&cookie_header),
        "sets::get_sets::session",
    )
    .expect("resolve");
    let verified = ctx
        .require_authenticated(&setup.chat)
        .expect("header verifies");
    assert_eq!(
        std::str::from_utf8(verified.key().as_bytes()).expect("utf8"),
        header_key,
        "X-Enc-Key must take precedence over any cookie"
    );

    // Given a wrong header plus correct cookies, when resolving, then the
    // wrong header still wins (and fails validation).
    let cookie_ok =
        format!("{session_pair}; enc_key={header_key}; enc_key-{username}={header_key}");
    let wrong_headers = headers_for(&cookie_ok, Some("wrong-header-key"));
    // Enroll nothing for the wrong header, so validation must fail.
    let ctx = DataRequestContext::resolve(
        &setup.identity,
        &wrong_headers,
        Some(&cookie_ok),
        "sets::get_sets::session",
    )
    .expect("resolve");
    let err = ctx
        .require_authenticated(&setup.chat)
        .expect_err("wrong header must fail even with correct cookies");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

#[test]
fn scoped_chat_service_rejects_foreign_key() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given two routers with distinct account roots/secrets, when the same
    // username presents A's key to B, then B rejects it through the adapter.
    let setup_a = make_owned_setup("data-ctx-scope-a");
    let setup_b = make_owned_setup("data-ctx-scope-b");
    let username = "data_ctx_scoped_user";
    let key_a = "scoped-key-for-A-123";
    let key_b = "scoped-key-for-B-456";
    enroll_owned(&setup_a.account_root, username, key_a, "data-ctx-scope-a");
    enroll_owned(&setup_b.account_root, username, key_b, "data-ctx-scope-b");

    let cookie_a = login_cookie(&setup_a.identity, username);
    let header_a = format!("{cookie_a}; enc_key={key_a}");
    let headers_a = headers_for(&header_a, None);
    let ctx_a = DataRequestContext::resolve(
        &setup_a.identity,
        &headers_a,
        Some(&header_a),
        "sets::get_sets::session",
    )
    .expect("resolve A");
    assert!(
        ctx_a.require_authenticated(&setup_a.chat).is_ok(),
        "owner A must accept its own key"
    );

    // Cross-check: A's key material presented to B's service must fail. Build
    // B's session for the same username so only the key root differs.
    let cookie_b = login_cookie(&setup_b.identity, username);
    let cross_header = format!("{cookie_b}; enc_key={key_a}");
    let cross_headers = headers_for(&cross_header, None);
    let cross_ctx = DataRequestContext::resolve(
        &setup_b.identity,
        &cross_headers,
        Some(&cross_header),
        "sets::get_sets::session",
    )
    .expect("resolve B");
    let err = cross_ctx
        .require_authenticated(&setup_b.chat)
        .expect_err("peer must reject foreign key");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

#[test]
fn history_image_hist_cookie_fallback_resolves() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Given only the <img>-only hist cookie, when resolving for the image
    // route, then the key resolves; the plain resolver keeps returning None.
    let setup = make_owned_setup("data-ctx-hist-secret");
    let username = "data_ctx_hist_user";
    let key = "hist-fallback-key-789";
    enroll_owned(&setup.account_root, username, key, "data-ctx-hist-secret");
    let session_pair = login_cookie(&setup.identity, username);
    let cookie_header = format!("{session_pair}; hist_enc_key={key}");
    let headers = headers_for(&cookie_header, None);

    let plain = DataRequestContext::resolve(
        &setup.identity,
        &headers,
        Some(&cookie_header),
        "sets::history_image::session",
    )
    .expect("plain resolve");
    assert!(
        plain.unverified_encryption_key().is_none(),
        "plain data routes must ignore hist_enc_key"
    );

    let image = DataRequestContext::resolve_for_history_image(
        &setup.identity,
        &headers,
        Some(&cookie_header),
        "sets::history_image::session",
    )
    .expect("image resolve");
    let verified = image
        .require_authenticated(&setup.chat)
        .expect("hist key verifies");
    assert_eq!(
        std::str::from_utf8(verified.key().as_bytes()).expect("utf8"),
        key
    );
}

#[tokio::test]
async fn required_auth_rejects_guest_with_not_authenticated() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();
    disable_rate_limits();
    let app = build_router(resolve_static_root());

    // Guest bootstrap via the production home page.
    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let guest_cookie = session_cookie_value(home.headers()).expect("guest cookie");

    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &guest_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets as guest"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(payload, json!({"error": "Not authenticated"}));
}

#[tokio::test]
async fn missing_and_wrong_keys_rejected_after_adapter() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    let username = "data_ctx_missing_user";
    let password = "Sup3rS3cret!";
    seed_global_user(username, password);
    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // Missing key stays a 401 unlock prompt, never a saved turn.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets without key"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        payload,
        json!({"error": "Encryption key required. Please unlock."})
    );

    // Wrong key stays a distinct 401.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-Enc-Key", "definitely-not-the-right-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets with wrong key"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(payload, json!({"error": "Invalid encryption key."}));

    // Optional route validates the same way once authenticated.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory without key"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        payload,
        json!({"error": "Encryption key required. Please unlock."})
    );
}

#[tokio::test]
async fn csrf_still_precedes_key_errors() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    let username = "data_ctx_csrf_user";
    let password = "Sup3rS3cret!";
    seed_global_user(username, password);
    let app = build_router(resolve_static_root());
    let (session_cookie, _) = login_session(&app, username, password).await;

    // Bogus CSRF plus a missing key must still report the CSRF failure, not
    // the key failure, proving CSRF stays at the route boundary.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", "bogus-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "x"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory with bad CSRF"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(payload, json!({"error": "Invalid or missing CSRF token"}));
}

#[tokio::test]
async fn model_error_still_saved_as_200_before_invalid_key() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    let username = "data_ctx_model_user";
    let password = "Sup3rS3cret!";
    seed_global_user(username, password);
    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    // Unknown model plus an invalid key must still return the model error as
    // a 200 turn: chat never eagerly validates before provider/model/prepare.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", "definitely-not-the-right-key")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "message": "hello",
                        "model_name": "no-such-model",
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat with bad model and bad key");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        text.contains("requested model not found"),
        "saved model error must win over invalid key, got: {text}"
    );
}

#[tokio::test]
async fn guest_optional_routes_keep_session_behavior_and_preferences_noop() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    let app = build_router(resolve_static_root());

    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let guest_cookie = session_cookie_value(home.headers()).expect("guest cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let guest_csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));

    // Guest memory writes stay session-scoped without any key.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &guest_cookie)
                    .header("X-CSRF-Token", &guest_csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "guest-note"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory as guest"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["storage"], "session");

    // Guest reset stays session-scoped.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/reset_chat")
                    .header(header::COOKIE, &guest_cookie)
                    .header("X-CSRF-Token", &guest_csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"set_name": "default"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /reset_chat as guest"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");

    // Guest preferences stay a no-op success.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_preferences")
                    .header(header::COOKIE, &guest_cookie)
                    .header("X-CSRF-Token", &guest_csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("POST /update_preferences as guest"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");
}

#[tokio::test]
async fn scoped_services_reject_foreign_key_over_http() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    // Two owned routers share no account roots: the same username carries
    // different keys, and each router rejects the peer's key through the
    // adapter's scoped ChatService validation.
    let setup_a = make_owned_setup("data-ctx-http-a");
    let setup_b = make_owned_setup("data-ctx-http-b");
    let username = "data_ctx_http_scoped";
    let key_a = "http-scoped-key-A-001";
    let key_b = "http-scoped-key-B-002";
    enroll_owned(&setup_a.account_root, username, key_a, "data-ctx-http-a");
    enroll_owned(&setup_b.account_root, username, key_b, "data-ctx-http-b");

    for (setup, key, secret) in [
        (&setup_a, key_a, "data-ctx-http-a"),
        (&setup_b, key_b, "data-ctx-http-b"),
    ] {
        let _ = (secret,);
        let cookie = login_cookie(&setup.identity, username);
        let services = AppServices::with_owned_stores(setup.identity.clone())
            .with_chat_service(setup.chat.clone());
        let app = build_router_with_services(resolve_static_root(), services);
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
        let home_body = to_bytes(home.into_body(), 512 * 1024)
            .await
            .expect("read home");
        let csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));

        // Owner key succeeds.
        let cookie_header = format!("{cookie}; enc_key={key}");
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/get_sets")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /get_sets owner");
        assert_eq!(ok.status(), StatusCode::OK);

        // Peer key fails on this router.
        let peer_key = if key == key_a { key_b } else { key_a };
        let peer_header = format!("{cookie}; enc_key={peer_key}");
        let (status, _) = read_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/get_sets")
                        .header(header::COOKIE, &peer_header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("GET /get_sets peer"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "scoped router must reject the foreign key"
        );
        let _ = csrf;
    }
}

#[tokio::test]
async fn logged_in_flag_still_expires_guest() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    let app = build_router(resolve_static_root());

    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let guest_cookie = session_cookie_value(home.headers()).expect("guest cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let guest_csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));

    // Given a guest claiming logged_in, when updating memory, then the
    // handler keeps the exact Session-expired 401 before any key check.
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_memory")
                    .header(header::COOKIE, &guest_cookie)
                    .header("X-CSRF-Token", &guest_csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"memory": "x", "logged_in": true})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("POST /update_memory logged_in guest"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(payload, json!({"error": "Session expired"}));
}

#[tokio::test]
async fn preferences_keeps_explicit_session_first_policy() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();

    // preferences stays explicit: session first, key only inside the
    // authenticated branch. Guests ignore even a wrong key header.
    let app = build_router(resolve_static_root());
    let home = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    let guest_cookie = session_cookie_value(home.headers()).expect("guest cookie");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let guest_csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_preferences")
                    .header(header::COOKIE, &guest_cookie)
                    .header("X-CSRF-Token", &guest_csrf)
                    .header("X-Enc-Key", "definitely-not-the-right-key")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("guest preferences with wrong key"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");

    // Authenticated preferences still validate the key.
    let username = "data_ctx_prefs_user";
    let password = "Sup3rS3cret!";
    seed_global_user(username, password);
    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;
    let (status, payload) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/update_preferences")
                    .header(header::COOKIE, &session_cookie)
                    .header("X-CSRF-Token", &csrf_token)
                    .header("X-Enc-Key", "definitely-not-the-right-key")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"web_search": true})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("authed preferences with wrong key"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(payload, json!({"error": "Invalid encryption key."}));
}
