use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    session,
    user_store::{CreateOutcome, UserStore},
};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

const REMEMBER_MAX_AGE: &str = "2592000";

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

fn set_cookie_values(response_headers: &axum::http::HeaderMap) -> Vec<String> {
    response_headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.to_owned())
        .collect()
}

/// First `name=value` pair of a Set-Cookie header, usable in a Cookie header.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

fn find_cookie_pair<'a>(cookies: &'a [String], name: &str) -> Option<String> {
    cookies.iter().find_map(|cookie| {
        let pair = cookie_pair(cookie);
        if pair.starts_with(&format!("{name}=")) {
            Some(pair)
        } else {
            None
        }
    })
}

async fn get_login_page(
    app: &axum::Router,
    cookie_header: Option<&str>,
) -> (String, Vec<String>) {
    let mut request = Request::builder().uri("/login");
    if let Some(cookie) = cookie_header {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read login body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token in login form");
    (csrf, cookies)
}

async fn post_login(
    app: &axum::Router,
    cookie_header: &str,
    csrf: &str,
    username: &str,
    password: &str,
    remember: bool,
) -> axum::http::Response<Body> {
    let mut payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(csrf)
    );
    if remember {
        payload.push_str("&remember_me=on");
    }
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie_header)
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login")
}

async fn login_with_remember(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> (String, String) {
    let (csrf, cookies) = get_login_page(app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let response = post_login(app, &guest_cookie, &csrf, username, password, true).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies = set_cookie_values(response.headers());
    let session = find_cookie_pair(&cookies, "session").expect("session cookie after login");
    let remember = find_cookie_pair(&cookies, "remember").expect("remember cookie after login");
    (session, remember)
}

async fn post_remember_login(
    app: &axum::Router,
    cookie_header: &str,
    csrf: &str,
    include_csrf: bool,
) -> axum::http::Response<Body> {
    let body = if include_csrf {
        format!("csrf_token={}", urlencoding::encode(csrf))
    } else {
        String::new()
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/remember")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie_header)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("POST /login/remember")
}

/// Simulate the browser state after a restart: GET /login with only the
/// remember cookie mints a fresh guest session; return the CSRF token plus a
/// Cookie header carrying both the guest session and the remember token.
async fn fresh_restore_session(
    app: &axum::Router,
    remember: &str,
) -> (String, String) {
    let (csrf, cookies) = get_login_page(app, Some(remember)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session cookie");
    (csrf, format!("{guest}; {remember}"))
}

#[tokio::test]
async fn login_with_remember_checkbox_issues_durable_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    seed_user("rememberuser", "Sup3rS3cret!");

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let response = post_login(&app, &guest_cookie, &csrf, "rememberuser", "Sup3rS3cret!", true).await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let cookies = set_cookie_values(response.headers());
    let remember = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember="))
        .expect("remember cookie issued with checkbox");
    assert!(remember.contains("HttpOnly"), "remember cookie must be HttpOnly");
    assert!(remember.contains("SameSite=Lax"), "remember cookie must be Lax");
    assert!(remember.contains("Path=/"));
    assert!(
        remember.contains(&format!("Max-Age={REMEMBER_MAX_AGE}")),
        "remember cookie must last 30 days, got {remember}"
    );
    // csrf defaults to on in the test config → Secure flag required.
    assert!(remember.contains("Secure"));

    let token = cookie_pair(remember);
    let token_value = token.strip_prefix("remember=").expect("token value");
    // 48 bytes family||secret, base64url.
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token_value)
            .expect("base64url token")
            .len(),
        48
    );
}

#[tokio::test]
async fn login_without_checkbox_issues_no_remember_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    seed_user("noremember", "Sup3rS3cret!");

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let response = post_login(&app, &guest_cookie, &csrf, "noremember", "Sup3rS3cret!", false).await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let cookies = set_cookie_values(response.headers());
    // Unchecked login may only emit the clearing cookie, never a token.
    for cookie in cookies.iter().filter(|c| c.starts_with("remember=")) {
        assert!(
            cookie.contains("Max-Age=0"),
            "unchecked login must not issue a remember token, got {cookie}"
        );
    }
    assert!(find_cookie_pair(&cookies, "session").is_some());
}

#[tokio::test]
async fn remember_login_restores_session_after_restart() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "restartuser";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    // Server restart: the in-memory session store is gone. Presenting only the
    // remember cookie yields a fresh guest session with a fresh CSRF token.
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;

    let response = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());

    let body = to_bytes(response.into_body(), 32 * 1024)
        .await
        .expect("read remember body");
    let body_str = std::str::from_utf8(&body).expect("utf8");
    assert!(body_str.contains(username), "response names the user: {body_str}");
    let payload: serde_json::Value =
        serde_json::from_str(body_str).expect("remember response is json");
    let returned_csrf = payload["csrf_token"]
        .as_str()
        .expect("csrf_token in response")
        .to_owned();
    assert!(!returned_csrf.is_empty());

    let new_session = find_cookie_pair(&cookies, "session").expect("session re-issued");
    let new_remember = find_cookie_pair(&cookies, "remember").expect("remember rotated");
    assert_ne!(
        new_remember, remember,
        "remember secret must rotate on every use"
    );

    let context = session::session_context(Some(&new_session)).expect("session after restore");
    assert_eq!(
        context.username.as_deref(),
        Some(username),
        "remember login must restore the authenticated session"
    );

    // The returned CSRF token must belong to the restored session: use it
    // directly (no fresh /login bootstrap) to restore again.
    let live_cookies = format!("{new_session}; {new_remember}");
    let again = post_remember_login(&app, &live_cookies, &returned_csrf, true).await;
    assert_eq!(
        again.status(),
        StatusCode::OK,
        "returned csrf_token must be valid for the restored session"
    );
}

#[tokio::test]
async fn remember_login_requires_csrf() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "csrfuser";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    let (_csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let response = post_remember_login(&app, &cookie_header, "", false).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remember_previous_generation_rejected_without_revoking() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "graceuser";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, first_token) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    // First restore rotates the token.
    let (csrf, cookie_header) = fresh_restore_session(&app, &first_token).await;
    let response = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let second_token = find_cookie_pair(&cookies, "remember").expect("rotated token");

    // Presenting the previous generation (concurrent tab) is rejected...
    let (_csrf, cookie_header) = fresh_restore_session(&app, &first_token).await;
    let grace = post_remember_login(&app, &cookie_header, &_csrf, true).await;
    assert_eq!(grace.status(), StatusCode::UNAUTHORIZED);

    // ...but the family survives: the current token still restores.
    let (csrf, cookie_header) = fresh_restore_session(&app, &second_token).await;
    let still_valid = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(still_valid.status(), StatusCode::OK);
}

#[tokio::test]
async fn remember_two_generations_old_replay_revokes_family() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "replayuser";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, first_token) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    // Rotate twice so first_token is two generations old.
    let (csrf, cookie_header) = fresh_restore_session(&app, &first_token).await;
    let response = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let second_token = find_cookie_pair(&cookies, "remember").expect("rotated token");

    let (csrf, cookie_header) = fresh_restore_session(&app, &second_token).await;
    let response = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let third_token = find_cookie_pair(&cookies, "remember").expect("rotated token");

    // Two generations stale: treated as theft, the family is revoked.
    let (csrf, cookie_header) = fresh_restore_session(&app, &first_token).await;
    let replay = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let (csrf, cookie_header) = fresh_restore_session(&app, &third_token).await;
    let after_revoke = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(
        after_revoke.status(),
        StatusCode::UNAUTHORIZED,
        "family revocation must invalidate the rotated token too"
    );
}

#[tokio::test]
async fn home_auto_restores_remembered_session_after_restart() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "homerestore";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    // Server restart: in-memory sessions are gone. Refreshing the app entry
    // point with only the remember cookie must land logged in.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &remember)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with remember cookie");
    assert_eq!(response.status(), StatusCode::OK);

    let cookies = set_cookie_values(response.headers());
    let new_session = find_cookie_pair(&cookies, "session").expect("session cookie on restored home");
    let new_remember = find_cookie_pair(&cookies, "remember").expect("rotated remember cookie");
    assert_ne!(new_remember, remember, "token must rotate on auto-restore");

    let body = to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("read home body");
    let body_str = std::str::from_utf8(&body).expect("utf8");
    assert!(
        body_str.contains("\"loggedIn\": true"),
        "home must render logged in after auto-restore"
    );
    assert!(
        body_str.contains(username),
        "home must name the restored user"
    );

    let context = session::session_context(Some(&new_session)).expect("session after restore");
    assert_eq!(
        context.username.as_deref(),
        Some(username),
        "auto-restore must authenticate the remembered user"
    );

    // A follow-up visit must not rotate again (already authenticated).
    let second_visit = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &new_session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("second GET /");
    let cookies = set_cookie_values(second_visit.headers());
    assert!(
        find_cookie_pair(&cookies, "remember").is_none(),
        "authenticated home visits must not touch the remember token"
    );
}

async fn post_keyauth(
    app: &axum::Router,
    cookie_header: &str,
    csrf: &str,
    username: &str,
    enc_key: Option<&str>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/login/keyauth")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie_header);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let body = format!(
        "csrf_token={}&username={}",
        urlencoding::encode(csrf),
        urlencoding::encode(username)
    );
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .expect("POST /login/keyauth")
}

#[tokio::test]
async fn keyauth_restores_session_without_password() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyauthuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    {
        let store = UserStore::new().expect("user store");
        let key = store
            .derive_encryption_key(username, password)
            .expect("derive key");
        store
            .ensure_key_verifier(username, &key)
            .expect("register verifier");
    }

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let key_b64 = {
        let store = UserStore::new().expect("user store");
        String::from_utf8(
            store
                .derive_encryption_key(username, password)
                .expect("derive key"),
        )
        .expect("key utf8")
    };

    let response =
        post_keyauth(&app, &guest_cookie, &csrf, username, Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());

    let body = to_bytes(response.into_body(), 32 * 1024)
        .await
        .expect("read keyauth body");
    let body_str = std::str::from_utf8(&body).expect("utf8");
    assert!(body_str.contains(username), "response names the user");

    let session = find_cookie_pair(&cookies, "session").expect("session cookie from keyauth");
    let context = session::session_context(Some(&session)).expect("session after keyauth");
    assert_eq!(
        context.username.as_deref(),
        Some(username),
        "keyauth must restore the authenticated session without a password"
    );
}

#[tokio::test]
async fn keyauth_rejects_bad_credentials() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyauthbad";
    let password = "Sup3rS3cret!";

    {
        let store = UserStore::new().expect("user store");
        let key = store
            .derive_encryption_key(username, password)
            .expect("derive key");
        store
            .ensure_key_verifier(username, &key)
            .expect("register verifier");
    }

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    // Wrong key.
    let response = post_keyauth(&app, &guest_cookie, &csrf, username, Some("wrong-key")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Missing key header.
    let response = post_keyauth(&app, &guest_cookie, &csrf, username, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Unknown username.
    let key_b64 = {
        let store = UserStore::new().expect("user store");
        String::from_utf8(
            store
                .derive_encryption_key(username, password)
                .expect("derive key"),
        )
        .expect("key utf8")
    };
    let response = post_keyauth(&app, &guest_cookie, &csrf, "ghost_user", Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // User without a registered verifier cannot key-login.
    seed_user("noverifier", password);
    let response = post_keyauth(&app, &guest_cookie, &csrf, "noverifier", Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn keyauth_requires_csrf() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyauthcsrf";
    seed_user(username, "Sup3rS3cret!");

    {
        let store = UserStore::new().expect("user store");
        let key = store
            .derive_encryption_key(username, "Sup3rS3cret!")
            .expect("derive key");
        store
            .ensure_key_verifier(username, &key)
            .expect("register verifier");
    }

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let key_b64 = {
        let store = UserStore::new().expect("user store");
        String::from_utf8(
            store
                .derive_encryption_key(username, "Sup3rS3cret!")
                .expect("derive key"),
        )
        .expect("key utf8")
    };

    // Empty CSRF value.
    let response = post_keyauth(&app, &guest_cookie, "", username, Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Valid CSRF still works afterwards (no session rotation happened).
    let response = post_keyauth(&app, &guest_cookie, &csrf, username, Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let session = find_cookie_pair(&cookies, "session").expect("session cookie from keyauth");
    let context = session::session_context(Some(&session)).expect("session after keyauth");
    assert_eq!(context.username.as_deref(), Some(username));
}

#[tokio::test]
async fn login_without_remember_revokes_existing_token() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "optoutuser";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    // A later login WITHOUT the checkbox must opt the device out: the old
    // token is revoked and the cookie cleared.
    let (csrf, cookies) = get_login_page(&app, Some(&remember)).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");
    let response = post_login(
        &app,
        &format!("{guest_cookie}; {remember}"),
        &csrf,
        username,
        "Sup3rS3cret!",
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies = set_cookie_values(response.headers());
    let clear = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember="))
        .expect("unchecked login must clear the remember cookie");
    assert!(clear.contains("Max-Age=0"));

    // The revoked token no longer auto-restores a session at the app entry.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &remember)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with revoked remember cookie");
    let body = to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("read home body");
    let body_str = std::str::from_utf8(&body).expect("utf8");
    assert!(
        body_str.contains("\"loggedIn\": false"),
        "revoked token must not restore the session"
    );

    // And the manual restore endpoint rejects it too.
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let restore = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(restore.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn keyauth_issues_remember_token_for_last_used_account() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyauthtoken";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    {
        let store = UserStore::new().expect("user store");
        let key = store
            .derive_encryption_key(username, password)
            .expect("derive key");
        store
            .ensure_key_verifier(username, &key)
            .expect("register verifier");
    }

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");

    let key_b64 = {
        let store = UserStore::new().expect("user store");
        String::from_utf8(
            store
                .derive_encryption_key(username, password)
                .expect("derive key"),
        )
        .expect("key utf8")
    };

    let response = post_keyauth(&app, &guest_cookie, &csrf, username, Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let remember = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember=") && cookie.contains(&format!("Max-Age={REMEMBER_MAX_AGE}")))
        .expect("keyauth must issue a remember token")
        .clone();

    // After a server restart, the app entry point auto-restores the
    // last-used account with that token alone.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &remember)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / after keyauth");
    let body = to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("read home body");
    let body_str = std::str::from_utf8(&body).expect("utf8");
    assert!(
        body_str.contains("\"loggedIn\": true"),
        "keyauth login must leave the device auto-restorable"
    );
}

#[tokio::test]
async fn logout_revokes_remember_token() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "logoutremember";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (session_cookie, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;
    let both_cookies = format!("{session_cookie}; {remember}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(header::COOKIE, &both_cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /logout");
    assert_eq!(response.status(), StatusCode::FOUND);

    let cookies = set_cookie_values(response.headers());
    let clear = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember="))
        .expect("logout must clear the remember cookie");
    assert!(clear.contains("Max-Age=0"), "clearing cookie expires it");

    // The revoked token no longer restores a session.
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let restore = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(restore.status(), StatusCode::UNAUTHORIZED);
}
