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

async fn post_remember_login_as(
    app: &axum::Router,
    cookie_header: &str,
    csrf: &str,
    username: &str,
    enc_key: Option<&str>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/login/remember")
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
        .expect("POST /login/remember")
}

fn derive_key_b64(username: &str, password: &str) -> String {
    let store = UserStore::new().expect("user store");
    String::from_utf8(
        store
            .derive_encryption_key(username, password)
            .expect("derive key"),
    )
    .expect("key utf8")
}

fn register_verifier(username: &str, password: &str) {
    let store = UserStore::new().expect("user store");
    let key = store
        .derive_encryption_key(username, password)
        .expect("derive key");
    store
        .ensure_key_verifier(username, &key)
        .expect("register verifier");
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
    let account = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember-rememberuser="))
        .expect("per-account remember cookie issued with checkbox");
    assert!(account.contains("HttpOnly"));
    assert_eq!(
        cookie_pair(account).strip_prefix("remember-rememberuser="),
        cookie_pair(remember).strip_prefix("remember=")
    );

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
async fn remember_login_with_username_must_match_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "matchuser";
    seed_user(username, "Sup3rS3cret!");
    seed_user("otheruser", "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;

    let mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/remember")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie_header)
                .body(Body::from(format!(
                    "csrf_token={}&username={}",
                    urlencoding::encode(&csrf),
                    urlencoding::encode("otheruser")
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login/remember mismatch");
    assert_eq!(mismatch.status(), StatusCode::UNAUTHORIZED);

    let match_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/remember")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie_header)
                .body(Body::from(format!(
                    "csrf_token={}&username={}",
                    urlencoding::encode(&csrf),
                    urlencoding::encode(username)
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login/remember match");
    assert_eq!(match_resp.status(), StatusCode::OK);
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

#[tokio::test]
async fn home_auto_restore_sets_per_account_remember_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "homeacct";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

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
    let new_remember = find_cookie_pair(&cookies, "remember").expect("rotated last-used cookie");
    let account_name = format!("remember-{username}");
    let new_account =
        find_cookie_pair(&cookies, &account_name).expect("rotated per-account remember cookie");
    assert_ne!(new_remember, remember, "token must rotate on auto-restore");
    assert_eq!(
        new_account.strip_prefix(&format!("{account_name}=")),
        new_remember.strip_prefix("remember="),
        "GET / must write the same rotated secret to last-used and per-account cookies"
    );
}

#[tokio::test]
async fn home_auto_restore_twice_does_not_self_revoke_per_account_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "twicerestore";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, first_remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;

    let first_home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &first_remember)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("first GET /");
    assert_eq!(first_home.status(), StatusCode::OK);
    let first_cookies = set_cookie_values(first_home.headers());
    let second_remember =
        find_cookie_pair(&first_cookies, "remember").expect("last-used after first restore");
    let account_name = format!("remember-{username}");
    let second_account = find_cookie_pair(&first_cookies, &account_name)
        .expect("per-account after first restore");

    let second_home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &second_remember)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("second GET /");
    assert_eq!(second_home.status(), StatusCode::OK);
    let second_cookies = set_cookie_values(second_home.headers());
    let third_account = find_cookie_pair(&second_cookies, &account_name)
        .expect("per-account after second restore");

    let (csrf, cookie_header) = fresh_restore_session(&app, &third_account).await;
    let restore =
        post_remember_login_as(&app, &cookie_header, &csrf, username, None).await;
    assert_eq!(
        restore.status(),
        StatusCode::OK,
        "latest per-account cookie must still restore after two GET / rotations"
    );

    let (csrf, cookie_header) = fresh_restore_session(&app, &first_remember).await;
    let stale = post_remember_login_as(&app, &cookie_header, &csrf, username, None).await;
    assert_eq!(
        stale.status(),
        StatusCode::UNAUTHORIZED,
        "two-generation-old token must still revoke the family"
    );

    let (csrf, cookie_header) = fresh_restore_session(&app, &second_account).await;
    let after_revoke =
        post_remember_login_as(&app, &cookie_header, &csrf, username, None).await;
    assert_eq!(
        after_revoke.status(),
        StatusCode::UNAUTHORIZED,
        "theft detection must still invalidate the family after a two-generation replay"
    );
}

#[tokio::test]
async fn keyauth_route_is_gone() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/keyauth")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=anyone"))
                .unwrap(),
        )
        .await
        .expect("POST /login/keyauth");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the Fernet key must not mint a session"
    );
}

#[tokio::test]
async fn encryption_key_alone_does_not_mint_session() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "keyonlyuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest_cookie = find_cookie_pair(&cookies, "session").expect("guest session cookie");
    let key_b64 = derive_key_b64(username, password);

    let response =
        post_remember_login_as(&app, &guest_cookie, &csrf, username, Some(&key_b64)).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "X-Enc-Key without a remember cookie must not log in"
    );
}

#[tokio::test]
async fn remember_login_sets_enc_key_cookie_when_key_matches() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "rememberenc";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, password).await;
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let key_b64 = derive_key_b64(username, password);

    let response =
        post_remember_login_as(&app, &cookie_header, &csrf, username, Some(&key_b64)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let enc = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .expect("matching X-Enc-Key on remember login must set enc_key cookie");
    assert!(enc.contains("HttpOnly"), "enc_key must be HttpOnly: {enc}");
}

#[tokio::test]
async fn remember_login_without_key_does_not_set_enc_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "remembernokey";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;
    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;

    let response = post_remember_login_as(&app, &cookie_header, &csrf, username, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    assert!(
        cookies.iter().all(|cookie| !cookie.starts_with("enc_key=")),
        "remember restore without a key must not mint enc_key"
    );
    let session = find_cookie_pair(&cookies, "session").expect("session from remember");
    let context = session::session_context(Some(&session)).expect("session after remember");
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
async fn logout_keeps_remember_token() {
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
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("logout redirect");
    assert_eq!(location, "/login");

    let cookies = set_cookie_values(response.headers());
    assert!(
        cookies
            .iter()
            .all(|cookie| !cookie.starts_with("remember=") || !cookie.contains("Max-Age=0")),
        "logout must not expire the remember cookie"
    );

    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let restore = post_remember_login(&app, &cookie_header, &csrf, true).await;
    assert_eq!(
        restore.status(),
        StatusCode::OK,
        "logout must leave the remember token usable until forget"
    );
}

#[tokio::test]
async fn per_account_cookie_survives_switching_accounts() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    seed_user("aliceacct", "Sup3rS3cret!");
    seed_user("bobacct", "Sup3rS3cret!");

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let alice_login = post_login(&app, &guest, &csrf, "aliceacct", "Sup3rS3cret!", true).await;
    assert_eq!(alice_login.status(), StatusCode::FOUND);
    let alice_cookies = set_cookie_values(alice_login.headers());
    let alice_account = find_cookie_pair(&alice_cookies, "remember-aliceacct")
        .expect("alice per-account remember cookie");

    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let bob_login = post_login(&app, &guest, &csrf, "bobacct", "Sup3rS3cret!", true).await;
    assert_eq!(bob_login.status(), StatusCode::FOUND);
    let bob_cookies = set_cookie_values(bob_login.headers());
    let bob_remember = find_cookie_pair(&bob_cookies, "remember").expect("bob last-used cookie");

    let (csrf, cookie_header) = fresh_restore_session(&app, &alice_account).await;
    let restore =
        post_remember_login_as(&app, &cookie_header, &csrf, "aliceacct", None).await;
    assert_eq!(
        restore.status(),
        StatusCode::OK,
        "alice's per-account cookie must still work after bob logged in"
    );
    let restored = set_cookie_values(restore.headers());
    let session = find_cookie_pair(&restored, "session").expect("alice session");
    let context = session::session_context(Some(&session)).expect("session");
    assert_eq!(context.username.as_deref(), Some("aliceacct"));

    let (csrf, cookie_header) = fresh_restore_session(&app, &bob_remember).await;
    let bob_restore =
        post_remember_login_as(&app, &cookie_header, &csrf, "bobacct", None).await;
    assert_eq!(bob_restore.status(), StatusCode::OK);
}

#[tokio::test]
async fn remembered_login_as_second_account_keeps_first_family() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    seed_user("aliceacct", "Sup3rS3cret!");
    seed_user("bobacct", "Sup3rS3cret!");

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let alice_login = post_login(&app, &guest, &csrf, "aliceacct", "Sup3rS3cret!", true).await;
    assert_eq!(alice_login.status(), StatusCode::FOUND);
    let alice_cookies = set_cookie_values(alice_login.headers());
    let alice_last_used =
        find_cookie_pair(&alice_cookies, "remember").expect("alice last-used cookie");
    let alice_account = find_cookie_pair(&alice_cookies, "remember-aliceacct")
        .expect("alice per-account remember cookie");

    let (csrf, cookies) = get_login_page(&app, Some(&alice_last_used)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let bob_login = post_login(
        &app,
        &format!("{guest}; {alice_last_used}; {alice_account}"),
        &csrf,
        "bobacct",
        "Sup3rS3cret!",
        true,
    )
    .await;
    assert_eq!(bob_login.status(), StatusCode::FOUND);
    let bob_cookies = set_cookie_values(bob_login.headers());
    let bob_remember = find_cookie_pair(&bob_cookies, "remember").expect("bob last-used cookie");
    assert!(
        find_cookie_pair(&bob_cookies, "remember-bobacct").is_some(),
        "bob per-account remember cookie"
    );

    let (csrf, cookie_header) = fresh_restore_session(&app, &alice_account).await;
    let restore =
        post_remember_login_as(&app, &cookie_header, &csrf, "aliceacct", None).await;
    assert_eq!(
        restore.status(),
        StatusCode::OK,
        "alice's per-account cookie must still work after bob logged in on the same browser"
    );
    let restored = set_cookie_values(restore.headers());
    let session = find_cookie_pair(&restored, "session").expect("alice session");
    let context = session::session_context(Some(&session)).expect("session");
    assert_eq!(context.username.as_deref(), Some("aliceacct"));

    let (csrf, cookie_header) = fresh_restore_session(&app, &bob_remember).await;
    let bob_restore =
        post_remember_login_as(&app, &cookie_header, &csrf, "bobacct", None).await;
    assert_eq!(bob_restore.status(), StatusCode::OK);
}

fn remember_family_count(workspace: &common::TestWorkspace) -> usize {
    let dir = workspace.path().join("remember_tokens");
    fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().map(|ext| ext == "json").unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn remember_login_refreshes_existing_family() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();
    let username = "refreshfamily";
    seed_user(username, "Sup3rS3cret!");

    let app = build_app();
    let (_session, remember) = login_with_remember(&app, username, "Sup3rS3cret!").await;
    assert_eq!(remember_family_count(&workspace), 1);

    let (csrf, cookies) = get_login_page(&app, Some(&remember)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let response = post_login(
        &app,
        &format!("{guest}; {remember}"),
        &csrf,
        username,
        "Sup3rS3cret!",
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        remember_family_count(&workspace),
        1,
        "second remembered login must rotate the same family"
    );
}

#[tokio::test]
async fn forget_revokes_only_matching_account() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    seed_user("aliceforget", "Sup3rS3cret!");
    seed_user("bobforget", "Sup3rS3cret!");

    let app = build_app();
    let (_session, alice_remember) = login_with_remember(&app, "aliceforget", "Sup3rS3cret!").await;

    let (csrf, cookies) = get_login_page(&app, Some(&alice_remember)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let cookie_header = format!("{guest}; {alice_remember}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/forget")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie_header)
                .body(Body::from(format!(
                    "csrf_token={}&username={}",
                    urlencoding::encode(&csrf),
                    urlencoding::encode("bobforget")
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login/forget bob");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    assert!(
        find_cookie_pair(&cookies, "remember").is_none(),
        "forgetting another account must not clear this device token"
    );

    let (csrf, restore_cookies) = fresh_restore_session(&app, &alice_remember).await;
    let restore = post_remember_login(&app, &restore_cookies, &csrf, true).await;
    assert_eq!(
        restore.status(),
        StatusCode::OK,
        "alice token must survive forgetting bob"
    );

    let alice_remember = find_cookie_pair(
        &set_cookie_values(restore.headers()),
        "remember",
    )
    .unwrap_or(alice_remember);

    let (csrf, cookies) = get_login_page(&app, Some(&alice_remember)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/forget")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &format!("{guest}; {alice_remember}"))
                .body(Body::from(format!(
                    "csrf_token={}&username={}",
                    urlencoding::encode(&csrf),
                    urlencoding::encode("aliceforget")
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login/forget alice");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let clear = cookies
        .iter()
        .find(|cookie| cookie.starts_with("remember="))
        .expect("forgetting the cookie's account must clear it");
    assert!(clear.contains("Max-Age=0"));

    let (csrf, restore_cookies) = fresh_restore_session(&app, &alice_remember).await;
    let restore = post_remember_login(&app, &restore_cookies, &csrf, true).await;
    assert_eq!(restore.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_with_remember_issues_per_account_enc_key_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "encacctuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let response = post_login(&app, &guest, &csrf, username, password, true).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies = set_cookie_values(response.headers());
    let last = find_cookie_pair(&cookies, "enc_key").expect("enc_key cookie");
    let account_name = format!("enc_key-{username}");
    let account = find_cookie_pair(&cookies, &account_name).expect("per-account enc_key cookie");
    let last_set = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .expect("enc_key Set-Cookie");
    let account_set = cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("{account_name}=")))
        .expect("account enc_key Set-Cookie");
    assert!(last_set.contains("HttpOnly"), "enc_key must be HttpOnly");
    assert!(
        last_set.contains("SameSite=Strict"),
        "enc_key must be Strict: {last_set}"
    );
    assert!(account_set.contains("HttpOnly"));
    assert!(account_set.contains("SameSite=Strict"));
    assert!(
        account_set.contains(&format!("Max-Age={REMEMBER_MAX_AGE}")),
        "per-account enc_key must last 30 days, got {account_set}"
    );
    assert_eq!(
        account.strip_prefix(&format!("{account_name}=")),
        last.strip_prefix("enc_key=")
    );
}

#[tokio::test]
async fn remember_login_promotes_account_enc_key_without_header() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "encpromote";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let login = post_login(&app, &guest, &csrf, username, password, true).await;
    assert_eq!(login.status(), StatusCode::FOUND);
    let login_cookies = set_cookie_values(login.headers());
    let remember = find_cookie_pair(&login_cookies, "remember").expect("remember");
    let account_enc = find_cookie_pair(&login_cookies, &format!("enc_key-{username}"))
        .expect("account enc_key");

    let (csrf, cookie_header) = fresh_restore_session(&app, &remember).await;
    let response = post_remember_login_as(
        &app,
        &format!("{cookie_header}; {account_enc}"),
        &csrf,
        username,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let enc = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .expect("remember restore must copy enc_key-{user} onto enc_key without X-Enc-Key");
    assert!(enc.contains("HttpOnly"), "promoted enc_key must be HttpOnly: {enc}");
}

#[tokio::test]
async fn logout_keeps_account_enc_key_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "enclogout";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let login = post_login(&app, &guest, &csrf, username, password, true).await;
    let login_cookies = set_cookie_values(login.headers());
    let session = find_cookie_pair(&login_cookies, "session").expect("session");
    let remember = find_cookie_pair(&login_cookies, "remember").expect("remember");
    let account_enc = find_cookie_pair(&login_cookies, &format!("enc_key-{username}"))
        .expect("account enc_key");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(
                    header::COOKIE,
                    format!("{session}; {remember}; {account_enc}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /logout");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies = set_cookie_values(response.headers());
    let clear = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .expect("logout must clear last-used enc_key");
    assert!(clear.contains("Max-Age=0"));
    assert!(
        cookies
            .iter()
            .all(|cookie| !cookie.starts_with(&format!("enc_key-{username}="))),
        "logout must not clear enc_key-{{user}}"
    );
}

#[tokio::test]
async fn forget_clears_account_enc_key_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "encforget";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let login = post_login(&app, &guest, &csrf, username, password, true).await;
    let login_cookies = set_cookie_values(login.headers());
    let remember = find_cookie_pair(&login_cookies, "remember").expect("remember");
    let account_enc = find_cookie_pair(&login_cookies, &format!("enc_key-{username}"))
        .expect("account enc_key");

    let (csrf, cookies) = get_login_page(&app, Some(&remember)).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/forget")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{guest}; {remember}; {account_enc}"),
                )
                .body(Body::from(format!(
                    "csrf_token={}&username={}",
                    urlencoding::encode(&csrf),
                    urlencoding::encode(username)
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login/forget");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    let clear = cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("enc_key-{username}=")))
        .expect("forget must clear enc_key-{{user}}");
    assert!(clear.contains("Max-Age=0"));
}

#[tokio::test]
async fn home_auto_restore_promotes_account_enc_key_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "enchomerestore";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();
    let (csrf, cookies) = get_login_page(&app, None).await;
    let guest = find_cookie_pair(&cookies, "session").expect("guest session");
    let login = post_login(&app, &guest, &csrf, username, password, true).await;
    let login_cookies = set_cookie_values(login.headers());
    let remember = find_cookie_pair(&login_cookies, "remember").expect("remember");
    let account_enc = find_cookie_pair(&login_cookies, &format!("enc_key-{username}"))
        .expect("account enc_key");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, format!("{remember}; {account_enc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_values(response.headers());
    assert!(
        cookies.iter().any(|cookie| cookie.starts_with("enc_key=")),
        "GET / restore must copy enc_key-{{user}} onto last-used enc_key"
    );
}
