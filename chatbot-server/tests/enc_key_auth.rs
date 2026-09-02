use std::{
    env, fs,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::user_store::{CreateOutcome, UserStore};
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

fn seed_user(username: &str, password: &str) {
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

async fn login_session(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> (String, String) {
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

    let mut session_cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("initial session cookie");

    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("read login body");
    let login_csrf =
        common::extract_csrf_token(std::str::from_utf8(&login_body).expect("login utf8"))
            .expect("csrf token in login form");

    let form_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&login_csrf),
    );

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(form_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    let login_status = login_response.status();
    assert!(
        login_status == StatusCode::SEE_OTHER || login_status == StatusCode::FOUND,
        "expected redirect after login, got {login_status}"
    );
    if let Some(value) = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");

    if let Some(value) = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        session_cookie = common::extract_cookie(value);
    }

    let home_body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    (session_cookie, csrf_token)
}

#[tokio::test]
async fn authenticated_load_set_without_enc_key_returns_unauthorized() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_key_user";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set without enc key");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "cookie alone must not decrypt chat data"
    );
}

#[tokio::test]
async fn authenticated_load_set_with_wrong_enc_key_returns_unauthorized() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_key_user2";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", "definitely-not-the-right-key")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with wrong enc key");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "wrong encryption key must be rejected"
    );
}

#[tokio::test]
async fn missing_verifier_does_not_enroll_from_data_request() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_key_no_enroll";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;
    let enc_key = common::derive_encryption_key_header(username, password);

    let verifier_dir = workspace.path().join("key_verifiers");
    fs::remove_dir_all(&verifier_dir).ok();
    fs::create_dir_all(&verifier_dir).expect("recreate verifier dir");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with no verifier");

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "data endpoints must not enroll a missing verifier"
    );
    let leftover: Vec<_> = fs::read_dir(&verifier_dir)
        .map(|entries| entries.filter_map(Result::ok).collect())
        .unwrap_or_default();
    assert!(
        leftover.is_empty(),
        "missing verifier must stay missing, found {leftover:?}"
    );
}

#[tokio::test]
async fn legacy_binary_verifier_still_validates_and_migrates() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_key_legacy_kv";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;
    let enc_key = common::derive_encryption_key_header(username, password);

    let json_path = workspace
        .path()
        .join("key_verifiers")
        .join(format!("{username}_kv.json"));
    let legacy_path = workspace
        .path()
        .join("key_verifiers")
        .join(format!("{username}_kv"));
    let json = fs::read_to_string(&json_path).expect("json verifier");
    let record: serde_json::Value = serde_json::from_str(&json).expect("parse verifier");
    let bytes: Vec<u8> = record["verifier"]
        .as_array()
        .expect("verifier array")
        .iter()
        .map(|v| v.as_u64().expect("byte") as u8)
        .collect();
    fs::write(&legacy_path, bytes).expect("write legacy verifier");
    fs::remove_file(&json_path).expect("remove json verifier");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with legacy verifier");

    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "legacy verifier must still unlock data"
    );
    assert!(json_path.exists(), "legacy verifier must migrate to json");
    assert!(!legacy_path.exists(), "legacy verifier file must be removed");
}

#[tokio::test]
async fn expired_verifier_json_still_validates() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_key_expired_json";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
    let (session_cookie, csrf_token) = login_session(&app, username, password).await;
    let enc_key = common::derive_encryption_key_header(username, password);

    let json_path = workspace
        .path()
        .join("key_verifiers")
        .join(format!("{username}_kv.json"));
    let json = fs::read_to_string(&json_path).expect("json verifier");
    let mut record: serde_json::Value = serde_json::from_str(&json).expect("parse verifier");
    record["expires"] = json!(1);
    fs::write(&json_path, serde_json::to_string(&record).unwrap()).expect("write expired field");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, &session_cookie)
                .header("X-CSRF-Token", &csrf_token)
                .header("X-Enc-Key", &enc_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with expired-field verifier");

    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "data-key verifier must not expire"
    );
    assert!(json_path.exists(), "verifier must not be deleted on use");
}

fn set_cookie_values(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.to_owned())
        .collect()
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

#[tokio::test]
async fn login_sets_httponly_enc_key_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_cookie_user";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
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
    let guest = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("guest cookie");
    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("login body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).expect("utf8"))
        .expect("csrf");

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &guest)
                .body(Body::from(format!(
                    "username={}&password={}&csrf_token={}&remember_me=on",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    urlencoding::encode(&csrf)
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    let cookies = set_cookie_values(login_response.headers());
    let enc = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .expect("enc_key cookie");
    assert!(enc.contains("HttpOnly"), "enc_key must be HttpOnly: {enc}");
    assert!(
        enc.contains("SameSite=Strict"),
        "enc_key must be SameSite=Strict: {enc}"
    );
    assert!(enc.contains("Path=/"), "enc_key Path=/: {enc}");
}

#[tokio::test]
async fn load_set_accepts_enc_key_cookie_without_header() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_cookie_load";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
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
    let guest = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("guest cookie");
    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("login body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).expect("utf8"))
        .expect("csrf");

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &guest)
                .body(Body::from(format!(
                    "username={}&password={}&csrf_token={}&remember_me=on",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    urlencoding::encode(&csrf)
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    let cookies = set_cookie_values(login_response.headers());
    let session = cookies
        .iter()
        .find(|cookie| cookie.starts_with("session="))
        .map(|cookie| cookie_pair(cookie))
        .expect("session cookie");
    let enc = cookies
        .iter()
        .find(|cookie| cookie.starts_with("enc_key="))
        .map(|cookie| cookie_pair(cookie))
        .expect("enc_key cookie");

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, format!("{session}; {enc}"))
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with enc cookie");

    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "HttpOnly enc_key cookie must unlock data without X-Enc-Key"
    );
}

#[tokio::test]
async fn load_set_accepts_account_enc_key_cookie_without_last_used() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    let username = "enc_acct_load";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_router(resolve_static_root());
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
    let guest = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("guest cookie");
    let login_body = to_bytes(login_page.into_body(), 128 * 1024)
        .await
        .expect("login body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).expect("utf8"))
        .expect("csrf");

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &guest)
                .body(Body::from(format!(
                    "username={}&password={}&csrf_token={}&remember_me=on",
                    urlencoding::encode(username),
                    urlencoding::encode(password),
                    urlencoding::encode(&csrf)
                )))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    let cookies = set_cookie_values(login_response.headers());
    let session = cookies
        .iter()
        .find(|cookie| cookie.starts_with("session="))
        .map(|cookie| cookie_pair(cookie))
        .expect("session cookie");
    let account_enc = cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("enc_key-{username}=")))
        .map(|cookie| cookie_pair(cookie))
        .expect("per-account enc_key cookie");

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("home body");
    let home_html = std::str::from_utf8(&home_body).expect("utf8");
    let csrf_token = CSRF_META_RE
        .captures(home_html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token meta");

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/load_set")
                .header(header::COOKIE, format!("{session}; {account_enc}"))
                .header("X-CSRF-Token", &csrf_token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"set_name": "default"})).expect("load payload"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /load_set with account enc cookie");

    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "enc_key-{{user}} must unlock data without last-used enc_key or X-Enc-Key"
    );
}
