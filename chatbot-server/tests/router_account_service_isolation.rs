//! MOD-003 router account service isolation through production endpoints.
//!
//! Two routers built with distinct owned [`AccountService`]s (separate roots
//! and verifier secrets) plus matching owned [`ChatService`]s share no
//! account records for the same username: the same username carries different
//! passwords, password logins reject the peer, and password-derived enc-key
//! cookies drive only their owner's chat. Remember tokens reject across roots
//! but rotate on the owner. Preferences, account-cookie promotion, and forget
//! stay scoped. Compatibility constructors keep the process-global account
//! service.

use std::{
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use chatbot_core::{
    account_service::AccountService,
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

fn all_set_cookies(response: &axum::http::Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.to_owned())
        .collect()
}

fn cookie_pair_value(set_cookie: &str) -> String {
    common::extract_cookie(set_cookie)
}

fn find_pairs(cookies: &[String], name: &str) -> Vec<String> {
    cookies
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with(&format!("{name}=")))
        .collect()
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
    accounts: AccountService,
}

/// Build an owned router sharing one account service between its chat service
/// and its account HTTP handlers. Call after the `TestWorkspace` is installed
/// so timeout/prompt resolve from the same config the production `run()`
/// captures. TTS tokens and rate counters are also owned.
fn make_owned_setup(secret: &str) -> OwnedSetup {
    let temp = tempfile::tempdir().expect("tempdir");
    let cfg = chatbot_core::config::app_config();
    let timeout = cfg.session_timeout;
    let prompt = cfg.default_system_prompt.clone();

    let account_root = temp.path().join("accounts");
    std::fs::create_dir_all(&account_root).expect("account root");
    let accounts =
        AccountService::with_root_and_secret(account_root.clone(), secret.to_owned());

    let sessions = Arc::new(ChatSessionStore::new(timeout, prompt));
    let chat = ChatService::with_storage_and_accounts(
        sessions,
        temp.path().to_path_buf(),
        accounts.clone(),
    );

    let identity = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let services = AppServices::with_owned_stores(identity)
        .with_chat_service(chat)
        .with_account_service(accounts.clone());
    let app = build_router_with_services(resolve_static_root(), services);
    OwnedSetup {
        _temp: temp,
        app,
        account_root,
        accounts,
    }
}

fn derive_owned_key(account_root: &Path, username: &str, password: &str) -> String {
    let store = UserStore::open(account_root).expect("open owned store");
    let bytes = store
        .derive_encryption_key(username, password)
        .expect("derive owned key");
    String::from_utf8(bytes).expect("utf8 key")
}

async fn signup_owned(app: &Router, username: &str, password: &str) {
    let get = app
        .clone()
        .oneshot(Request::builder().uri("/signup").body(Body::empty()).unwrap())
        .await
        .expect("GET /signup");
    assert_eq!(get.status(), StatusCode::OK);
    let cookie = session_pair(&get);
    let body = axum::body::to_bytes(get.into_body(), 128 * 1024)
        .await
        .expect("read signup");
    let csrf =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8")).expect("signup csrf");
    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
    );
    let post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/signup")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /signup");
    assert_eq!(post.status(), StatusCode::FOUND, "signup {username}");
    let _ = axum::body::to_bytes(post.into_body(), 32 * 1024)
        .await
        .expect("drain signup");
}

async fn login_owned(
    app: &Router,
    username: &str,
    password: &str,
    remember: bool,
) -> (String, String, Vec<String>) {
    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let cookie = session_pair(&login_get);
    let body = axum::body::to_bytes(login_get.into_body(), 128 * 1024)
        .await
        .expect("read login");
    let form_csrf =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8")).expect("login csrf");
    let mut form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&form_csrf),
    );
    if remember {
        form.push_str("&remember_me=on");
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
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let set_cookies = all_set_cookies(&login_post);
    let mut session = cookie;
    if let Some(raw) = set_cookies.iter().find_map(|c| {
        let pair = cookie_pair_value(c);
        pair.starts_with("session=").then_some(pair)
    }) {
        session = raw;
    }
    let _ = axum::body::to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .expect("drain login");

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    if let Some(raw) = home.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()) {
        let rotated = common::extract_cookie(raw);
        if rotated.starts_with("session=") {
            session = rotated;
        }
    }
    let home_body = axum::body::to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let csrf = csrf_from_home(std::str::from_utf8(&home_body).expect("utf8"));
    (session, csrf, set_cookies)
}

async fn try_login_owned(
    app: &Router,
    username: &str,
    password: &str,
) -> StatusCode {
    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let cookie = session_pair(&login_get);
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
    let status = login_post.status();
    let _ = axum::body::to_bytes(login_post.into_body(), 32 * 1024)
        .await
        .expect("drain login");
    status
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

/// Cookie-only chat: the real password-login `enc_key` Set-Cookie pair travels
/// as `Cookie` with no `X-Enc-Key` header, proving the login-derived cookie
/// drives the owned chat end to end.
async fn post_chat_cookie_only(
    app: &Router,
    cookie_header: &str,
    csrf: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie_header)
                .header("X-CSRF-Token", csrf)
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
    cookie_header: &str,
    csrf: &str,
    enc_key: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/load_set")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie_header)
        .header("X-CSRF-Token", csrf);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let response = app
        .clone()
        .oneshot(
            builder
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

fn enc_key_pair(set_cookies: &[String]) -> String {
    set_cookies
        .iter()
        .map(|c| cookie_pair_value(c))
        .find(|pair| {
            pair.starts_with("enc_key=") && pair.len() > "enc_key=".len()
        })
        .expect("login must issue a non-empty last-used enc_key cookie")
}

async fn post_json_authed(
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

async fn guest_csrf(app: &Router) -> (String, String) {
    let get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(get.status(), StatusCode::OK);
    let cookie = session_pair(&get);
    let body = axum::body::to_bytes(get.into_body(), 128 * 1024)
        .await
        .expect("read login");
    let csrf =
        common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8")).expect("login csrf");
    (cookie, csrf)
}

async fn post_remember(
    app: &Router,
    guest_cookie: &str,
    guest_csrf: &str,
    username: &str,
    remember_pairs: &[String],
    enc_key: Option<&str>,
) -> (StatusCode, Vec<String>, Value) {
    let mut cookie_header = guest_cookie.to_owned();
    for pair in remember_pairs {
        cookie_header.push_str("; ");
        cookie_header.push_str(pair);
    }
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/login/remember")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, &cookie_header);
    if let Some(key) = enc_key {
        builder = builder.header("X-Enc-Key", key);
    }
    let body = format!(
        "csrf_token={}&username={}",
        urlencoding::encode(guest_csrf),
        urlencoding::encode(username)
    );
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .expect("POST /login/remember");
    let status = response.status();
    let set_cookies = all_set_cookies(&response);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read remember body");
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, set_cookies, payload)
}

#[tokio::test]
async fn owned_routers_isolate_password_login_and_chat() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_account_user";
    const PASSWORD_A: &str = "Sup3rS3cret-A-1!";
    const PASSWORD_B: &str = "Sup3rS3cret-B-2!";
    const SECRET_A: &str = "router-account-secret-a";
    const SECRET_B: &str = "router-account-secret-b";

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);

    signup_owned(&setup_a.app, USERNAME, PASSWORD_A).await;
    signup_owned(&setup_b.app, USERNAME, PASSWORD_B).await;

    // Each password works only on its owner; no global fixture was enrolled.
    let global = UserStore::new().expect("global store");
    assert!(
        !global
            .validate_user(USERNAME, PASSWORD_A)
            .expect("global validate A"),
        "owned signup must not enroll the global store"
    );
    assert!(
        !global
            .validate_user(USERNAME, PASSWORD_B)
            .expect("global validate B"),
        "owned signup must not enroll the global store"
    );

    let (cookie_a, csrf_a, login_cookies_a) =
        login_owned(&setup_a.app, USERNAME, PASSWORD_A, false).await;
    let (cookie_b, csrf_b, login_cookies_b) =
        login_owned(&setup_b.app, USERNAME, PASSWORD_B, false).await;
    assert_eq!(
        try_login_owned(&setup_a.app, USERNAME, PASSWORD_B).await,
        StatusCode::UNAUTHORIZED,
        "router A must reject router B's password"
    );
    assert_eq!(
        try_login_owned(&setup_b.app, USERNAME, PASSWORD_A).await,
        StatusCode::UNAUTHORIZED,
        "router B must reject router A's password"
    );

    // Password-derived keys drive only their owner's chat; no pre-enrolled
    // global verifier is involved.
    let key_a = derive_owned_key(&setup_a.account_root, USERNAME, PASSWORD_A);
    let key_b = derive_owned_key(&setup_b.account_root, USERNAME, PASSWORD_B);

    let (status, _) = post_chat(
        &setup_a.app,
        &cookie_a,
        &csrf_a,
        &key_b,
        json!({"message": "cross key", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "router A must reject B's key");

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

    // Real password-login cookies drive each owner's chat with no `X-Enc-Key`
    // header, proving the login-derived cookie works end to end through the
    // shared owned account service.
    let cookie_header_a = format!("{cookie_a}; {}", enc_key_pair(&login_cookies_a));
    let cookie_header_b = format!("{cookie_b}; {}", enc_key_pair(&login_cookies_b));

    set_chunks(&["cookie answer A"]);
    let (status, body) = post_chat_cookie_only(
        &setup_a.app,
        &cookie_header_a,
        &csrf_a,
        json!({"message": "hello cookie A", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("cookie answer A"), "got: {body}");

    set_chunks(&["cookie answer B"]);
    let (status, body) = post_chat_cookie_only(
        &setup_b.app,
        &cookie_header_b,
        &csrf_b,
        json!({"message": "hello cookie B", "set_name": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("cookie answer B"), "got: {body}");

    let (status, loaded_a) =
        post_load_set(&setup_a.app, &cookie_header_a, &csrf_a, None).await;
    assert_eq!(status, StatusCode::OK);
    let history_a = loaded_a["history"].as_array().expect("history array");
    assert!(
        history_a.iter().any(|pair| pair[0] == "hello cookie A"),
        "owner A durable history must contain its cookie-driven turn: {loaded_a}"
    );
    assert!(
        history_a.iter().all(|pair| pair[0] != "hello cookie B"),
        "owner A must not see owner B's cookie-driven turn: {loaded_a}"
    );

    let (status, loaded_b) =
        post_load_set(&setup_b.app, &cookie_header_b, &csrf_b, None).await;
    assert_eq!(status, StatusCode::OK);
    let history_b = loaded_b["history"].as_array().expect("history array");
    assert!(
        history_b.iter().any(|pair| pair[0] == "hello cookie B"),
        "owner B durable history must contain its cookie-driven turn: {loaded_b}"
    );
    assert!(
        history_b.iter().all(|pair| pair[0] != "hello cookie A"),
        "owner B must not see owner A's cookie-driven turn: {loaded_b}"
    );

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn owned_remember_tokens_reject_peer_but_rotate_owner() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_account_remember";
    const PASSWORD_A: &str = "Sup3rS3cret-A-1!";
    const PASSWORD_B: &str = "Sup3rS3cret-B-2!";
    const SECRET_A: &str = "router-remember-secret-a";
    const SECRET_B: &str = "router-remember-secret-b";

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);
    signup_owned(&setup_a.app, USERNAME, PASSWORD_A).await;
    signup_owned(&setup_b.app, USERNAME, PASSWORD_B).await;

    let (_, _, cookies_a) = login_owned(&setup_a.app, USERNAME, PASSWORD_A, true).await;
    let (_, _, cookies_b) = login_owned(&setup_b.app, USERNAME, PASSWORD_B, true).await;
    let key_a = derive_owned_key(&setup_a.account_root, USERNAME, PASSWORD_A);
    let key_b = derive_owned_key(&setup_b.account_root, USERNAME, PASSWORD_B);

    let remember_a: Vec<String> = cookies_a
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with("remember=") || pair.starts_with(&format!("remember-{USERNAME}=")))
        .collect();
    assert_eq!(remember_a.len(), 2, "login must issue last-used plus account token");
    let remember_b: Vec<String> = cookies_b
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with("remember=") || pair.starts_with(&format!("remember-{USERNAME}=")))
        .collect();
    assert_eq!(remember_b.len(), 2);

    // Cross-root resume is rejected and leaves the peer family intact.
    let (guest_b, csrf_b) = guest_csrf(&setup_b.app).await;
    let (status, _, _) = post_remember(
        &setup_b.app,
        &guest_b,
        &csrf_b,
        USERNAME,
        &remember_a,
        Some(&key_a),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "router B must reject router A's remember token"
    );

    // Owner resume succeeds, rotates the token, and promotes the enc key.
    let (guest_a, csrf_a) = guest_csrf(&setup_a.app).await;
    let (status, rotated_cookies, payload) = post_remember(
        &setup_a.app,
        &guest_a,
        &csrf_a,
        USERNAME,
        &remember_a,
        Some(&key_a),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["username"], USERNAME);
    let rotated: Vec<String> = rotated_cookies
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with("remember=") || pair.starts_with(&format!("remember-{USERNAME}=")))
        .collect();
    assert_eq!(rotated.len(), 2, "resume must rotate both remember cookies");
    assert_ne!(rotated, remember_a, "rotated tokens must differ");
    assert!(
        find_pairs(&rotated_cookies, "enc_key").is_empty() == false
            || rotated_cookies.iter().any(|c| c.starts_with("enc_key=")),
        "matching X-Enc-Key must promote the last-used enc_key cookie"
    );

    // The rotated token still resumes on the owner; the peer still resumes
    // with its own token.
    let (guest_a2, csrf_a2) = guest_csrf(&setup_a.app).await;
    let (status, _, _) = post_remember(
        &setup_a.app,
        &guest_a2,
        &csrf_a2,
        USERNAME,
        &rotated,
        Some(&key_a),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotated token must keep working");

    let (guest_b2, csrf_b2) = guest_csrf(&setup_b.app).await;
    let (status, _, _) = post_remember(
        &setup_b.app,
        &guest_b2,
        &csrf_b2,
        USERNAME,
        &remember_b,
        Some(&key_b),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "peer family must stay intact");

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn owned_preferences_promotion_and_forget_stay_scoped() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_account_prefs";
    const PASSWORD_A: &str = "Sup3rS3cret-A-1!";
    const PASSWORD_B: &str = "Sup3rS3cret-B-2!";
    const SECRET_A: &str = "router-prefs-secret-a";
    const SECRET_B: &str = "router-prefs-secret-b";

    let setup_a = make_owned_setup(SECRET_A);
    let setup_b = make_owned_setup(SECRET_B);
    signup_owned(&setup_a.app, USERNAME, PASSWORD_A).await;
    signup_owned(&setup_b.app, USERNAME, PASSWORD_B).await;

    let (cookie_a, csrf_a, _) = login_owned(&setup_a.app, USERNAME, PASSWORD_A, false).await;
    let (cookie_b, csrf_b, _) = login_owned(&setup_b.app, USERNAME, PASSWORD_B, false).await;
    let key_a = derive_owned_key(&setup_a.account_root, USERNAME, PASSWORD_A);
    let key_b = derive_owned_key(&setup_b.account_root, USERNAME, PASSWORD_B);

    let (status, payload) = post_json_authed(
        &setup_a.app,
        "/update_preferences",
        &cookie_a,
        &csrf_a,
        &key_a,
        json!({"last_set": "set-a"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");
    let (status, payload) = post_json_authed(
        &setup_b.app,
        "/update_preferences",
        &cookie_b,
        &csrf_b,
        &key_b,
        json!({"last_set": "set-b"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload["status"], "success");

    let (last_a, ..) = setup_a
        .accounts
        .users()
        .expect("open A")
        .user_preferences(USERNAME)
        .expect("prefs A");
    let (last_b, ..) = setup_b
        .accounts
        .users()
        .expect("open B")
        .user_preferences(USERNAME)
        .expect("prefs B");
    assert_eq!(last_a.as_deref(), Some("set-a"));
    assert_eq!(last_b.as_deref(), Some("set-b"));

    // Cross-key preferences are rejected without touching the owner.
    let (status, _) = post_json_authed(
        &setup_a.app,
        "/update_preferences",
        &cookie_a,
        &csrf_a,
        &key_b,
        json!({"last_set": "hijack"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (last_a, ..) = setup_a
        .accounts
        .users()
        .expect("open A")
        .user_preferences(USERNAME)
        .expect("prefs A");
    assert_eq!(last_a.as_deref(), Some("set-a"));

    // Account-cookie promotion is scoped: the peer key verifies nowhere.
    let promoted = chatbot_server::chat_utils::promote_enc_key_cookies_with_accounts(
        Some(&format!("enc_key-{USERNAME}={key_a}")),
        USERNAME,
        &setup_a.accounts,
    );
    assert!(
        !promoted.is_empty(),
        "owner must promote its account key onto last-used"
    );
    let peer_promoted = chatbot_server::chat_utils::promote_enc_key_cookies_with_accounts(
        Some(&format!("enc_key-{USERNAME}={key_a}")),
        USERNAME,
        &setup_b.accounts,
    );
    assert!(
        peer_promoted.is_empty(),
        "peer must not promote the foreign account key"
    );

    // Forget on the owner revokes only the owner family.
    let (_, _, cookies_a) = login_owned(&setup_a.app, USERNAME, PASSWORD_A, true).await;
    let (_, _, cookies_b) = login_owned(&setup_b.app, USERNAME, PASSWORD_B, true).await;
    let remember_a: Vec<String> = cookies_a
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with("remember=") || pair.starts_with(&format!("remember-{USERNAME}=")))
        .collect();
    let remember_b: Vec<String> = cookies_b
        .iter()
        .map(|c| cookie_pair_value(c))
        .filter(|pair| pair.starts_with("remember=") || pair.starts_with(&format!("remember-{USERNAME}=")))
        .collect();

    let (guest_a, csrf_a) = guest_csrf(&setup_a.app).await;
    let mut forget_cookie = guest_a.clone();
    for pair in &remember_a {
        forget_cookie.push_str("; ");
        forget_cookie.push_str(pair);
    }
    let forget_body = format!(
        "csrf_token={}&username={}",
        urlencoding::encode(&csrf_a),
        urlencoding::encode(USERNAME)
    );
    let forget = setup_a
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login/forget")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &forget_cookie)
                .body(Body::from(forget_body))
                .unwrap(),
        )
        .await
        .expect("POST /login/forget");
    assert_eq!(forget.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(forget.into_body(), 64 * 1024)
        .await
        .expect("read forget");
    let payload: Value = serde_json::from_slice(&bytes).expect("forget json");
    assert_eq!(payload["revoked"], true);

    let (guest_a2, csrf_a2) = guest_csrf(&setup_a.app).await;
    let (status, _, _) = post_remember(
        &setup_a.app,
        &guest_a2,
        &csrf_a2,
        USERNAME,
        &remember_a,
        Some(&key_a),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "forgotten token must no longer resume"
    );

    let (guest_b2, csrf_b2) = guest_csrf(&setup_b.app).await;
    let (status, _, _) = post_remember(
        &setup_b.app,
        &guest_b2,
        &csrf_b2,
        USERNAME,
        &remember_b,
        Some(&key_b),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "peer family must survive the forget");

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}

#[tokio::test]
async fn compatibility_constructors_share_account_http() {
    common::init_tracing();
    let _guard = lock_tests();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    disable_rate_limits();
    clear_generation_env();

    const USERNAME: &str = "mod003_account_compat";
    const PASSWORD: &str = "Sup3rS3cret!";

    // Two routers with independent chat services but default (global)
    // accounts share signup/login, preserving committed router-chat semantics.
    let temp_a = tempfile::tempdir().expect("tempdir");
    let temp_b = tempfile::tempdir().expect("tempdir");
    let cfg = chatbot_core::config::app_config();
    let make_chat = |temp: &tempfile::TempDir, prompt: &str| {
        let legacy = temp.path().join("legacy");
        std::fs::create_dir_all(&legacy).expect("legacy");
        let history = HistoryService::open_with_data_dir(
            temp.path().join("history.redb"),
            &legacy,
            prompt.to_owned(),
        )
        .expect("history");
        let sessions = Arc::new(ChatSessionStore::new(3600, prompt.to_owned()));
        ChatService::new(
            sessions,
            Arc::new(history),
            temp.path().join("accounts"),
            "compat-chat-secret".to_owned(),
        )
    };
    let chat_a = make_chat(&temp_a, &cfg.default_system_prompt);
    let chat_b = make_chat(&temp_b, &cfg.default_system_prompt);
    let identity_a = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let identity_b = RequestIdentity::with_store_and_csrf(
        Arc::new(HttpSessionStore::new(3600)),
        true,
    );
    let app_a = build_router_with_services(
        resolve_static_root(),
        AppServices::with_owned_stores(identity_a).with_chat_service(chat_a),
    );
    let app_b = build_router_with_services(
        resolve_static_root(),
        AppServices::with_owned_stores(identity_b).with_chat_service(chat_b),
    );

    signup_owned(&app_a, USERNAME, PASSWORD).await;
    // Peer password would have failed above if accounts were isolated; the
    // same password now logs in on the sibling through the shared global store.
    let (cookie_b, _, _) = login_owned(&app_b, USERNAME, PASSWORD, false).await;
    assert!(cookie_b.starts_with("session="));

    clear_generation_env();
    disable_rate_limits();
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0
    );
}
