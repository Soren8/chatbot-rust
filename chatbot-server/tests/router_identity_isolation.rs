//! MOD-003 router identity isolation through production endpoints.
//!
//! Two routers built with independent owned [`HttpSessionStore`]s share no
//! CSRF, cookie, or login identity, while the default [`build_router`] keeps
//! matching the process-global store used by existing fixtures. Unknown
//! cookies keep the established log-ingestion policy (SEC-002) and the
//! non-creating rate-limit fallback on every router.

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Request, StatusCode},
};
use chatbot_core::session_identity::HttpSessionStore;
use chatbot_server::{
    build_router, build_router_with_identity, identity::RequestIdentity, resolve_static_root,
};
use regex::Regex;
use std::sync::Arc;
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

/// Router backed by a fresh owned store with an explicit CSRF policy, so the
/// test never depends on ambient config.
fn isolated_router() -> axum::Router {
    let store = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(store, true);
    build_router_with_identity(resolve_static_root(), identity)
}

/// First `session=...` pair from a response carrying several Set-Cookie
/// values (login also sets encryption-key cookies).
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

/// Guest bootstrap on `app` via the production home page.
async fn home_session(app: &axum::Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_pair(&response);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let html = std::str::from_utf8(&body).expect("utf8 home");
    (cookie, csrf_from_home(html))
}

/// Empty-message `/chat`: 400 proves the CSRF check passed (validation runs
/// after it), 401 proves it did not. No provider is ever contacted.
async fn post_chat_empty(app: &axum::Router, cookie: &str, csrf: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(r#"{"message":""}"#))
                .unwrap(),
        )
        .await
        .expect("POST /chat")
        .status()
}

async fn post_client_logs(
    app: &axum::Router,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/client_logs")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("X-CSRF-Token", csrf);
    }
    app.clone()
        .oneshot(builder.body(Body::from(r#"{"lines":["hello"]}"#)).unwrap())
        .await
        .expect("POST /client_logs")
        .status()
}

#[tokio::test]
async fn default_router_matches_global_session_store() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    // Fixture bootstraps through the global API, exactly like existing tests.
    let bootstrap = chatbot_core::session::prepare_home_context(None).expect("global bootstrap");
    let cookie = common::extract_cookie(&bootstrap.set_cookie);

    let app = build_router(resolve_static_root());

    // The default router honors the global CSRF token: validation runs, so
    // the empty message fails as a 400, not a 401.
    assert_eq!(
        post_chat_empty(&app, &cookie, &bootstrap.csrf_token).await,
        StatusCode::BAD_REQUEST,
        "default router must accept CSRF issued by the global store"
    );

    // The default router reuses the global session instead of minting a new
    // one, proving it is backed by the same store.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with global cookie");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        session_pair(&response),
        cookie,
        "default router must reuse the presented global session cookie"
    );
}

#[tokio::test]
async fn isolated_routers_reject_each_others_csrf_and_cookies() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    let app_a = isolated_router();
    let app_b = isolated_router();

    let (cookie_a, csrf_a) = home_session(&app_a).await;
    let (cookie_b, csrf_b) = home_session(&app_b).await;
    assert_ne!(cookie_a, cookie_b, "owned stores must mint distinct cookies");
    assert_ne!(csrf_a, csrf_b, "owned stores must mint distinct CSRF tokens");

    assert_eq!(
        post_chat_empty(&app_a, &cookie_a, &csrf_a).await,
        StatusCode::BAD_REQUEST,
        "own cookie plus own CSRF must pass the CSRF gate"
    );
    assert_eq!(
        post_chat_empty(&app_b, &cookie_b, &csrf_b).await,
        StatusCode::BAD_REQUEST,
        "own cookie plus own CSRF must pass the CSRF gate"
    );
    assert_eq!(
        post_chat_empty(&app_b, &cookie_a, &csrf_a).await,
        StatusCode::UNAUTHORIZED,
        "router B must reject router A's session identity"
    );
    assert_eq!(
        post_chat_empty(&app_a, &cookie_b, &csrf_b).await,
        StatusCode::UNAUTHORIZED,
        "router A must reject router B's session identity"
    );
    assert_eq!(
        post_chat_empty(&app_a, &cookie_a, "bogus-token").await,
        StatusCode::UNAUTHORIZED,
        "a presented but unknown CSRF token must not validate"
    );
}

#[tokio::test]
async fn isolated_routers_reject_each_others_login_cookies() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    let username = "router_identity_user";
    let password = "Sup3rS3cret!";
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    let mut store = chatbot_core::user_store::UserStore::new().expect("user store");
    match store.create_user(username, &hashed) {
        Ok(chatbot_core::user_store::CreateOutcome::Created)
        | Ok(chatbot_core::user_store::CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to seed user: {err}"),
    }

    let app_a = isolated_router();
    let app_b = isolated_router();

    // Log in through router A via the production login pages.
    let login_get = app_a
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let guest_cookie = session_pair(&login_get);
    let login_body = to_bytes(login_get.into_body(), 128 * 1024)
        .await
        .expect("read login page");
    let form_csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).expect("utf8"))
        .expect("login csrf");
    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&form_csrf),
    );
    let login_post = app_a
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &guest_cookie)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let login_cookie = session_pair(&login_post);
    assert_ne!(
        login_cookie, guest_cookie,
        "login must rotate the session cookie"
    );

    // Router B does not know the login: it serves a guest page and mints a
    // fresh cookie instead of adopting the foreign one.
    let foreign_home = app_b
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / on router B with router A login cookie");
    assert_eq!(foreign_home.status(), StatusCode::OK);
    let foreign_cookie = session_pair(&foreign_home);
    assert_ne!(
        foreign_cookie, login_cookie,
        "router B must mint a fresh guest instead of adopting the foreign login"
    );
    let foreign_body = to_bytes(foreign_home.into_body(), 512 * 1024)
        .await
        .expect("read foreign home");
    assert!(
        std::str::from_utf8(&foreign_body)
            .expect("utf8")
            .contains("data-logged-in=\"false\""),
        "router B must treat router A's login cookie as a guest"
    );

    // Router A still recognizes it as the logged-in user.
    let own_home = app_a
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / on router A with its login cookie");
    assert_eq!(own_home.status(), StatusCode::OK);
    let own_body = to_bytes(own_home.into_body(), 512 * 1024)
        .await
        .expect("read own home");
    let own_html = std::str::from_utf8(&own_body).expect("utf8");
    assert!(
        own_html.contains("data-logged-in=\"true\""),
        "router A must recognize its own login cookie"
    );

    // The login-bound CSRF token validates on the owning router only.
    let login_csrf = csrf_from_home(own_html);
    assert_eq!(
        post_chat_empty(&app_a, &login_cookie, &login_csrf).await,
        StatusCode::BAD_REQUEST,
        "login CSRF must validate on the owning router"
    );
    assert_eq!(
        post_chat_empty(&app_b, &login_cookie, &login_csrf).await,
        StatusCode::UNAUTHORIZED,
        "router B must reject router A's login-bound CSRF"
    );
}

#[tokio::test]
async fn isolated_routers_preserve_unknown_cookie_log_policy() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    let app_a = isolated_router();
    let app_b = isolated_router();
    let unknown = "session=router-identity-unknown-cookie";

    for app in [&app_a, &app_b] {
        // SEC-002 policy preserved per router: a presented-but-unknown
        // cookie still authorizes log ingestion without a CSRF header, and
        // the absence of any cookie still rejects.
        assert_eq!(
            post_client_logs(app, Some(unknown), None).await,
            StatusCode::NO_CONTENT,
            "unknown cookie must authorize client_logs without CSRF"
        );
        assert_eq!(
            post_client_logs(app, None, None).await,
            StatusCode::UNAUTHORIZED,
            "missing cookie must reject client_logs"
        );
        assert_eq!(
            post_client_logs(app, Some(unknown), Some("bogus-token")).await,
            StatusCode::UNAUTHORIZED,
            "a presented CSRF token must still validate on client_logs"
        );
        // Unknown cookies never satisfy the CSRF gate on mutating routes.
        assert_eq!(
            post_chat_empty(app, unknown, "bogus-token").await,
            StatusCode::UNAUTHORIZED,
            "unknown cookie must not pass the /chat CSRF gate"
        );
    }
}

#[tokio::test]
async fn isolated_router_keeps_rate_limit_unknown_cookie_fallback() {
    common::init_tracing();
    let _guard = lock_tests();
    // The executor disables rate limiting via the environment, which takes
    // precedence over YAML; follow the established env-var pattern and
    // restore it afterwards so later tests in this process keep defaults.
    let _workspace = setup();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "2");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();

    let app = isolated_router();
    let unknown = "session=router-identity-ratelimit-cookie";

    // The unknown cookie maps to a stable per-cookie budget without creating
    // a session: the first two ingestions pass, the third is rate limited.
    assert_eq!(
        post_client_logs(&app, Some(unknown), None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app, Some(unknown), None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_client_logs(&app, Some(unknown), None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "unknown cookie must keep its stable rate-limit fallback key"
    );

    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
}

#[tokio::test]
async fn injected_router_prefers_account_enc_key_for_owned_login() {
    common::init_tracing();
    let _guard = lock_tests();
    let _workspace = setup();

    let username = "router_scoped_key_user";
    let password = "Sup3rS3cret!";
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hash password");
    let mut store = chatbot_core::user_store::UserStore::new().expect("user store");
    match store.create_user(username, &hashed) {
        Ok(chatbot_core::user_store::CreateOutcome::Created)
        | Ok(chatbot_core::user_store::CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to seed user: {err}"),
    }

    let owned = Arc::new(HttpSessionStore::new(3600));
    let identity = RequestIdentity::with_store_and_csrf(owned, true);
    let app = build_router_with_identity(resolve_static_root(), identity.clone());

    let login_get = app
        .clone()
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let guest_cookie = session_pair(&login_get);
    let login_body = to_bytes(login_get.into_body(), 128 * 1024)
        .await
        .expect("read login page");
    let form_csrf = common::extract_csrf_token(std::str::from_utf8(&login_body).expect("utf8"))
        .expect("login csrf");
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
                .header(header::COOKIE, &guest_cookie)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let login_cookie = session_pair(&login_post);

    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with login cookie");
    assert_eq!(home.status(), StatusCode::OK);
    let home_body = to_bytes(home.into_body(), 512 * 1024)
        .await
        .expect("read home");
    let home_html = std::str::from_utf8(&home_body).expect("utf8");
    assert!(home_html.contains("data-logged-in=\"true\""));
    let login_csrf = csrf_from_home(home_html);

    // Login registered the key verifier, so the derived key verifies.
    let key = common::derive_encryption_key_header(username, password);
    let cookie_header = format!(
        "{login_cookie}; enc_key=wrong-key-value; enc_key-{username}={}",
        urlencoding::encode(&key)
    );

    // The scoped lookup resolves the owned login binding to the account key,
    // while the global lookup cannot see that session and takes the generic
    // decoy. This pins the divergence the endpoint assertion relies on.
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie_header.parse().expect("cookie header"));
    let scoped =
        chatbot_server::chat_utils::extract_enc_key_with_identity(&identity, &headers)
            .expect("scoped account key");
    assert_eq!(
        std::str::from_utf8(scoped.as_bytes()).expect("key utf8"),
        key,
        "scoped lookup must resolve the owned account key"
    );
    let global = chatbot_server::chat_utils::extract_enc_key(&headers).expect("generic key");
    assert_eq!(
        std::str::from_utf8(global.as_bytes()).expect("key utf8"),
        "wrong-key-value",
        "global lookup must not see the owned session"
    );

    // The handler accepts the request only when it resolves the account key
    // through the injected identity; the generic decoy alone would 401.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/update_preferences")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie_header)
                .header("X-CSRF-Token", &login_csrf)
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .expect("POST /update_preferences");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "injected router must verify the owned account key"
    );
    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("read preferences body");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("json body");
    assert_eq!(payload.get("status").and_then(|v| v.as_str()), Some("success"));
}
