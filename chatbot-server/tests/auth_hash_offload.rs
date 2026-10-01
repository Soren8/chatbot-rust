//! Password hashing and key derivation must not stall the request's tokio
//! worker: on a current-thread runtime a concurrent timer task keeps ticking
//! while POST /login (bcrypt verify + PBKDF2) or POST /signup (bcrypt hash)
//! is in flight.

use std::{
    env,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::user_store::{CreateOutcome, UserStore};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

/// Ticks a busy worker must still deliver while hashing runs elsewhere.
const MIN_TICKS: usize = 5;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

async fn cookie_and_csrf(app: &axum::Router, uri: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("GET form");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie")
        .to_owned();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf)
}

/// Run `request` while a 1 ms timer task counts ticks on the same
/// current-thread runtime; returns the response and the ticks observed
/// before it completed.
async fn race_with_ticker(app: &axum::Router, request: Request<Body>) -> (Response, usize) {
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = tokio::spawn({
        let ticks = ticks.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let response = app.clone().oneshot(request).await.expect("request");
    let observed = ticks.load(Ordering::Relaxed);
    ticker.abort();
    (response, observed)
}

fn form_post(uri: &str, cookie: &str, payload: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(payload))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn login_hashing_does_not_block_the_worker() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let _workspace = setup_workspace();
    let username = "offload_login_user";
    let password = "Sup3rS3cret!";
    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = cookie_and_csrf(&app, "/login").await;
    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let (response, ticks) = race_with_ticker(&app, form_post("/login", &cookie, payload)).await;

    assert_eq!(response.status(), StatusCode::FOUND, "login still succeeds");
    assert_eq!(
        response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/")
    );
    assert!(
        ticks >= MIN_TICKS,
        "worker stalled during login hashing: only {ticks} timer ticks"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn signup_hashing_does_not_block_the_worker() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let _workspace = setup_workspace();

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = cookie_and_csrf(&app, "/signup").await;
    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode("offload_signup_user"),
        urlencoding::encode("Sup3rS3cret!"),
        urlencoding::encode(&csrf)
    );

    let (response, ticks) = race_with_ticker(&app, form_post("/signup", &cookie, payload)).await;

    assert_eq!(response.status(), StatusCode::FOUND, "signup still succeeds");
    assert_eq!(
        response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login")
    );
    assert!(
        ticks >= MIN_TICKS,
        "worker stalled during signup hashing: only {ticks} timer ticks"
    );
}
