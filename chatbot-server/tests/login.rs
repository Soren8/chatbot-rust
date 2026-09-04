use std::{
    env,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
};
use tokio::net::TcpListener;

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

#[tokio::test]
async fn login_get_renders_form_with_security_headers() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();

    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present");
    assert!(
        set_cookie.contains("session"),
        "session cookie should include session id"
    );

    let csp = headers
        .get("Content-Security-Policy")
        .and_then(|value| value.to_str().ok())
        .expect("CSP header present");
    assert!(
        csp.contains("default-src 'self'"),
        "CSP header should include default-src"
    );

    for name in [
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
    ] {
        assert!(
            headers.get(name).is_some(),
            "expected {name} header to be present"
        );
    }

    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let body_str = std::str::from_utf8(&body).expect("utf8 response body");
    assert!(
        body_str.contains("<form action=\"/login\" method=\"post\">"),
        "login form markup present"
    );
    assert!(
        body_str.contains("name=\"remember_me\" id=\"remember_me\" value=\"on\" checked"),
        "remember checkbox should default to checked so sessions auto-restore"
    );

    let csrf = common::extract_csrf_token(body_str).expect("csrf token embedded in login form");
    assert!(
        !csrf.is_empty(),
        "csrf token extracted from login form should not be empty"
    );
}

#[tokio::test]
async fn login_flow_sets_session_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "testuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");

    assert_eq!(get_response.status(), StatusCode::OK);
    let set_cookie = get_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(get_response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let payload = format!(
        "username={}&password={}&csrf_token={}&remember_me=on",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let post_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let location = post_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert_eq!(location, "/");

    let set_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("set-cookie on login");
    assert!(set_cookie.starts_with("session="));
}

#[tokio::test]
async fn csrf_token_is_stable_for_existing_session() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();

    let first_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("first GET /login");

    assert_eq!(first_response.status(), StatusCode::OK);
    let set_cookie = first_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let first_body = to_bytes(first_response.into_body(), 64 * 1024)
        .await
        .expect("read first body");
    let first_csrf =
        common::extract_csrf_token(std::str::from_utf8(&first_body).expect("utf8 body"))
            .expect("csrf token in first response");

    let cookie_header = common::extract_cookie(&set_cookie);

    let second_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("second GET /login");

    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = to_bytes(second_response.into_body(), 64 * 1024)
        .await
        .expect("read second body");
    let second_csrf =
        common::extract_csrf_token(std::str::from_utf8(&second_body).expect("utf8 body"))
            .expect("csrf token in second response");

    assert_eq!(
        first_csrf, second_csrf,
        "csrf token should remain stable within a session"
    );
}

#[tokio::test]
async fn session_context_reflects_logged_in_user() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "sessionuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(get_response.status(), StatusCode::OK);

    let initial_cookie = get_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(get_response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let post_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&initial_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("set-cookie after login")
        .to_owned();

    let cookie_header = common::extract_cookie(&login_cookie);
    let session =
        session::session_context(Some(&cookie_header)).expect("session context after login");

    assert_eq!(
        session.username.as_deref(),
        Some(username),
        "username should be stored in session context"
    );
    assert_eq!(
        session.session_id, username,
        "session id should track the username after login"
    );

    let store = UserStore::new().expect("user store");
    assert!(
        store.has_key_verifier(username).expect("check verifier"),
        "login should register encryption key verifier"
    );
}

#[tokio::test]
async fn logout_clears_session_username() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "logoutuser";
    let password = "Sup3rS3cret!";
    seed_user(username, password);

    let app = build_app();

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(get_response.status(), StatusCode::OK);

    let initial_cookie = get_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(get_response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let post_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&initial_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(post_response.status(), StatusCode::FOUND);
    let login_cookie = post_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("login set-cookie")
        .to_owned();
    let cookie_header = common::extract_cookie(&login_cookie);

    let logout_response = app
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /logout");

    assert_eq!(logout_response.status(), StatusCode::FOUND);
    let logout_cookie = logout_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("logout set-cookie");
    assert!(
        logout_cookie.contains("session="),
        "logout should include session cookie"
    );

    let logout_cookie_header = common::extract_cookie(logout_cookie);
    let session_after_logout = session::session_context(Some(&logout_cookie_header))
        .expect("session context after logout");

    assert!(
        session_after_logout.username.is_none(),
        "username should be cleared after logout"
    );
}

async fn spawn_test_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = build_app();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    (addr, handle)
}

#[tokio::test]
async fn real_http_webserver_login_omits_secure_flag_for_plain_http_and_authenticates() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let username = "dummy_http_user";
    let password = "DummyPassword123!";
    seed_user(username, password);

    let (addr, server_handle) = spawn_test_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    let base_url = format!("http://{addr}");

    // 1. Plain HTTP GET /login: cookies MUST NOT have Secure flag (RFC 6265bis Android WebView compatibility)
    let get_resp = client
        .get(format!("{base_url}/login"))
        .send()
        .await
        .expect("GET /login");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);

    let get_cookies: Vec<String> = get_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();

    let session_cookie = get_cookies
        .iter()
        .find(|c| c.starts_with("session="))
        .expect("session cookie on GET /login");
    assert!(
        !session_cookie.contains("Secure"),
        "Plain HTTP session cookie must NOT contain Secure flag, got: {session_cookie}"
    );
    assert!(
        session_cookie.contains("HttpOnly"),
        "Session cookie must be HttpOnly"
    );

    let body_text = get_resp.text().await.expect("read login HTML");
    let csrf_token = common::extract_csrf_token(&body_text).expect("extract csrf token");
    let session_pair = common::extract_cookie(session_cookie);

    // 2. Plain HTTP POST /login with dummy account and remember_me
    let post_resp = client
        .post(format!("{base_url}/login"))
        .header(reqwest::header::COOKIE, &session_pair)
        .form(&[
            ("username", username),
            ("password", password),
            ("csrf_token", &csrf_token),
            ("remember_me", "on"),
        ])
        .send()
        .await
        .expect("POST /login");

    assert_eq!(
        post_resp.status(),
        reqwest::StatusCode::FOUND,
        "POST /login should redirect to / on success"
    );

    let post_cookies: Vec<String> = post_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();

    let mut auth_cookie_pairs = Vec::new();
    for c in &post_cookies {
        assert!(
            !c.contains("Secure"),
            "Plain HTTP POST /login cookie must NOT contain Secure flag, got: {c}"
        );
        auth_cookie_pairs.push(common::extract_cookie(c));
    }

    let remember_cookie = post_cookies
        .iter()
        .find(|c| c.starts_with("remember="))
        .expect("remember cookie issued on successful login");
    assert!(!remember_cookie.contains("Secure"));

    let enc_key_cookie = post_cookies
        .iter()
        .find(|c| c.starts_with("enc_key="))
        .expect("enc_key cookie issued on successful login");
    assert!(!enc_key_cookie.contains("Secure"));

    // 3. Authenticated GET / using the plain-HTTP cookies
    let cookie_header_val = auth_cookie_pairs.join("; ");
    let home_resp = client
        .get(format!("{base_url}/"))
        .header(reqwest::header::COOKIE, &cookie_header_val)
        .send()
        .await
        .expect("GET /");

    assert_eq!(home_resp.status(), reqwest::StatusCode::OK);
    let home_html = home_resp.text().await.expect("home HTML");
    assert!(
        home_html.contains("data-logged-in=\"true\""),
        "Home page should indicate user is logged in"
    );

    server_handle.abort();
}

#[tokio::test]
async fn real_http_webserver_retains_secure_flag_when_proxied_over_https() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let (addr, server_handle) = spawn_test_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    let base_url = format!("http://{addr}");

    let get_resp = client
        .get(format!("{base_url}/login"))
        .header("X-Forwarded-Proto", "https")
        .send()
        .await
        .expect("GET /login with HTTPS proxy header");

    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);

    let get_cookies: Vec<String> = get_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();

    let session_cookie = get_cookies
        .iter()
        .find(|c| c.starts_with("session="))
        .expect("session cookie on GET /login");
    assert!(
        session_cookie.contains("Secure"),
        "Proxied HTTPS session cookie must retain Secure flag, got: {session_cookie}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn real_http_webserver_csrf_mismatch_redirects_with_fresh_token_and_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let username = "dummy_csrf_user";
    let password = "DummyPassword123!";
    seed_user(username, password);

    let (addr, server_handle) = spawn_test_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    let base_url = format!("http://{addr}");

    // Post with an invalid / stale CSRF token (like the mobile app bug after dropped cookie)
    let post_fail_resp = client
        .post(format!("{base_url}/login"))
        .form(&[
            ("username", username),
            ("password", password),
            ("csrf_token", "invalid_stale_token"),
        ])
        .send()
        .await
        .expect("POST /login with bad CSRF");

    assert_eq!(
        post_fail_resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "Failed CSRF validation should redirect 303 to /login"
    );
    let location = post_fail_resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header on 303");
    assert_eq!(location, "/login");

    // Follow redirect to GET /login
    let get_resp = client
        .get(format!("{base_url}{location}"))
        .send()
        .await
        .expect("GET /login after redirect");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);

    let get_cookies: Vec<String> = get_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();

    let fresh_session_cookie = get_cookies
        .iter()
        .find(|c| c.starts_with("session="))
        .expect("fresh session cookie on GET /login");
    assert!(!fresh_session_cookie.contains("Secure"));
    let fresh_session_pair = common::extract_cookie(fresh_session_cookie);

    let body_text = get_resp.text().await.expect("read login HTML");
    let fresh_csrf_token = common::extract_csrf_token(&body_text).expect("extract fresh csrf token");

    // Retry login with fresh CSRF token and fresh session cookie
    let retry_resp = client
        .post(format!("{base_url}/login"))
        .header(reqwest::header::COOKIE, &fresh_session_pair)
        .form(&[
            ("username", username),
            ("password", password),
            ("csrf_token", &fresh_csrf_token),
        ])
        .send()
        .await
        .expect("retry POST /login");

    assert_eq!(
        retry_resp.status(),
        reqwest::StatusCode::FOUND,
        "Retry with fresh CSRF token should succeed"
    );

    server_handle.abort();
}

