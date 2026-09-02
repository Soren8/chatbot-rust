use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

#[tokio::test]
async fn logout_flow_clears_session_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let password = "Sup3rS3cret!";
    let username = "testuser";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let mut store = chatbot_core::user_store::UserStore::new().expect("user store");
    match store.create_user(username, &hashed) {
        Ok(chatbot_core::user_store::CreateOutcome::Created)
        | Ok(chatbot_core::user_store::CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to seed user: {err}"),
    }

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
    let get_set_cookie = login_get
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(login_get.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let login_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&get_set_cookie))
                .body(Body::from(login_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");

    assert_eq!(login_response.status(), StatusCode::FOUND);
    let login_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("set-cookie after login");

    let logout_response = app
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(header::COOKIE, login_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /logout");

    assert_eq!(logout_response.status(), StatusCode::FOUND);
    let location = logout_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert_eq!(location, "/login");

    let logout_cookie = logout_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("set-cookie on logout");
    assert_ne!(
        logout_cookie, login_cookie,
        "logout should rotate the session cookie"
    );
}

#[tokio::test]
async fn logged_in_home_distinguishes_switch_account_from_device_logout() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let password = "Sup3rS3cret!";
    let username = "uitestuser";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let mut store = chatbot_core::user_store::UserStore::new().expect("user store");
    match store.create_user(username, &hashed) {
        Ok(chatbot_core::user_store::CreateOutcome::Created)
        | Ok(chatbot_core::user_store::CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to seed user: {err}"),
    }

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
    let get_set_cookie = login_get
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();
    let body = to_bytes(login_get.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");
    let login_html = std::str::from_utf8(&body).expect("utf8 body");
    assert!(
        login_html.contains("Switching accounts from chat does not."),
        "login page must explain that switch keeps the cached account"
    );

    let login_payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&get_set_cookie))
                .body(Body::from(login_payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_response.status(), StatusCode::FOUND);
    let login_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("set-cookie after login");

    let home = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    assert_eq!(home.status(), StatusCode::OK);
    let home_body = to_bytes(home.into_body(), 256 * 1024)
        .await
        .expect("read home");
    let home_html = std::str::from_utf8(&home_body).expect("utf8");
    assert!(
        home_html.contains("Switch account"),
        "logged-in home must offer Switch account"
    );
    assert!(
        home_html.contains("Stay signed in on this computer"),
        "Switch account must say the computer stays signed in"
    );
    assert!(
        home_html.contains("Log out of this computer"),
        "logged-in home must offer Log out of this computer"
    );
    assert!(
        home_html.contains("Password required next time"),
        "device logout must say the password is required next time"
    );
    assert!(
        home_html.contains("logout-this-computer"),
        "device logout control must be wired"
    );
}
