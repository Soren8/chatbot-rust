use std::{
    env,
    fs::File,
    io::BufReader,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use regex::Regex;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use urlencoding::encode;

mod common;

fn extract_csrf_token(html: &str) -> Option<String> {
    let re = Regex::new(r#"name="csrf_token" value="([^"]+)""#).unwrap();
    re.captures(html).and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
}

fn extract_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

#[tokio::test]
async fn signup_flow_creates_user_record() {
    common::ensure_pythonpath();
    common::init_tracing();

    env::set_var("SECRET_KEY", "test_secret_key");

    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());

    bridge::initialize_python().expect("python init");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/signup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /signup");

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
    let csrf = extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let username = format!(
        "testuser_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let payload = format!(
        "username={}&password={}&csrf_token={}",
        encode(&username),
        encode("Password123"),
        encode(&csrf)
    );

    let post_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signup")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /signup");

    assert_eq!(post_response.status(), StatusCode::FOUND);
    let location = post_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location");
    assert_eq!(location, "/login");

    let users_file = data_dir.path().join("users.json");
    let users_reader = BufReader::new(File::open(&users_file).expect("users.json exists"));
    let users: Value = serde_json::from_reader(users_reader).expect("valid users json");
    assert!(users.get(&username).is_some(), "signup persisted user");
}
