use std::{env, fs::File, io::Write};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

fn extract_csrf_token(html: &str) -> Option<String> {
    let re = regex::Regex::new(r#"name="csrf_token" value="([^"]+)""#).unwrap();
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
async fn login_flow_sets_session_cookie() {
    common::ensure_pythonpath();
    common::init_tracing();
    env::set_var("SECRET_KEY", "test_secret_key");

    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());

    let password = "Sup3rS3cret!";
    let username = "testuser";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    let users_json = data_dir.path().join("users.json");
    let mut file = File::create(&users_json).expect("users.json create");
    let payload = json!({
        username: {
            "password": hashed,
            "tier": "free"
        }
    });
    file.write_all(serde_json::to_string_pretty(&payload).unwrap().as_bytes())
        .expect("write users");

    bridge::initialize_python().expect("python init");

    let static_root = resolve_static_root();
    let app = build_router(static_root);

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
    let csrf = extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token present");

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let post_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, extract_cookie(&set_cookie))
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
