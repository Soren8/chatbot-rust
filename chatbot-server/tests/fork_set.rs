use std::{env, fs};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
}

async fn login_user(app: &axum::Router, username: &str, password: &str) -> AuthCtx {
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
    let mut cookie = login_page
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("cookie");
    let body = to_bytes(login_page.into_body(), 128 * 1024).await.unwrap();
    let csrf_login =
        common::extract_csrf_token(std::str::from_utf8(&body).unwrap()).expect("csrf");
    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf_login),
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
    if let Some(v) = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let _ = to_bytes(login_post.into_body(), 32 * 1024).await.unwrap();
    let home = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    if let Some(v) = home
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        cookie = common::extract_cookie(v);
    }
    let home_body = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let csrf = CSRF_META_RE
        .captures(std::str::from_utf8(&home_body).unwrap())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf meta");
    let enc_key = common::derive_encryption_key_header(username, password);
    AuthCtx {
        cookie,
        csrf,
        enc_key,
    }
}

async fn post_json(
    app: &axum::Router,
    auth: &AuthCtx,
    uri: &str,
    payload: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let body = to_bytes(res.into_body(), 512 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    (status, json)
}

async fn get_sets(app: &axum::Router, auth: &AuthCtx) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/get_sets")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 256 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn chat_turn(app: &axum::Router, auth: &AuthCtx, set_name: &str, message: &str) {
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", r#"["a1"]"#);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &auth.cookie)
                .header("X-CSRF-Token", &auth.csrf)
                .header("X-Enc-Key", &auth.enc_key)
                .body(Body::from(
                    serde_json::to_vec(&json!({"message": message, "set_name": set_name}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "chat failed for {message}");
    let _ = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
}

#[tokio::test]
async fn fork_set_copies_prefix_and_autonames() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();

    let username = "forkuser";
    let password = "Sup3rS3cret!";
    let hashed = hash(password, DEFAULT_COST).expect("hash");
    fs::write(
        workspace.path().join("users.json"),
        serde_json::to_string_pretty(&json!({
            username: { "password": hashed, "tier": "free" }
        }))
        .unwrap(),
    )
    .unwrap();

    let app = build_router(resolve_static_root());
    let auth = login_user(&app, username, password).await;

    // Explicit set keeps its name across chats.
    let (status, created) = post_json(&app, &auth, "/create_set", json!({"set_name": "trip"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["status"], "success");

    for msg in ["one", "two", "three"] {
        chat_turn(&app, &auth, "trip", msg).await;
    }

    let sets = get_sets(&app, &auth).await;
    let src = sets
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "trip")
        .cloned()
        .expect("trip set present");
    let set_id = src["set_id"].as_str().unwrap().to_owned();
    let version = src["version"].as_u64().unwrap();

    // Fork at pair 1 (inclusive) with no name → `trip - branch`.
    let (status, forked) = post_json(
        &app,
        &auth,
        "/fork_set",
        json!({"set_id": set_id, "expected_version": version, "pair_index": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fork body: {forked}");
    assert_eq!(forked["status"], "success");
    assert_eq!(forked["name"], "trip - branch");
    let fork_id = forked["set_id"].as_str().unwrap().to_owned();

    // Forked history is the prefix; source untouched.
    let (_, loaded) = post_json(&app, &auth, "/load_set", json!({"set_id": fork_id})).await;
    assert_eq!(loaded["history_total"], 2);
    assert_eq!(loaded["history"][0][0], "one");
    assert_eq!(loaded["history"][1][0], "two");
    let (_, src_loaded) = post_json(&app, &auth, "/load_set", json!({"set_id": set_id})).await;
    assert_eq!(src_loaded["history_total"], 3);

    // Second fork at the same point dedups.
    let (status, forked2) = post_json(
        &app,
        &auth,
        "/fork_set",
        json!({"set_id": set_id, "pair_index": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(forked2["name"], "trip - branch 2");

    // Out of range → 404.
    let (status, _) = post_json(
        &app,
        &auth,
        "/fork_set",
        json!({"set_id": set_id, "pair_index": 99}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Missing pair_index → 400.
    let (status, _) = post_json(&app, &auth, "/fork_set", json!({"set_id": set_id})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Empty create gets the auto placeholder; first message adopts a name.
    let (status, auto) = post_json(&app, &auth, "/create_set", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(auto["name"], "New Chat");
    chat_turn(&app, &auth, "New Chat", "Plan my trip to Tokyo").await;
    let sets = get_sets(&app, &auth).await;
    assert!(
        sets.as_array().unwrap().iter().any(|s| s["name"] == "Plan my trip to Tokyo"),
        "first message should auto-name the set, got: {sets}"
    );
}
