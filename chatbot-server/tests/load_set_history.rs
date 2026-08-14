//! Long-chat load path: page recent pairs first, send UI thumbnails, fetch full
//! images on demand. Reproduces the "load everything at full resolution" stall.

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
    chat_images,
    enc_key::EncryptionKey,
    history::HistoryService,
};
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

struct AuthCtx {
    cookie: String,
    csrf: String,
    enc_key: String,
    username: String,
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

    AuthCtx {
        cookie,
        csrf,
        enc_key: common::derive_encryption_key_header(username, password),
        username: username.to_owned(),
    }
}

fn seed_user(workspace_path: &std::path::Path, username: &str, password: &str) {
    let hashed = hash(password, DEFAULT_COST).expect("hash");
    fs::write(
        workspace_path.join("users.json"),
        serde_json::to_string_pretty(&json!({
            username: { "password": hashed, "tier": "free" }
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn post_json(
    app: &axum::Router,
    auth: &AuthCtx,
    uri: &str,
    body: serde_json::Value,
    max_bytes: usize,
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
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), max_bytes).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        json!({"_raw": String::from_utf8_lossy(&bytes)})
    });
    (status, json)
}

async fn ensure_default_and_seed_pairs(
    app: &axum::Router,
    auth: &AuthCtx,
    pairs: &[(String, String)],
) -> (String, u64) {
    let (status, loaded) = post_json(
        app,
        auth,
        "/load_set",
        json!({"set_name": "default"}),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "load default: {loaded}");
    let set_id = loaded["set_id"].as_str().expect("set_id").to_owned();
    let mut version = loaded["version"].as_u64().expect("version");

    let key = EncryptionKey::from_header_value(&auth.enc_key).unwrap();
    let hs = HistoryService::global().unwrap();
    let id = chatbot_core::history::SetId::parse(&set_id).unwrap();
    for (user, assistant) in pairs {
        version = hs
            .append_pair(
                &auth.username,
                id,
                chatbot_core::history::SetVersion(version),
                user,
                assistant,
                &key,
            )
            .unwrap()
            .get();
    }
    (set_id, version)
}

#[tokio::test]
async fn load_set_without_limit_still_returns_full_history() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "page_full_user", "PageFull1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "page_full_user", "PageFull1!").await;

    let pairs: Vec<(String, String)> = (0..5)
        .map(|i| (format!("u{i}"), format!("a{i}")))
        .collect();
    let (set_id, _) = ensure_default_and_seed_pairs(&app, &auth, &pairs).await;

    let (status, loaded) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id}),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    let history = loaded["history"].as_array().expect("history");
    assert_eq!(history.len(), 5);
    assert_eq!(loaded["history_start"], 0);
    assert_eq!(loaded["history_total"], 5);
    assert_eq!(loaded["has_more"], false);
    assert_eq!(history[0][0], "u0");
    assert_eq!(history[4][0], "u4");
}

#[tokio::test]
async fn load_set_limit_returns_most_recent_page_then_older() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "page_tail_user", "PageTail1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "page_tail_user", "PageTail1!").await;

    let pairs: Vec<(String, String)> = (0..50)
        .map(|i| (format!("u{i}"), format!("a{i}")))
        .collect();
    let (set_id, _) = ensure_default_and_seed_pairs(&app, &auth, &pairs).await;

    let (status, tail) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id, "limit": 10}),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tail}");
    let history = tail["history"].as_array().expect("history");
    assert_eq!(history.len(), 10);
    assert_eq!(tail["history_start"], 40);
    assert_eq!(tail["history_total"], 50);
    assert_eq!(tail["has_more"], true);
    assert_eq!(history[0][0], "u40");
    assert_eq!(history[9][0], "u49");

    let (status, older) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id, "limit": 10, "before": 40}),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{older}");
    let older_hist = older["history"].as_array().expect("older history");
    assert_eq!(older_hist.len(), 10);
    assert_eq!(older["history_start"], 30);
    assert_eq!(older["has_more"], true);
    assert_eq!(older_hist[0][0], "u30");
    assert_eq!(older_hist[9][0], "u39");
}

#[tokio::test]
async fn load_set_thumbnails_then_history_pair_returns_full_image() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "page_thumb_user", "PageThumb1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "page_thumb_user", "PageThumb1!").await;

    let full = chat_images::fixture_jpeg_data_url(800, 800);
    let user_msg = format!("what is this?\n[IMAGE:{full}]");
    let (set_id, version) =
        ensure_default_and_seed_pairs(&app, &auth, &[(user_msg.clone(), "a photo".into())]).await;

    let (status, loaded) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id, "thumbnails": true}),
        1024 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    let shown = loaded["history"][0][0].as_str().expect("user msg");
    assert!(
        shown.contains("[IMAGE:]") || shown.contains("[IMAGE]"),
        "paged JSON should keep an image marker: {shown}"
    );
    assert!(
        !shown.contains("data:image"),
        "paged JSON must not inline image bytes: {shown}"
    );
    assert!(
        shown.len() < user_msg.len(),
        "text-only JSON should be smaller than stored message ({} vs {})",
        shown.len(),
        user_msg.len()
    );
    assert_ne!(shown, user_msg);

    let (status, pair) = post_json(
        &app,
        &auth,
        "/history_pair",
        json!({"set_id": set_id, "pair_index": 0}),
        2 * 1024 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pair}");
    assert_eq!(pair["user"].as_str(), Some(user_msg.as_str()));
    assert_eq!(pair["assistant"], "a photo");
    assert_eq!(pair["version"], version);

    let (status, img) = post_json(
        &app,
        &auth,
        "/history_pair",
        json!({"set_id": set_id, "pair_index": 0, "image_index": 0}),
        2 * 1024 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{img}");
    assert_eq!(img["image_src"].as_str(), Some(full.as_str()));
    assert!(img.get("user").is_none(), "image-only response must omit full pair");

    let uri = format!("/history_image/{set_id}/{version}/0/0");
    let cookie = format!(
        "{}; hist_enc_key={}",
        auth.cookie,
        urlencoding::encode(&auth.enc_key)
    );
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "GET {uri}");
    let headers = res.headers().clone();
    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("image/"),
        "expected image content-type, got {ctype}"
    );
    let cache = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache.contains("private") && cache.contains("max-age="),
        "browser-cacheable Cache-Control required, got {cache}"
    );
    let body = to_bytes(res.into_body(), 2 * 1024 * 1024).await.unwrap();
    assert!(body.starts_with(&[0xFF, 0xD8]), "JPEG SOI marker");

    let thumb_uri = format!("{uri}?size=thumb");
    let thumb_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&thumb_uri)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(thumb_res.status(), StatusCode::OK, "GET {thumb_uri}");
    let thumb_ctype = thumb_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        thumb_ctype.starts_with("image/"),
        "expected thumb image content-type, got {thumb_ctype}"
    );
    let thumb_body = to_bytes(thumb_res.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    assert!(thumb_body.starts_with(&[0xFF, 0xD8]), "thumb JPEG SOI");
    assert!(
        thumb_body.len() < body.len(),
        "thumb ({} B) should be smaller than full ({} B)",
        thumb_body.len(),
        body.len()
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&uri)
                .header(header::COOKIE, &auth.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::UNAUTHORIZED,
        "image GET without enc key must 401"
    );
}

#[tokio::test]
async fn delete_message_accepts_thumbnail_user_message() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");
    let workspace = common::TestWorkspace::with_openai_provider();
    seed_user(workspace.path(), "page_del_user", "PageDel1!");
    let app = build_router(resolve_static_root());
    let auth = login_user(&app, "page_del_user", "PageDel1!").await;

    let full = chat_images::fixture_jpeg_data_url(640, 480);
    let user_msg = format!("keep text\n[IMAGE:{full}]");
    let (set_id, version) =
        ensure_default_and_seed_pairs(&app, &auth, &[(user_msg, "reply".into())]).await;

    let (status, loaded) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id, "thumbnails": true}),
        1024 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    let thumb_msg = loaded["history"][0][0].as_str().expect("thumb").to_owned();

    let (status, deleted) = post_json(
        &app,
        &auth,
        "/delete_message",
        json!({
            "set_id": set_id,
            "expected_version": version,
            "pair_index": 0,
            "user_message": thumb_msg
        }),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["status"], "success");

    let (status, after) = post_json(
        &app,
        &auth,
        "/load_set",
        json!({"set_id": set_id}),
        256 * 1024,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["history"].as_array().map(|a| a.len()), Some(0));
}
