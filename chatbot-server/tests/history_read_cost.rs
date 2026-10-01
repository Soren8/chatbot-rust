//! Request paths decrypt only the history blobs they need.
//!
//! Counts come from the thread-local history blob counters, so every request
//! here runs on the test's `current_thread` runtime.

mod common;

use std::{collections::HashMap, env, net::SocketAddr, sync::{Arc, Mutex, OnceLock}};

use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, routing::post, Router};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    account_service::AccountService,
    enc_key::EncryptionKey,
    history::{cost::take_blob_opens, SetId, SetVersion},
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
    user_store::UserStore,
};
use chatbot_server::{build_router_with_services, generation_deps::GenerationDeps, identity::RequestIdentity, resolve_static_root, services::AppServices};
use chatbot_test_support::TestWorkspace;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;

const USER: &str = "cost-owner";
const PASSWORD: &str = "CostPassword!42";
const IMAGES: u64 = 3;
const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aenQAAAAASUVORK5CYII=";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

struct Session { cookie: String, csrf: String, key: String }

fn home_csrf(html: &[u8]) -> String {
    let html = std::str::from_utf8(html).unwrap();
    regex::Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#)
        .unwrap().captures(html).unwrap()[1].to_owned()
}

async fn login(app: &Router) -> Session {
    let page = app.clone().oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = common::extract_cookie(page.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let html = to_bytes(page.into_body(), 64 * 1024).await.unwrap();
    let csrf = common::extract_csrf_token(std::str::from_utf8(&html).unwrap()).unwrap();
    let form = format!("username={USER}&password={}&csrf_token={}", urlencoding::encode(PASSWORD), urlencoding::encode(&csrf));
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/login")
        .header(header::COOKIE, cookie).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = common::extract_cookie(response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let page = app.clone().oneshot(Request::builder().uri("/").header(header::COOKIE, &cookie).body(Body::empty()).unwrap()).await.unwrap();
    let html = to_bytes(page.into_body(), 256 * 1024).await.unwrap();
    Session { cookie, csrf: home_csrf(&html), key: common::derive_encryption_key_header(USER, PASSWORD) }
}

fn json_request(session: &Session, uri: &str, payload: Value) -> Request<Body> {
    Request::builder().method(Method::POST).uri(uri).header(header::COOKIE, &session.cookie)
        .header("X-CSRF-Token", &session.csrf).header("X-Enc-Key", &session.key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap())).unwrap()
}

async fn voice_stub() -> SocketAddr {
    let router = Router::new().route("/v1/stt", post(|| async { axum::Json(json!({"text":"stub transcript"})) }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    address
}

/// A signed-in user owning one set whose history holds `IMAGES` image pairs.
async fn fixture() -> (TestWorkspace, Router, Session, String) {
    let voice = voice_stub().await;
    env::set_var("SECRET_KEY", "privacy_read_cost_secret");
    let workspace = TestWorkspace::with_config(&format!(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-test
    base_url: https://api.openai.com/v1
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
tts_provider: kokoro
tts_codec: wav
stt_privacy_level: non_private
tts_privacy_level: non_private
voice_service_host: "{}"
voice_service_port: {}
"#, voice.ip(), voice.port()));
    UserStore::new().unwrap().create_user(USER, &hash(PASSWORD, DEFAULT_COST).unwrap()).unwrap();
    let root: std::path::PathBuf = env::var("HOST_DATA_DIR").unwrap().into();
    let accounts = AccountService::with_root_and_secret(root.clone(), "privacy_read_cost_secret");
    let chat = ChatService::with_storage_and_accounts(Arc::new(ChatSessionStore::new(3600, String::new())), root, accounts.clone());
    let provider = chatbot_core::config::get_provider_config(None).unwrap();
    let generation = GenerationDeps::new_with_fake(
        HashMap::from([("default".into(), provider)]), "default".into(), false, false,
        None, Some(vec!["answer".into()]), None, None, 0, None,
    );
    let services = AppServices::with_owned_stores(RequestIdentity::with_store(Arc::new(HttpSessionStore::new(3600))))
        .with_chat_service(chat.clone()).with_account_service(accounts).with_generation_deps(generation);
    let app = build_router_with_services(resolve_static_root(), services);
    let session = login(&app).await;
    let response = app.clone().oneshot(json_request(&session, "/create_set", json!({"set_name":"costly"}))).await.unwrap();
    let created: Value = serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let set_id = created["set_id"].as_str().unwrap().to_owned();
    let key = EncryptionKey::from_header_value(&session.key).unwrap();
    let history = chat.history().unwrap();
    let mut version = SetVersion(created["version"].as_u64().unwrap());
    for turn in 0..IMAGES {
        version = history.append_pair(USER, SetId::parse(&set_id).unwrap(), version,
            &format!("picture {turn} [IMAGE:{PNG}]"), "seen", &key).unwrap();
    }
    let response = app.clone().oneshot(json_request(&session, "/set_privacy",
        json!({"set_id":set_id,"expected_version":version.0,"privacy_level":"non_private"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    (workspace, app, session, set_id)
}

#[tokio::test(flavor = "current_thread")]
async fn bound_tts_admission_decrypts_no_history_images() {
    let _guard = lock();
    let (_workspace, app, session, set_id) = fixture().await;
    take_blob_opens();
    let response = app.clone().oneshot(json_request(&session, "/tts", json!({"text":"One sentence.","set_id":set_id}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opens = take_blob_opens();
    assert_eq!((opens.images, opens.pairs), (0, 0), "a sentence admission only needs the set's privacy policy: {opens:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn bound_stt_decrypts_no_history_images() {
    let _guard = lock();
    let (_workspace, app, session, set_id) = fixture().await;
    let body = format!("--cost\r\ncontent-disposition: form-data; name=\"audio\"; filename=\"a.webm\"\r\ncontent-type: audio/webm\r\n\r\nfakeaudio\r\n--cost\r\ncontent-disposition: form-data; name=\"set_id\"\r\n\r\n{set_id}\r\n--cost--\r\n");
    take_blob_opens();
    let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/stt")
        .header(header::COOKIE, &session.cookie).header("X-CSRF-Token", &session.csrf).header("X-Enc-Key", &session.key)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=cost")
        .body(Body::from(body)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opens = take_blob_opens();
    assert_eq!((opens.images, opens.pairs), (0, 0), "transcription only needs the set's privacy policy: {opens:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn chat_privacy_binding_adds_no_history_materialization() {
    let _guard = lock();
    let (_workspace, app, session, set_id) = fixture().await;
    take_blob_opens();
    let response = app.clone().oneshot(json_request(&session, "/chat", json!({"message":"next","set_id":set_id}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opens = take_blob_opens();
    assert!(opens.images <= IMAGES, "prepare may materialize the set once; the privacy binding must not add another: {opens:?}");
    to_bytes(response.into_body(), 64 * 1024).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chat_prompt_decrypts_only_the_full_resolution_image() {
    let _guard = lock();
    let (_workspace, app, session, set_id) = fixture().await;
    take_blob_opens();
    let response = app.clone().oneshot(json_request(&session, "/chat", json!({"message":"next","set_id":set_id}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opens = take_blob_opens();
    assert_eq!(opens.images, 1, "only the newest image is sent at full resolution: {opens:?}");
    assert_eq!(opens.thumbs, IMAGES - 1, "older images come from stored thumbnails: {opens:?}");
    to_bytes(response.into_body(), 64 * 1024).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn regenerate_prompt_decrypts_only_the_edited_pair_image() {
    let _guard = lock();
    let (_workspace, app, session, set_id) = fixture().await;
    let last = IMAGES - 1;
    take_blob_opens();
    let response = app.clone().oneshot(json_request(&session, "/regenerate", json!({
        "message": format!("picture {last} [IMAGE:{PNG}]"), "set_id": set_id, "pair_index": last,
    }))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opens = take_blob_opens();
    assert_eq!(opens.images, 1, "the edited pair's stored image is the only full-resolution read: {opens:?}");
    assert_eq!(opens.thumbs, IMAGES - 1, "the history prefix uses stored thumbnails: {opens:?}");
    to_bytes(response.into_body(), 64 * 1024).await.unwrap();
}
