use std::{collections::HashMap, io::Cursor, sync::Arc};

use axum::{body::{to_bytes, Body}, http::{header, Request, StatusCode}, routing::post, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use chatbot_core::{
    account_service::AccountService,
    chat_images::{decode_image_data_url, nth_image_data_url},
    config::{PrivacyLevel, ProviderConfig, SearchProvidersConfig},
    config_source::{ConfigSource, DestinationPolicy},
    enc_key::EncryptionKey,
    history::SetId,
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
};
use chatbot_server::{
    build_router_with_services, generation_deps::GenerationDeps, identity::RequestIdentity,
    policy::RatePolicy, resolve_static_root, services::AppServices,
};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use serde_json::{json, Value};
use tower::ServiceExt;

struct Fixture {
    _directory: tempfile::TempDir,
    app: Router,
    chat: ChatService,
    cookie: String,
    csrf: String,
    key: EncryptionKey,
    set_id: SetId,
    captured: Arc<tokio::sync::Mutex<Vec<Value>>>,
    mock: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) { self.mock.abort(); }
}

async fn fixture(kind: &'static str) -> Fixture {
    let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let capture = captured.clone();
    let path = if kind == "xai" { "/v1/responses" } else { "/v1/chat/completions" };
    let mock_app = Router::new().route(path, post(move |axum::Json(payload): axum::Json<Value>| {
        let capture = capture.clone();
        async move {
            capture.lock().await.push(payload);
            let delta = if kind == "xai" {
                json!({"type":"response.output_text.delta", "delta":"bounded reply"})
            } else {
                json!({"choices":[{"delta":{"content":"bounded reply"}}]})
            };
            ([(header::CONTENT_TYPE, "text/event-stream")], format!("data: {delta}\n\ndata: [DONE]\n\n"))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let mock = tokio::spawn(async move { axum::serve(listener, mock_app).await.unwrap() });
    let provider = ProviderConfig {
        privacy_level: PrivacyLevel::Private, provider_name: "vision".into(),
        provider_type: kind.into(), tier: None, model_name: "vision".into(), context_size: Some(32768),
        base_url: base, api_key: None, allowed_providers: Vec::new(), request_timeout: Some(5.0),
        rate_limit_retries: Some(0), rate_limit_max_wait_secs: None, test_chunks: None,
        search: false, xai_search: false, xai_zdr: false,
    };
    let config = ConfigSource::new(true, 3600, "system".into(), "http://127.0.0.1:1".into())
        .with_destination_policy(DestinationPolicy::from_providers(
            &[provider.clone()], &SearchProvidersConfig::default(), PrivacyLevel::Private, PrivacyLevel::Private));
    let identity = RequestIdentity::with_store_and_config(Arc::new(HttpSessionStore::new(3600)), config.clone());
    let login = identity.finalize_login(None, "photo_user").unwrap();
    let cookie = login.set_cookie.split(';').next().unwrap().to_owned();
    let directory = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(directory.path().to_owned(), "image_safety_secret");
    let key = EncryptionKey::from_header_value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let mut users = accounts.users().unwrap();
    users.create_user("photo_user", "unused-password-hash").unwrap();
    users.ensure_key_verifier("photo_user", key.as_bytes()).unwrap();
    let chat = ChatService::with_storage_and_accounts(
        Arc::new(ChatSessionStore::new(3600, "system".into())), directory.path().to_owned(), accounts.clone());
    let set_id = chat.history().unwrap().ensure_default_set_id("photo_user", &key).unwrap();
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat.clone())
        .with_account_service(accounts).with_config_source(config).with_rate_policy(RatePolicy::new(0, 0))
        .with_generation_deps(GenerationDeps::new(HashMap::from([("vision".into(), provider)]), "vision".into(), false, false, None));
    Fixture { _directory: directory, app: build_router_with_services(resolve_static_root(), services),
        chat, cookie, csrf: login.csrf_token, key, set_id, captured, mock }
}

async fn call(f: &Fixture, method: &str, path: &str, payload: Value) -> (StatusCode, Vec<u8>) {
    let response = f.app.clone().oneshot(Request::builder().method(method).uri(path)
        .header(header::COOKIE, &f.cookie).header("X-CSRF-Token", &f.csrf)
        .header("X-Enc-Key", std::str::from_utf8(f.key.as_bytes()).unwrap())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 8 * 1024 * 1024).await.unwrap().to_vec();
    (status, body)
}

fn png_url() -> String {
    let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1225, 1430, Rgb([40, 80, 120])));
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, ImageFormat::Png).unwrap();
    format!("data:image/png;base64,{}", STANDARD.encode(bytes.into_inner()))
}

fn assert_bounded_provider_images(payload: &Value, kind: &str) {
    let messages = payload[if kind == "xai" { "input" } else { "messages" }].as_array().unwrap();
    let mut count = 0;
    for message in messages {
        if let Some(parts) = message["content"].as_array() {
            for part in parts {
                let url = if kind == "xai" { part["image_url"].as_str() } else { part["image_url"]["url"].as_str() };
                if let Some(url) = url {
                    let (_, bytes) = decode_image_data_url(url).unwrap();
                    let image = image::load_from_memory(&bytes).unwrap();
                    assert_eq!((image.width(), image.height()), (877, 1024), "oversized PNG on {kind} wire");
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 1, "exactly one retained image must reach {kind}");
}

async fn check_provider_bounds(kind: &'static str) {
    let f = fixture(kind).await;
    let original = png_url();
    let message = format!("portrait [IMAGE:{original}]");

    let (status, _) = call(&f, "POST", "/chat", json!({"set_id":f.set_id.to_string(), "message":message})).await;
    assert_eq!(status, StatusCode::OK);
    assert_bounded_provider_images(&f.captured.lock().await[0], kind);
    let stored = f.chat.history().unwrap().load("photo_user", f.set_id, &f.key).unwrap();
    assert_eq!(nth_image_data_url(&stored.history[0].0, 0).unwrap(), original);

    let (status, _) = call(&f, "POST", "/chat", json!({"set_id":f.set_id.to_string(), "message":"describe it again"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_bounded_provider_images(&f.captured.lock().await[1], kind);

    let (status, _) = call(&f, "POST", "/regenerate", json!({"set_id":f.set_id.to_string(), "pair_index":0, "message":"edited portrait [IMAGE:]"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_bounded_provider_images(&f.captured.lock().await[2], kind);
    let edited = f.chat.history().unwrap().load("photo_user", f.set_id, &f.key).unwrap();
    assert_eq!(nth_image_data_url(&edited.history[0].0, 0).unwrap(), original);
    assert!(edited.history[0].0.starts_with("edited portrait"));
}

#[tokio::test]
async fn openai_chat_history_and_regenerate_send_bounded_images_and_keep_originals() {
    check_provider_bounds("openai").await;
}

#[tokio::test]
async fn xai_chat_history_and_regenerate_send_bounded_images_and_keep_originals() {
    check_provider_bounds("xai").await;
}

#[tokio::test]
async fn svg_uploads_are_rejected_before_generation_or_saved_error_turns() {
    let f = fixture("openai").await;
    let svg = STANDARD.encode(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>");
    for path in ["/chat", "/regenerate"] {
        let (status, body) = call(&f, "POST", path, json!({"set_id":f.set_id.to_string(),
            "message":format!("caption [IMAGE:data:image/svg+xml;base64,{svg}]"), "pair_index":0,
            "model_name":"unknown-model"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "SVG on {path}: {}", String::from_utf8_lossy(&body));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"], "SVG images are not supported");
    }
    assert!(f.captured.lock().await.is_empty());
    assert!(f.chat.history().unwrap().load("photo_user", f.set_id, &f.key).unwrap().history.is_empty());
}

#[tokio::test]
async fn stored_svg_is_not_served_as_an_active_attachment_document() {
    let f = fixture("openai").await;
    let svg = STANDARD.encode(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>");
    let history = f.chat.history().unwrap();
    let version = history.load("photo_user", f.set_id, &f.key).unwrap().version;
    let version = history.append_pair("photo_user", f.set_id, version,
        &format!("legacy attachment [IMAGE:data:image/svg+xml;base64,{svg}]"), "legacy", &f.key).unwrap();

    let (status, body) = call(&f, "GET", &format!("/history_image/{}/{}/0/0", f.set_id, version.get()), Value::Null).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!String::from_utf8_lossy(&body).contains("<svg"));
}
