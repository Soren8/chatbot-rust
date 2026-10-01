//! A voice turn spends one POST /tts plus one GET /tts_stream/{token} per
//! sentence. Only the POST, which mints the single-use token, counts against
//! the per-user budget; the token-bound stream GET and cancel DELETE do not,
//! so short-sentence replies are not cut off with 429 mid-playback.

mod common;

use std::{net::SocketAddr, sync::Arc, thread::JoinHandle};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Router,
};
use chatbot_core::{config::TtsAccess, session_identity::HttpSessionStore};
use chatbot_server::{
    build_router_with_services,
    identity::RequestIdentity,
    policy::{RatePolicy, TtsPolicy},
    resolve_static_root,
    services::AppServices,
};
use chatbot_test_support::TestWorkspace;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};
use tower::ServiceExt;

const PER_USER_BUDGET: u32 = 60;
const SENTENCES: usize = 35;

fn kokoro_stub() -> Router {
    Router::new().route(
        "/v1/tts/kokoro",
        post(|| async {
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::HeaderName::from_static("x-sample-rate"), "24000"),
                ],
                vec![0_u8; 4800],
            )
        }),
    )
}

async fn spawn_stub(router: Router) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let std_listener = listener.into_std().expect("into std");
    let (tx, rx) = oneshot::channel();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).expect("from std");
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
    });
    (addr, tx, handle)
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("session cookie")
        .to_owned();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let html = std::str::from_utf8(&body).expect("utf8");
    let csrf = regex::Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#)
        .unwrap()
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    (common::extract_cookie(&set_cookie), csrf)
}

async fn post_tts(app: &Router, cookie: &str, csrf: &str, text: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::from(serde_json::to_vec(&json!({ "text": text })).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /tts")
}

async fn send(app: &Router, method: Method, uri: String, cookie: &str, csrf: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header("X-CSRF-Token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request")
        .status()
}

#[tokio::test]
async fn tts_stream_and_cancel_do_not_consume_the_per_user_budget() {
    common::init_tracing();
    std::env::set_var("SECRET_KEY", "integration_test_secret");
    let (addr, shutdown, handle) = spawn_stub(kokoro_stub()).await;
    let _workspace = TestWorkspace::with_openai_provider();

    let tts = TtsPolicy::new(
        TtsAccess::Anyone,
        "opus".to_string(),
        "kokoro".to_string(),
        None,
        "http://127.0.0.1:9".to_string(),
        format!("http://{}:{}", addr.ip(), addr.port()),
    );
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let services = AppServices::with_owned_stores(identity)
        .with_rate_policy(RatePolicy::new(PER_USER_BUDGET, 600))
        .with_tts_policy(tts);
    let app = build_router_with_services(resolve_static_root(), services);
    let (cookie, csrf) = guest_session(&app).await;

    for sentence in 0..SENTENCES {
        let response = post_tts(&app, &cookie, &csrf, &format!("Sentence {sentence}.")).await;
        assert_eq!(response.status(), StatusCode::OK, "POST /tts for sentence {sentence}");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
            .as_str()
            .expect("token")
            .to_owned();
        let stream = send(&app, Method::GET, format!("/tts_stream/{token}"), &cookie, &csrf).await;
        assert_eq!(stream, StatusCode::OK, "GET /tts_stream for sentence {sentence}");
        let cancel =
            send(&app, Method::DELETE, format!("/tts_stream/{token}"), &cookie, &csrf).await;
        assert_eq!(cancel, StatusCode::NO_CONTENT, "DELETE /tts_stream for sentence {sentence}");
    }

    // Only the POSTs counted: the remaining budget admits exactly 60 in total.
    for extra in SENTENCES..PER_USER_BUDGET as usize {
        let status = post_tts(&app, &cookie, &csrf, &format!("Extra {extra}.")).await.status();
        assert_eq!(status, StatusCode::OK, "POST /tts {extra} within budget");
    }
    let over = post_tts(&app, &cookie, &csrf, "One too many.").await.status();
    assert_eq!(over, StatusCode::TOO_MANY_REQUESTS, "POST /tts past the budget is limited");

    shutdown.send(()).ok();
    handle.join().expect("join kokoro stub");
}
