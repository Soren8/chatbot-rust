//! S-PERF-1: provider HTTP clients are reused across chat turns.
//!
//! Given a live (non-fake) OpenAI-compatible provider pointed at a local
//! keep-alive upstream, when two sequential `/chat` turns stream through it,
//! then both requests must travel over one pooled TCP connection. A fresh
//! `reqwest::Client` per turn would open a second connection (and pay DNS +
//! TCP + TLS again before the first token).

mod common;

use std::{
    env,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use regex::Regex;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;

fn openai_config(base_url: &str) -> String {
    // Test-only classification: the local loopback mock retains nothing.
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "{base_url}"
    api_key: "${{OPENAI_API_KEY}}"
    context_size: 4096
    privacy_level: "private"
"#
    )
}

/// Reads one HTTP/1.1 request (headers plus `Content-Length` body) from
/// `stream`, keeping any over-read bytes in `buf`. Returns `false` on EOF.
async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let body_len = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let total = end + 4 + body_len;
            while buf.len() < total {
                let mut chunk = [0u8; 8192];
                let n = stream.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return false;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            buf.drain(..total);
            return true;
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return false;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Keep-alive SSE upstream that counts accepted TCP connections and served
/// requests. Every request gets one complete streaming completion.
async fn spawn_counting_openai_mock(
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            connections.fetch_add(1, Ordering::SeqCst);
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while read_request(&mut stream, &mut buf).await {
                    requests.fetch_add(1, Ordering::SeqCst);
                    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"pooled reply\"}}]}\n\ndata: [DONE]\n\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, handle)
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /");
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(common::extract_cookie)
        .expect("session cookie");
    let body = to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    let csrf = Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#)
        .expect("csrf regex")
        .captures(std::str::from_utf8(&body).expect("utf8"))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");
    (cookie, csrf)
}

async fn post_chat(app: &Router, cookie: &str, csrf: &str, payload: Value) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    let status = response.status();
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("chat body");
    (status, String::from_utf8(body.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn sequential_chat_turns_reuse_one_upstream_connection() {
    common::init_tracing();
    env::set_var("SECRET_KEY", "llm_client_reuse_secret");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");

    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (addr, mock) = spawn_counting_openai_mock(connections.clone(), requests.clone()).await;
    let _workspace = common::TestWorkspace::with_config(&openai_config(&format!("http://{addr}/v1")));

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;

    for message in ["first turn", "second turn"] {
        let (status, body) = post_chat(
            &app,
            &cookie,
            &csrf,
            json!({
                "message": message,
                "set_name": "default",
                "model_name": "default",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("pooled reply"), "expected mock delta, got: {body}");
    }

    let served = requests.load(Ordering::SeqCst);
    let accepted = connections.load(Ordering::SeqCst);
    mock.abort();

    assert_eq!(served, 2, "each turn must reach the upstream once");
    assert_eq!(
        accepted, 1,
        "both turns must reuse one pooled upstream connection"
    );
}
