//! Given an upstream SSE stream split inside a UTF-8 codepoint, when `/chat` streams it,
//! then provider decoding preserves the original multibyte text without replacement characters.

mod common;

use std::{
    env,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use chatbot_server::{build_router, resolve_static_root};
use regex::Regex;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn provider_config(kind: &str, base_url: &str) -> String {
    let api_key_var = if kind == "xai" { "XAI_API_KEY" } else { "OPENAI_API_KEY" };
    format!(
        r#"
llms:
  - provider_name: "default"
    type: "{kind}"
    model_name: "gpt-test"
    base_url: "{base_url}"
    api_key: "${{{api_key_var}}}"
    context_size: 4096
    xai_search: false
"#
    )
}

async fn read_request(stream: &mut TcpStream) -> bool {
    let mut buf = Vec::new();
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return true;
        }
        let mut bytes = [0; 4096];
        let n = stream.read(&mut bytes).await.unwrap_or(0);
        if n == 0 {
            return false;
        }
        buf.extend_from_slice(&bytes[..n]);
    }
}

async fn spawn_sse_mock(path: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                if !read_request(&mut stream).await {
                    return;
                }
                // Each test uses its own listener and configured URL.
                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                if stream.write_all(headers.as_bytes()).await.is_err() { return; }
                let line = if path == "/responses" {
                    "data: {\"type\":\"response.output_text.delta\",\"delta\":\"café ☕\"}\n\n"
                } else {
                    "data: {\"choices\":[{\"delta\":{\"content\":\"café ☕\"}}]}\n\n"
                };
                // Split within the two-byte UTF-8 sequence for é; distinct HTTP chunks are
                // flushed so the upstream transport cannot coalesce the test fixture writes.
                let bytes = line.as_bytes();
                let split = bytes.windows(2).position(|w| w == "é".as_bytes()).unwrap() + 1;
                for part in [&bytes[..split], &bytes[split..]] {
                    let framing = format!("{:X}\r\n", part.len());
                    if stream.write_all(framing.as_bytes()).await.is_err()
                        || stream.write_all(part).await.is_err()
                        || stream.write_all(b"\r\n").await.is_err()
                        || stream.flush().await.is_err()
                    {
                        return;
                    }
                }
                let done = b"data: [DONE]\n\n";
                let framing = format!("{:X}\r\n", done.len());
                let _ = stream.write_all(framing.as_bytes()).await;
                let _ = stream.write_all(done).await;
                let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                let _ = stream.flush().await;
            });
        }
    });
    (addr, handle)
}

async fn guest_session(app: &Router) -> (String, String) {
    let response = app.clone().oneshot(Request::builder().method(Method::GET).uri("/").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = response.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).map(common::extract_cookie).expect("session cookie");
    let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let csrf = Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).unwrap()
        .captures(std::str::from_utf8(&body).unwrap()).and_then(|c| c.get(1).map(|m| m.as_str().to_owned())).expect("csrf token");
    (cookie, csrf)
}

async fn chat(kind: &str, tool_aware: bool) {
    let path = if kind == "xai" { "/responses" } else { "/chat/completions" };
    let (addr, mock) = spawn_sse_mock(path).await;
    let base = format!("http://{addr}/v1");
    let _workspace = common::TestWorkspace::with_config(&provider_config(kind, &base));
    env::set_var("SECRET_KEY", "provider_sse_utf8_secret");
    if kind == "xai" {
        env::set_var("XAI_API_KEY", "test-key");
    }
    if tool_aware {
        env::set_var("BRAVE_API_KEY", "test-brave-key");
        env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "fixture results");
    }

    let app = build_router(resolve_static_root());
    let (cookie, csrf) = guest_session(&app).await;
    let response = app.clone().oneshot(Request::builder()
        .method(Method::POST)
        .uri("/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf)
        .header(header::COOKIE, cookie)
        .body(Body::from(serde_json::to_vec(&json!({
            "message": "say hello",
            "set_name": "default",
            "model_name": "default",
            "web_search": tool_aware,
        })).unwrap())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
    let text = String::from_utf8(body.to_vec()).expect("chat stream is UTF-8");
    mock.abort();
    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("XAI_API_KEY");
    assert!(text.contains("café ☕"), "expected intact multibyte delta, got: {text}");
    assert!(!text.contains('\u{FFFD}'), "replacement character in stream: {text}");
}

#[tokio::test]
async fn openai_plain_stream_preserves_split_utf8() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    chat("openai", false).await;
}

#[tokio::test]
async fn xai_responses_stream_preserves_split_utf8() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    chat("xai", false).await;
}

#[tokio::test]
async fn openai_tool_aware_stream_preserves_split_utf8() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    chat("openai", true).await;
}
