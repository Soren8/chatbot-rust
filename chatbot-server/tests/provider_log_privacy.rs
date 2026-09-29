mod common;

use std::{io::Write, sync::{Arc, Mutex}};

use axum::{body::{to_bytes, Body}, http::{header, Request, StatusCode}, routing::post, Router};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::json;
use tower::ServiceExt;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Self::Writer { self.clone() }
}

async fn upstream(path: &'static str, status: StatusCode, body: String) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(path, post(move || {
        let body = body.clone();
        async move { (status, [(header::CONTENT_TYPE, "text/event-stream")], body) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, handle)
}

async fn chat(base: &str, provider: &str, message: &str, search: bool) -> String {
    std::env::set_var("SECRET_KEY", "provider_log_privacy_secret");
    let config = format!("llms:\n  - provider_name: default\n    type: {provider}\n    model_name: test\n    base_url: '{base}'\n    api_key: '${{OPENAI_API_KEY}}'\n    context_size: 4096\n    rate_limit_retries: 0\n");
    let _workspace = common::TestWorkspace::with_config(&config);
    let app = build_router(resolve_static_root());
    let home = app.clone().oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = common::extract_cookie(home.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let html = to_bytes(home.into_body(), 512 * 1024).await.unwrap();
    let csrf = regex::Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#)
        .unwrap().captures(std::str::from_utf8(&html).unwrap()).unwrap()[1].to_string();
    let payload = json!({"message": message, "set_name": "default", "model_name": "default", "web_search": search});
    let response = app.oneshot(Request::builder().method("POST").uri("/chat")
        .header(header::COOKIE, cookie).header("X-CSRF-Token", csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(to_bytes(response.into_body(), 512 * 1024).await.unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn sec006_upstream_content_never_enters_logs() {
    let _lock = TEST_LOCK.lock().unwrap();
    let logs = Logs(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG)
        .with_ansi(false).with_writer(logs.clone()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let prompt = "SEC006_PRIVATE_PROMPT_4729";
    let delta = "SEC006_PRIVATE_CHUNK_8351";
    let secret = "SEC006_PRIVATE_KEY_6943";
    let error = format!("upstream echoed {prompt} and {secret}");
    for (kind, path) in [("xai", "/v1/responses"), ("openai", "/v1/chat/completions")] {
        let success = if kind == "xai" {
            format!("data: {}\n\ndata: [DONE]\n\n", json!({"type":"response.output_text.delta","delta":delta}))
        } else {
            format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"delta":{"content":delta}}]}))
        };
        let (base, task) = upstream(path, StatusCode::OK, success).await;
        let answer = chat(&base, kind, prompt, false).await;
        assert!(answer.contains(delta));
        task.abort();
        let (base, task) = upstream(path, StatusCode::BAD_REQUEST, error.clone()).await;
        let answer = chat(&base, kind, prompt, false).await;
        assert!(answer.contains("400"), "{answer}");
        assert!(!answer.contains(prompt) && !answer.contains(secret), "upstream echo must not reach client");
        task.abort();
    }
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for sentinel in [prompt, delta, secret] {
        assert!(!output.contains(sentinel), "logs contain {sentinel}");
    }
    assert!(output.contains("400"), "status missing from logs");
}

#[tokio::test]
async fn sec012_in_band_sse_error_does_not_echo_private_content() {
    let _lock = TEST_LOCK.lock().unwrap();
    let logs = Logs(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG)
        .with_ansi(false).with_writer(logs.clone()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let prompt = "SEC012_PRIVATE_PROMPT_4729";
    let secret = "SEC012_PRIVATE_KEY_6943";
    let body = format!("data: {}\n\n", json!({"error": {"message": format!("upstream echoed {prompt} and {secret}"), "code": 502}}));

    for search in [false, true] {
        if search {
            std::env::set_var("BRAVE_API_KEY", "fake-brave-key");
        }
        let (base, task) = upstream("/v1/chat/completions", StatusCode::OK, body.clone()).await;
        let answer = chat(&base, "openai", prompt, search).await;
        task.abort();
        if search {
            std::env::remove_var("BRAVE_API_KEY");
        }

        assert!(answer.contains("Error"), "in-band SSE error must terminate as error (search={search}): {answer}");
        for sentinel in [prompt, secret] {
            assert!(!answer.contains(sentinel), "client stream leaked {sentinel} (search={search}): {answer}");
        }
    }

    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for sentinel in [prompt, secret] {
        assert!(!output.contains(sentinel), "logs contain {sentinel}");
    }
}

#[tokio::test]
async fn sec006_search_query_never_enters_logs() {
    let _lock = TEST_LOCK.lock().unwrap();
    let logs = Logs(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG)
        .with_ansi(false).with_writer(logs.clone()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let query = "SEC006_PRIVATE_SEARCH_QUERY_1607";
    std::env::set_var("BRAVE_API_KEY", "fake-brave-key");
    std::env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", query);
    std::env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "fake results");
    std::env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", "[\"answer\"]");
    let result = chat("http://127.0.0.1:1/v1", "openai", "hello", true).await;
    for key in ["BRAVE_API_KEY", "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "CHATBOT_TEST_BRAVE_RESULTS", "CHATBOT_TEST_OPENAI_CHUNKS"] { std::env::remove_var(key); }
    assert!(result.contains(query), "query still shown to requesting client: {result}");
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(!output.contains(query), "search query entered tracing logs");
}
