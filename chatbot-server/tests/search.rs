use std::{
    env,
    sync::{Mutex, OnceLock},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
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

/// Sets the given env vars, makes a POST /chat request with web_search enabled,
/// and returns the response body text. Cleans up env vars afterwards.
async fn chat_with_search(
    brave_api_key: Option<&str>,
    tool_call_query: Option<&str>,
    brave_results: Option<&str>,
    final_chunks: &[&str],
) -> String {
    env::set_var("SECRET_KEY", "search_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    if let Some(key) = brave_api_key {
        env::set_var("BRAVE_API_KEY", key);
    } else {
        env::remove_var("BRAVE_API_KEY");
    }
    if let Some(q) = tool_call_query {
        env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", q);
    } else {
        env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    }
    if let Some(r) = brave_results {
        env::set_var("CHATBOT_TEST_BRAVE_RESULTS", r);
    } else {
        env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    }

    let chunks_json =
        serde_json::to_string(&final_chunks.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", &chunks_json);

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let home_response = app
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

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();
    let home_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let home_text = std::str::from_utf8(&home_bytes).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token");

    let payload = json!({
        "message": "What is the weather today?",
        "set_name": "default",
        "model_name": "default",
        "web_search": true,
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");

    assert_eq!(chat_response.status(), StatusCode::OK);

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap().to_owned();

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_BRAVE_RESULTS");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");

    body
}

#[tokio::test]
async fn search_emits_think_tags_and_final_answer() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let body = chat_with_search(
        Some("test-brave-key"),
        Some("weather today"),
        Some("Atlanta: 72°F, sunny"),
        &["The weather is nice today."],
    )
    .await;

    assert!(
        body.contains("<think>Searching for: weather today...</think>"),
        "expected search think tag, got: {body}"
    );
    assert!(
        body.contains("<think>Search complete.</think>"),
        "expected search complete tag, got: {body}"
    );
    assert!(
        body.contains("The weather is nice today."),
        "expected final answer chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}

#[tokio::test]
async fn search_streams_direct_answer_without_tool_call() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let body = chat_with_search(
        Some("test-brave-key"),
        None,
        None,
        &["Direct answer while search is enabled."],
    )
    .await;

    assert!(
        !body.contains("<think>Searching"),
        "direct answer should not emit search status, got: {body}"
    );
    assert!(
        body.contains("Direct answer while search is enabled."),
        "expected direct stream content, got: {body}"
    );
}

#[tokio::test]
async fn search_falls_back_to_streaming_when_brave_not_configured() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    // No BRAVE_API_KEY → brave_client() returns None → falls back to stream_chat
    let body = chat_with_search(
        None,
        None,
        None,
        &["Regular answer without search."],
    )
    .await;

    assert!(
        !body.contains("<think>Searching"),
        "no search tags expected when Brave not configured, got: {body}"
    );
    assert!(
        body.contains("Regular answer without search."),
        "expected fallback stream chunk, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}

#[tokio::test]
async fn search_skipped_when_web_search_false() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    env::set_var("SECRET_KEY", "search_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "should not be called");
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["Direct answer.".to_string()]).unwrap(),
    );

    let static_root = resolve_static_root();
    let app = build_router(static_root);

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();
    let home_bytes = to_bytes(home_response.into_body(), 256 * 1024).await.unwrap();
    let home_text = std::str::from_utf8(&home_bytes).unwrap();
    let csrf_token = CSRF_META_RE
        .captures(home_text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .unwrap();

    // web_search: false
    let payload = json!({
        "message": "Hello",
        "set_name": "default",
        "model_name": "default",
        "web_search": false,
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(chat_response.status(), StatusCode::OK);
    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap();

    assert!(
        !body.contains("<think>Searching"),
        "search should not run when web_search=false, got: {body}"
    );
    assert!(
        body.contains("Direct answer."),
        "expected regular stream chunk, got: {body}"
    );

    env::remove_var("BRAVE_API_KEY");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

async fn read_http_request(stream: &mut TcpStream) -> serde_json::Value {
    let mut reader = BufReader::new(stream);
    let mut headers = Vec::new();
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await.expect("read request header");
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        headers.extend_from_slice(&line);
    }

    let headers = String::from_utf8(headers).expect("request headers are UTF-8");
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().expect("valid content length"))
    });
    let chunked = headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });

    let body = if let Some(length) = content_length {
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await.expect("read request body");
        body
    } else if chunked {
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await.expect("read chunk size");
            let size = usize::from_str_radix(size_line.trim(), 16).expect("valid chunk size");
            if size == 0 {
                let mut trailer = String::new();
                reader.read_line(&mut trailer).await.expect("read final chunk line");
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await.expect("read chunk");
            let mut ending = [0; 2];
            reader.read_exact(&mut ending).await.expect("read chunk ending");
        }
        body
    } else {
        panic!("request has neither Content-Length nor chunked transfer encoding: {headers}");
    };

    serde_json::from_slice(&body).expect("request body is JSON")
}

async fn write_sse_response(stream: &mut TcpStream, response_body: &str) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(headers.as_bytes()).await.expect("write response headers");
    stream.write_all(response_body.as_bytes()).await.expect("write SSE response");
}

#[tokio::test]
async fn search_result_is_sent_in_real_openai_followup_request() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock address");
    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(2);
    let mock = tokio::spawn(async move {
        for index in 0..2 {
            let (stream, _) = listener.accept().await.expect("accept provider request");
            let mut stream = stream;
            let request = read_http_request(&mut stream).await;
            requests_tx.send(request).await.expect("send captured request");
            let response = if index == 0 {
                concat!(
                    "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"brave_web_search\",\"arguments\":\"{\\\"query\\\":\\\"weather today\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
                    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
                    "data: [DONE]\n\n"
                )
            } else {
                "data: {\"choices\":[{\"delta\":{\"content\":\"final answer\"}}]}\n\ndata: [DONE]\n\n"
            };
            write_sse_response(&mut stream, response).await;
        }
    });

    let previous = [
        ("CHATBOT_TEST_OPENAI_CHUNKS", env::var("CHATBOT_TEST_OPENAI_CHUNKS").ok()),
        ("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", env::var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY").ok()),
        ("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS", env::var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS").ok()),
        ("CHATBOT_TEST_BRAVE_RESULTS", env::var("CHATBOT_TEST_BRAVE_RESULTS").ok()),
        ("BRAVE_API_KEY", env::var("BRAVE_API_KEY").ok()),
    ];
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
    env::remove_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY");
    env::remove_var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "UNIQUE-BRAVE-RESULT-7f3a");
    env::set_var("BRAVE_API_KEY", "test-brave-key");
    env::set_var("SECRET_KEY", "search_test_secret");

    let config = format!(
        "llms:\n  - provider_name: \"default\"\n    type: \"openai\"\n    model_name: \"gpt-test\"\n    base_url: \"http://{addr}/v1\"\n    api_key: \"${{OPENAI_API_KEY}}\"\n    context_size: 4096\n    privacy_level: private\n"
    );
    let _workspace = common::TestWorkspace::with_config(&config);
    let app = build_router(resolve_static_root());
    let home = app.clone().oneshot(
        Request::builder().method(Method::GET).uri("/").body(Body::empty()).unwrap()
    ).await.expect("GET /");
    let cookie = home.headers().get(header::SET_COOKIE).and_then(|v| v.to_str().ok()).unwrap().to_owned();
    let home_body = to_bytes(home.into_body(), 256 * 1024).await.unwrap();
    let csrf = CSRF_META_RE.captures(std::str::from_utf8(&home_body).unwrap())
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned())).expect("csrf token");
    let response = app.oneshot(Request::builder()
        .method(Method::POST).uri("/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf)
        .header(header::COOKIE, common::extract_cookie(&cookie))
        .body(Body::from(serde_json::to_vec(&json!({
            "message": "What is the weather today?", "set_name": "default",
            "model_name": "default", "web_search": true,
        })).unwrap())).unwrap()).await.expect("POST /chat");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body_bytes).unwrap().to_owned();

    let request_one = requests_rx.recv().await.expect("first model request");
    let request_two = requests_rx.recv().await.expect("second model request");
    mock.await.expect("mock server completes two requests");

    assert!(request_one["tools"].as_array().unwrap().iter().any(|tool| {
        tool["function"]["name"] == "brave_web_search"
    }), "first request must define brave_web_search: {request_one}");
    let messages = request_two["messages"].as_array().expect("second request messages");
    assert!(messages.iter().any(|message| {
        message["role"] == "user"
            && message["content"].as_array().is_some_and(|parts| {
                let content = parts.iter().filter_map(|part| part["text"].as_str()).collect::<String>();
                content.contains("[Web search results for \"weather today\"]")
                    && content.contains("UNIQUE-BRAVE-RESULT-7f3a")
            })
    }), "second request must contain injected Brave result: {request_two}");
    assert!(messages.iter().any(|message| {
        message["role"] == "user"
            && message["content"].as_array().is_some_and(|parts| {
                parts.iter().any(|part| part["text"].as_str().is_some_and(|text| text.contains("What is the weather today?")))
            })
    }), "second request must retain original question: {request_two}");
    assert!(body.contains("final answer"), "expected final answer, got: {body}");
    assert!(body.contains("<think>Search complete.</think>"), "expected search complete marker, got: {body}");
    assert!(requests_rx.try_recv().is_err(), "exactly two model requests expected");

    for (key, value) in previous {
        if let Some(value) = value { env::set_var(key, value); } else { env::remove_var(key); }
    }
}

#[tokio::test]
async fn search_result_injected_into_augmented_messages() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    // Brave results contain a unique token we can check made it to the model
    // (visible in the augmented user message that stream_chat receives).
    // The final chunks come from CHATBOT_TEST_OPENAI_CHUNKS, so the search
    // result text itself won't appear in the response — but no error should occur
    // and the response should stream successfully.
    let body = chat_with_search(
        Some("test-brave-key"),
        Some("Rust programming language"),
        Some("Rust is a systems language focused on safety and performance."),
        &["Here is what I found about Rust."],
    )
    .await;

    assert!(
        body.contains("Here is what I found about Rust."),
        "expected final stream chunk, got: {body}"
    );
    assert!(
        body.contains("<think>Searching for: Rust programming language...</think>"),
        "expected search think tag, got: {body}"
    );
    assert_eq!(
        chatbot_server::test_instrumentation::take_error_count(),
        0,
        "no 5xx errors expected"
    );
}
