use std::env;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

#[tokio::test]
async fn chat_endpoint_returns_stubbed_stream() {
    common::ensure_pythonpath();
    // Initialize a tracing subscriber that captures logs into an in-memory
    // buffer so we can assert no internal server errors are logged during
    // the test. We avoid calling `common::init_tracing()` here because it
    // installs a global test writer we cannot inspect.
    let log_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    {
        let make_writer_buf = log_buf.clone();
        struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut inner = self.0.lock().unwrap();
                inner.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(move || BufWriter(make_writer_buf.clone()))
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    env::set_var("SECRET_KEY", "integration_test_secret");
    let data_dir = TempDir::new().expect("temp data dir");
    env::set_var("HOST_DATA_DIR", data_dir.path());

    bridge::initialize_python().expect("python bridge init");

    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec![
            "Hello from test ".to_string(),
            "<think>plan</think>".to_string(),
            "final chunk".to_string(),
        ])
        .expect("chunk json"),
    );

    Python::with_gil(|py| {
        let code = std::ffi::CString::new(
            r#"
from app.config import Config

Config.LLM_PROVIDERS = [{
    'provider_name': 'default',
    'type': 'openai',
    'model_name': 'gpt-test',
    'base_url': 'https://api.openai.com/v1',
    'api_key': 'test-key',
    'context_size': 4096,
}]
Config.DEFAULT_LLM = Config.LLM_PROVIDERS[0]
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, None)
            .expect("configure openai provider");
    });

    // Redirect Python stderr to an in-memory buffer so we can assert no
    // Python-side tracebacks or errors were written during the request.
    Python::with_gil(|py| {
        let io = py.import("io").expect("import io");
        let sys = py.import("sys").expect("import sys");
        let stringio = io.call_method0("StringIO").expect("StringIO");
        sys.setattr("stderr", stringio).expect("redirect stderr");
    });

    // Sanity-check the python bridge module for required imports that the
    // Rust bridge expects at runtime. If these are missing (for example
    // `base64`), `chat_prepare` will raise a NameError and the server will
    // return a bridge error; fail the test early so CI surfaces this class
    // of bug immediately.
    Python::with_gil(|py| {
        let bridge = py.import("app.rust_bridge").expect("import rust_bridge");
        assert!(bridge.getattr("base64").is_ok(), "app.rust_bridge missing 'base64' import");
    });

    // Also invoke the Python `chat_prepare` entry point directly with a
    // minimal payload to ensure it does not raise during normal setup. If
    // this call raises (for example due to a missing symbol), fail the
    // test so we catch regressions in the bridge code path.
    Python::with_gil(|py| {
        let bridge = py.import("app.rust_bridge").expect("import rust_bridge");
        let payload = pyo3::types::PyDict::new(py);
        payload.set_item("message", "healthcheck").expect("set message");
        let result = bridge.call_method("chat_prepare", (py.None(), payload), None);
        assert!(result.is_ok(), "python chat_prepare raised: {:?}", result.err());
    });

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
        .expect("GET / response");

    assert_eq!(home_response.status(), StatusCode::OK);

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();

    let body_bytes = to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = CSRF_META_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let payload = json!({
        "message": "Hello",
        "system_prompt": "Test system",
        "set_name": "default",
        "model_name": "default",
    });

    let chat_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf_token)
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(
                    serde_json::to_vec(&payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /chat response");

    assert_eq!(chat_response.status(), StatusCode::OK);
    let content_type = chat_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain content-type, got {content_type}"
    );
    assert!(chat_response
        .headers()
        .get(header::TRANSFER_ENCODING)
        .is_none());

    let body_bytes = to_bytes(chat_response.into_body(), 512 * 1024)
        .await
        .expect("read chat body");
    let body_text = std::str::from_utf8(&body_bytes).expect("chat utf8");

    // Fail fast if the response indicates a bridge/server error so the
    // integration test surfaces real backend failures instead of silently
    // passing on a stubbed happy-path. Check a broad set of error
    // indicators (tracebacks, exception names, HTTP 500 markers, and
    // bridge-specific error chunks).
    let error_indicators = [
        "Error: bridge error",
        "Failed to load resource",
        "500 (Internal Server Error)",
        "Internal Server Error",
        "[Error]",
        "bridge error",
        "Traceback (most recent call last):",
        "Traceback",
        "PyErr",
        "NameError",
        "TypeError",
        "ValueError",
        "RuntimeError",
        "Exception:",
    ];

    for indicator in error_indicators {
        assert!(
            !body_text.contains(indicator),
            "chat returned error indicator '{}': {}",
            indicator,
            body_text
        );
    }

    // Also ensure no internal server errors were recorded in the log buffer
    // we installed earlier. This catches cases where the server responded
    // with HTTP 500 to an XHR/fetch (seen only in browser console) and
    // where the response body itself doesn't include the error text.
    let logs = String::from_utf8_lossy(&log_buf.lock().unwrap()).to_string();
    let log_error_indicators = ["Internal Server Error", "ERROR", "bridge error", "Traceback"]; 
    for ind in &log_error_indicators {
        assert!(
            !logs.contains(ind),
            "server logs contained error indicator '{}': {}",
            ind,
            logs
        );
    }

    // Also check the test instrumentation counter for any recorded 500s.
    // The server increments this counter whenever a 500 is built so tests
    // can detect server-side errors that may not surface in the response
    // body directly.
    let error_count = chatbot_server::test_instrumentation::take_error_count();
    assert_eq!(error_count, 0, "server emitted {} HTTP 5xx responses", error_count);

    // Inspect Python stderr for tracebacks that would indicate bridge-side
    // exceptions that may not appear in the HTTP body. Fail the test if any
    // such Python errors were recorded.
    Python::with_gil(|py| {
        let sys = py.import("sys").expect("import sys");
        let stderr = sys.getattr("stderr").expect("get stderr");
        let contents = stderr.call_method0("getvalue").expect("getvalue");
        let py_err_text: String = contents.extract().unwrap_or_default();
        assert!(
            !py_err_text.contains("Traceback"),
            "python stderr contained traceback: {}",
            py_err_text
        );
    });

    // Validate expected streamed chunks are present
    assert!(body_text.contains("Hello from test "));
    assert!(body_text.contains("<think>plan</think>"));
    assert!(body_text.contains("final chunk"));

    env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS");
}
