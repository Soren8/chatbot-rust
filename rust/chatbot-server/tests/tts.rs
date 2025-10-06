use std::env;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chatbot_core::bridge;
use chatbot_server::{build_router, resolve_static_root};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::Regex;
use serde_json::json;
use tower::ServiceExt;

mod common;

static META_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn ensure_base_config(py: Python<'_>) {
    let code = std::ffi::CString::new(
        r#"
from app.config import Config

Config.TTS_BASE_URL = 'http://tts.test'
"#,
    )
    .expect("c string");

    py.run(code.as_c_str(), None, None)
        .expect("configure base config");
}

#[tokio::test]
async fn tts_returns_wav_audio() {
    if !common::ensure_flask_available() {
        eprintln!("skipping tts_returns_wav_audio: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    bridge::initialize_python().expect("python bridge init");

    Python::with_gil(|py| {
        ensure_base_config(py);

        let code = std::ffi::CString::new(
            r#"
from app import tts
import requests

class _FakeResponse:
    def __init__(self, status_code=200, content=b'\x00\x01', payload=None):
        self.status_code = status_code
        self.content = content
        self._payload = payload or {}

    def json(self):
        return self._payload

def _fake_post(url, json=None, timeout=None):
    tts._TEST_LAST_TTS_PAYLOAD = {
        'url': url,
        'json': json,
        'timeout': timeout,
    }
    return _FakeResponse()

requests.post = _fake_post
tts.requests.post = _fake_post
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, None)
            .expect("install tts stub");
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

    let body_bytes = axum::body::to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let cookie_value = common::extract_cookie(&set_cookie);

    let tts_payload = json!({"text": "Hello <think>ignore</think>"});

    let tts_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&tts_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts response");

    assert_eq!(tts_response.status(), StatusCode::OK);
    assert_eq!(
        tts_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("audio/wav"),
    );

    let disposition = tts_response
        .headers()
        .get("Content-Disposition")
        .and_then(|value| value.to_str().ok())
        .expect("content disposition header");
    assert!(disposition.contains("tts.wav"));

    let wav_bytes = axum::body::to_bytes(tts_response.into_body(), 512 * 1024)
        .await
        .expect("read wav body");
    assert!(!wav_bytes.is_empty(), "wav body should not be empty");

    Python::with_gil(|py| {
        let locals = pyo3::types::PyDict::new(py);
        let code = std::ffi::CString::new(
            r#"
from app import tts
payload = getattr(tts, '_TEST_LAST_TTS_PAYLOAD', None)
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, Some(&locals))
            .expect("read stub payload");

        let payload_any = locals
            .get_item("payload")
            .expect("payload lookup")
            .expect("payload None");
        let payload_dict = payload_any
            .downcast::<pyo3::types::PyDict>()
            .expect("payload dict");

        let url: String = payload_dict
            .get_item("url")
            .expect("url lookup")
            .expect("url missing")
            .extract()
            .expect("extract url");
        assert_eq!(url, "http://tts.test/api/tts");

        let json_any = payload_dict
            .get_item("json")
            .expect("json lookup")
            .expect("json missing");
        let json_dict = json_any
            .downcast::<pyo3::types::PyDict>()
            .expect("json dict");

        let text: String = json_dict
            .get_item("text")
            .expect("text lookup")
            .expect("text missing")
            .extract()
            .expect("extract text");
        assert_eq!(text, "Hello");

        let timeout: i64 = payload_dict
            .get_item("timeout")
            .expect("timeout lookup")
            .expect("timeout missing")
            .extract()
            .expect("extract timeout");
        assert_eq!(timeout, 30);
    });
}

#[tokio::test]
async fn tts_returns_error_when_service_fails() {
    if !common::ensure_flask_available() {
        eprintln!("skipping tts_returns_error_when_service_fails: flask not available");
        return;
    }
    common::init_tracing();

    env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    bridge::initialize_python().expect("python bridge init");

    Python::with_gil(|py| {
        ensure_base_config(py);

        let code = std::ffi::CString::new(
            r#"
from app import tts
import requests

class _FakeResponse:
    def __init__(self, status_code=500, content=b'', payload=None):
        self.status_code = status_code
        self.content = content
        self._payload = payload or {'error': 'backend unavailable'}

    def json(self):
        return self._payload

def _fake_post(url, json=None, timeout=None):
    return _FakeResponse()

requests.post = _fake_post
tts.requests.post = _fake_post
"#,
        )
        .expect("c string");

        py.run(code.as_c_str(), None, None)
            .expect("install failing tts stub");
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

    let set_cookie = home_response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie present")
        .to_owned();

    let body_bytes = axum::body::to_bytes(home_response.into_body(), 256 * 1024)
        .await
        .expect("read home body");
    let body_text = std::str::from_utf8(&body_bytes).expect("home utf8");
    let csrf_token = META_TOKEN_RE
        .captures(body_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token in page");

    let cookie_value = common::extract_cookie(&set_cookie);

    let tts_payload = json!({"text": "Failure case"});

    let tts_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", &csrf_token)
                .header(header::COOKIE, &cookie_value)
                .body(Body::from(
                    serde_json::to_vec(&tts_payload).expect("payload bytes"),
                ))
                .unwrap(),
        )
        .await
        .expect("POST /tts response");

    assert_eq!(tts_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let content_type = tts_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content type");
    assert!(content_type.contains("application/json"));

    let body_bytes = axum::body::to_bytes(tts_response.into_body(), 128 * 1024)
        .await
        .expect("read error body");
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json body");
    assert_eq!(payload["error"], "TTS generation failed");
}
