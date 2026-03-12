use std::time::Duration;

use axum::{
    body::Body,
    extract::{FromRequest, Multipart},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{config, session};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{debug, error};

const MAX_AUDIO_BYTES: usize = 10 * 1024 * 1024; // 10 MB

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("stt http client")
});

pub async fn handle_stt(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_owned());

    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok());

    let csrf_valid =
        session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token for /stt");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    if !csrf_valid {
        return json_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token");
    }

    // Parse the incoming multipart form to extract the audio field
    let rebuilt = Request::from_parts(parts, Body::from(body));
    let mut multipart: Multipart = Multipart::from_request(rebuilt, &())
        .await
        .map_err(|err| {
            error!(?err, "failed to parse multipart form for /stt");
            (StatusCode::BAD_REQUEST, "invalid multipart form".to_string())
        })?;

    let mut audio_data: Option<Vec<u8>> = None;
    let mut audio_content_type = String::from("audio/webm");
    let mut audio_file_name = String::from("audio.webm");

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|n| n.to_owned());
        if name.as_deref() == Some("audio") {
            if let Some(ct) = field.content_type() {
                audio_content_type = ct.to_owned();
            }
            if let Some(fname) = field.file_name() {
                audio_file_name = fname.to_owned();
            }
            let data: bytes::Bytes = field.bytes().await.map_err(|err| {
                error!(?err, "failed to read audio field bytes");
                (StatusCode::BAD_REQUEST, "failed to read audio data".to_string())
            })?;
            if data.len() > MAX_AUDIO_BYTES {
                return json_error(StatusCode::BAD_REQUEST, "audio file too large");
            }
            audio_data = Some(data.to_vec());
            break;
        }
    }

    let audio_bytes = audio_data
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no 'audio' field in form".to_string()))?;

    if audio_bytes.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "No audio data provided");
    }

    debug!(bytes = audio_bytes.len(), content_type = %audio_content_type, "forwarding audio to voice service");

    let config = config::app_config();
    let base = config.voice_service_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/stt");

    let audio_part = reqwest::multipart::Part::bytes(audio_bytes)
        .file_name(audio_file_name)
        .mime_str(&audio_content_type)
        .map_err(|err| {
            error!(?err, "invalid audio content-type for STT multipart");
            (StatusCode::BAD_REQUEST, "unsupported audio format".to_string())
        })?;

    let form = reqwest::multipart::Form::new().part("audio", audio_part);

    let response = HTTP_CLIENT
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach voice service for STT");
            (StatusCode::BAD_GATEWAY, "voice service unreachable".to_string())
        })?;

    let status = response.status();
    let body_bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read voice service STT response");
        (StatusCode::BAD_GATEWAY, "voice service response error".to_string())
    })?;

    if !status.is_success() {
        let message = extract_error(status, &body_bytes);
        error!(?status, message, "voice service STT returned error");
        return json_error(StatusCode::BAD_GATEWAY, &message);
    }

    // The voice service returns {"text": "..."} — forward it directly
    let parsed: Value = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse STT response JSON");
        (StatusCode::BAD_GATEWAY, "invalid response from voice service".to_string())
    })?;

    let out = serde_json::to_vec(&parsed).map_err(|err| {
        error!(?err, "failed to serialize STT response");
        (StatusCode::INTERNAL_SERVER_ERROR, "serialization error".to_string())
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(out))
        .map_err(|err| {
            error!(?err, "failed to build STT response");
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error".to_string())
        })
}

fn json_error(status: StatusCode, message: &str) -> Result<Response<Body>, (StatusCode, String)> {
    let payload = json!({ "error": message });
    let body = serde_json::to_vec(&payload).map_err(|err| {
        error!(?err, "failed to serialize error payload");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response serialization failed".to_string(),
        )
    })?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|err| {
            error!(?err, "failed to build error response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}

fn extract_error(status: reqwest::StatusCode, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(detail) = value.get("detail").and_then(|v| v.as_str()) {
            if !detail.trim().is_empty() {
                return detail.trim().to_string();
            }
        }
        if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
            if !error.trim().is_empty() {
                return error.trim().to_string();
            }
        }
    }
    status
        .canonical_reason()
        .unwrap_or("STT backend error")
        .to_string()
}
