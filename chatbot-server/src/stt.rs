use std::time::Duration;

use axum::{
    body::Body,
    extract::{FromRequest, Multipart},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{config, session};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, error};

use crate::http_error::{
    api_error, log_and_api_error, map_body_read_err, map_json_parse_err, map_response_build_err,
    map_serialization_err, map_session_err, HttpError,
};

const MAX_AUDIO_BYTES: usize = 10 * 1024 * 1024; // 10 MB

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("stt http client")
});

pub async fn handle_stt(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
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

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "stt::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    // Parse the incoming multipart form to extract the audio field
    let rebuilt = Request::from_parts(parts, Body::from(body));
    let mut multipart: Multipart = Multipart::from_request(rebuilt, &())
        .await
        .map_err(|err| {
            log_and_api_error(
                StatusCode::BAD_REQUEST,
                "invalid multipart form",
                "stt::post::multipart",
                err,
            )
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
            let data: bytes::Bytes = field
                .bytes()
                .await
                .map_err(|err| map_body_read_err(err, "stt::post::audio"))?;
            if data.len() > MAX_AUDIO_BYTES {
                return Err(api_error(StatusCode::BAD_REQUEST, "audio file too large"));
            }
            audio_data = Some(data.to_vec());
            break;
        }
    }

    let audio_bytes = audio_data
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "no 'audio' field in form"))?;

    if audio_bytes.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "No audio data provided"));
    }

    debug!(bytes = audio_bytes.len(), content_type = %audio_content_type, "forwarding audio to voice service");

    let config = config::app_config();
    let base = config.voice_service_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/stt");

    let audio_part = reqwest::multipart::Part::bytes(audio_bytes)
        .file_name(audio_file_name)
        .mime_str(&audio_content_type)
        .map_err(|err| {
            log_and_api_error(
                StatusCode::BAD_REQUEST,
                "unsupported audio format",
                "stt::post::audio_content_type",
                err,
            )
        })?;

    let form = reqwest::multipart::Form::new().part("audio", audio_part);

    let response = HTTP_CLIENT
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach voice service for STT");
            api_error(StatusCode::BAD_GATEWAY, "voice service unreachable")
        })?;

    let status = response.status();
    let body_bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read voice service STT response");
        api_error(StatusCode::BAD_GATEWAY, "voice service response error")
    })?;

    if !status.is_success() {
        let message = extract_error(status, &body_bytes);
        error!(?status, message, "voice service STT returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, message));
    }

    // The voice service returns {"text": "..."} — forward it directly
    let parsed: Value = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "stt::post::voice_response"))?;

    let out = serde_json::to_vec(&parsed)
        .map_err(|err| map_serialization_err(err, "stt::post::response"))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(out))
        .map_err(|err| map_response_build_err(err, "stt::post::response"))
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
