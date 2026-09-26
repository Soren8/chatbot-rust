use std::time::Duration;

use axum::{
    body::Body,
    extract::{FromRequest, Multipart},
    http::{header, Method, Request, Response, StatusCode},
};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::Value;
use tracing::error;

use crate::http_error::{
    api_error, api_error_json, log_and_api_error, map_body_read_err, map_encryption_key_validation_err,
    map_json_parse_err, map_response_build_err, map_serialization_err, map_session_err, HttpError,
};
use crate::services::AppServices;

pub const MAX_AUDIO_BYTES: usize = 50 * 1024 * 1024; // 50 MB

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
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    // Clone headers: parts is rebuilt into a multipart request below, but the
    // privacy binding afterwards still needs cookie/CSRF/IP inputs.
    let headers = parts.headers.clone();

    let cookie_header = crate::request_context::extract_cookie(&headers);

    let csrf_token = crate::request_context::extract_csrf(&headers);

    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
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
    let mut set_id_raw: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|n| n.to_owned());
        if name.as_deref() == Some("audio") {
            if audio_data.is_some() {
                // Drain duplicate audio fields without buffering them.
                let _ = field.bytes().await;
                continue;
            }
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
            // Do not break: a set_id metadata field may follow the audio.
        } else if name.as_deref() == Some("set_id") {
            if set_id_raw.is_none() {
                let text = field
                    .text()
                    .await
                    .map_err(|err| map_body_read_err(err, "stt::post::set_id"))?;
                if text.len() > 512 {
                    return Err(api_error(StatusCode::BAD_REQUEST, "set_id too large"));
                }
                let trimmed = text.trim().to_owned();
                if !trimmed.is_empty() {
                    set_id_raw = Some(trimmed);
                }
            }
        }
    }

    let audio_bytes = audio_data
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "no 'audio' field in form"))?;

    if audio_bytes.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "No audio data provided"));
    }

    // Info level (production RUST_LOG) so host logs always show which codec
    // arrived. If `compressed=false` the client fell back to PCM WAV (missing
    // WebCodecs, insecure context, unsupported encoder config, or encoder
    // error) — that is the signal that wire compression is not engaging.
    let compressed = !(audio_file_name.ends_with(".wav") || audio_content_type == "audio/wav");
    tracing::info!(
        bytes = audio_bytes.len(),
        content_type = %audio_content_type,
        file = %audio_file_name,
        compressed,
        "STT audio received"
    );

    // Privacy binding: the initiating conversation authorizes voice
    // dispatch. Client-supplied privacy levels never authorize anything.
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "stt::post::session",
    )?;
    let (session_context, encryption_key) = data_context.into_unverified_parts();
    let chat = services.chat().clone();
    let stt_level = services
        .config_source()
        .destination_policy()
        .map(|policy| policy.stt)
        .unwrap_or(chatbot_core::config::PrivacyLevel::NonPrivate);
    // Shared set permits are held across the single outbound voice-service
    // call so a mode change cannot slip between authorization and dispatch.
    let _stt_permit = match session_context.username.as_deref() {
        Some(user) => {
            if let Some(raw) = set_id_raw.as_deref() {
                // Bound requests read the authoritative stored mode, which
                // requires the valid per-request user key.
                let key = encryption_key.as_ref().ok_or_else(|| {
                    api_error(StatusCode::UNAUTHORIZED, "Encryption key required. Please unlock.")
                })?;
                chat.validate_encryption_key_for_user(user, Some(key))
                    .map_err(map_encryption_key_validation_err)?;
                let history = chat.history().map_err(|_| {
                    api_error(StatusCode::INTERNAL_SERVER_ERROR, "history unavailable")
                })?;
                let set_id =
                    crate::set_privacy_coordinator::resolve_content_set(&history, user, Some(raw), None, key)
                        .map_err(crate::set_privacy_coordinator::map_resolution_error)?;
                let permit = services.set_privacy().content(user, set_id).await;
                let snapshot = history
                    .load(user, set_id, key)
                    .map_err(crate::set_privacy_coordinator::map_resolution_error)?;
                if !chatbot_core::config::destination_is_eligible(snapshot.privacy_level, stt_level) {
                    return Err(api_error_json(
                        StatusCode::FORBIDDEN,
                        serde_json::json!({"error":"privacy_restricted","destination":"stt"}),
                    ));
                }
                Some(permit)
            } else {
                chat.validate_encryption_key_for_user(user, encryption_key.as_ref())
                    .map_err(map_encryption_key_validation_err)?;
                if !chatbot_core::config::destination_is_eligible(
                    chatbot_core::config::PrivacyLevel::Private,
                    stt_level,
                ) {
                    return Err(api_error_json(
                        StatusCode::FORBIDDEN,
                        serde_json::json!({"error":"privacy_restricted","destination":"stt","hint":"bind_set_id"}),
                    ));
                }
                None
            }
        }
        None => {
            if set_id_raw.is_some() {
                return Err(api_error(StatusCode::BAD_REQUEST, "set_id requires login"));
            }
            None
        }
    };

    let config = services.config_source();
    let base = config.voice_service_base_url();
    let base = base.trim_end_matches('/');
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
            api_error(StatusCode::BAD_GATEWAY, "STT backend provider unreachable")
        })?;

    let status = response.status();
    let body_bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read voice service STT response");
        api_error(StatusCode::BAD_GATEWAY, "STT backend provider error")
    })?;

    if !status.is_success() {
        let message = extract_error(status, &body_bytes);
        error!(?status, error_len = message.len(), "voice service STT returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, "STT backend provider error"));
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
        .unwrap_or("STT backend provider error")
        .to_string()
}
