use std::time::Duration;

use axum::{
    body::{self, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{config, session};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error};

const MAX_BODY_BYTES: usize = 512 * 1024;
const DEFAULT_VOICE_FILE: &str = "voices/default.wav";
const SAMPLE_RATE_HZ: u32 = 22_050;
const CHANNELS: u16 = 1;
const BITS_PER_SAMPLE: u16 = 16;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?s)<think>.*?</think>").expect("valid think regex"));

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
});

#[derive(Debug, Deserialize)]
struct ApiTtsRequest {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    voice_file: Option<String>,
}

#[derive(Debug, Serialize)]
struct BackendRequest {
    text: String,
    voice_file: String,
}

#[derive(Debug, Serialize)]
struct FishSpeechRequest {
    text: String,
    reference_id: String,
    streaming: bool,
    format: String,
}

pub async fn handle_tts(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed".into()));
    }

    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let csrf_valid =
        session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token for /tts");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token".to_string()));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase());

    let is_json = content_type
        .as_deref()
        .map(|value| value.contains("application/json"))
        .unwrap_or(false);

    if !is_json {
        return json_error(StatusCode::BAD_REQUEST, "JSON body required");
    }

    let body_bytes = body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|err| {
        error!(?err, "failed to read TTS request body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    if body_bytes.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "No text provided");
    }

    let payload: ApiTtsRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload for /tts");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let raw_text = match payload.text {
        Some(text) if !text.is_empty() => text,
        _ => return json_error(StatusCode::BAD_REQUEST, "No text provided"),
    };

    let cleaned = sanitize_text(&raw_text);
    if cleaned.is_empty() {
        debug!("sanitized /tts payload resulted in empty text");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed");
    }

    let config = config::app_config();
    debug!(provider = %config.tts_provider, "handling /tts request");
    if config.tts_provider == "fish" {
        return handle_fish_speech(cleaned).await;
    }

    debug!("using default/kokoro backend for /tts");
    let backend_request = BackendRequest {
        text: cleaned,
        voice_file: DEFAULT_VOICE_FILE.to_string(),
    };

    let response = match post_backend("/api/tts", &backend_request).await {
        Ok(response) => response,
        Err((status, message)) => {
            error!(?status, ?message, "failed to reach TTS backend for /tts");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed");
        }
    };

    let status = response.status();
    let bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read /tts backend response body");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response read error".to_string(),
        )
    })?;

    if !status.is_success() {
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "TTS backend returned error for /tts");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed");
    }

    let wav_bytes = pcm_to_wav(&bytes);

    build_audio_response(wav_bytes)
}

pub async fn handle_api_tts(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (_, body) = request.into_parts();
    let body_bytes = body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|err| {
        error!(?err, "failed to read /api/tts body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: ApiTtsRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload for /api/tts");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let backend_request = match build_backend_request(payload) {
        Ok(request) => request,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };

    let config = config::app_config();
    debug!(provider = %config.tts_provider, "handling /api/tts request");
    if config.tts_provider == "fish" {
        return handle_fish_speech(backend_request.text).await;
    }

    debug!("using default/kokoro backend for /api/tts");
    let response = post_backend("/api/tts", &backend_request).await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.map_err(|err| {
            error!(?err, "failed to read /api/tts backend error body");
            (
                StatusCode::BAD_GATEWAY,
                "TTS backend response error".to_string(),
            )
        })?;
        let message = extract_backend_error(status, &body);
        return json_error(StatusCode::BAD_GATEWAY, &message);
    }

    let pcm_bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read /api/tts backend body");
        (
            StatusCode::BAD_GATEWAY,
            "TTS backend response error".to_string(),
        )
    })?;

    let wav_bytes = pcm_to_wav(&pcm_bytes);

    build_audio_response(wav_bytes)
}

pub async fn handle_api_tts_stream(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    if request.method() != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only POST allowed".to_string(),
        ));
    }

    let (_, body) = request.into_parts();
    let body_bytes = body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|err| {
        error!(?err, "failed to read /api/tts/stream body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let payload: ApiTtsRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error!(?err, "invalid JSON payload for /api/tts/stream");
        (StatusCode::BAD_REQUEST, "Invalid JSON payload".to_string())
    })?;

    let backend_request = match build_backend_request(payload) {
        Ok(request) => request,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };

    let config = config::app_config();
    if config.tts_provider == "fish" {
         // Fish speech streaming might be handled differently, but for now we reuse the handler
         // If Fish Speech supports streaming response with the same payload, we can just use handle_fish_speech
         // but that function waits for full bytes.
         // For now, let's just use the non-streaming handler for Fish as the request has "streaming: true" in body but we might consume it fully or stream it.
         // The prompt example said "streaming: true", so maybe it returns chunked encoding.
         // Let's implement a specific stream handler for Fish if needed, or just pipe the response.
         // Given the constraints and simplicity, I'll pipe the response.
         return handle_fish_speech_stream(backend_request.text).await;
    }

    let response = post_backend("/api/tts/stream", &backend_request).await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.map_err(|err| {
            error!(?err, "failed to read /api/tts/stream backend error body");
            (
                StatusCode::BAD_GATEWAY,
                "TTS backend response error".to_string(),
            )
        })?;
        let message = extract_backend_error(status, &body);
        return json_error(StatusCode::BAD_GATEWAY, &message);
    }

    let stream = response.bytes_stream();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(
            header::CONTENT_DISPOSITION,
            "inline; filename=tts-stream.wav",
        )
        .body(Body::from_stream(stream))
        .map_err(|err| {
            error!(?err, "failed to build streaming TTS response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}

async fn handle_fish_speech(text: String) -> Result<Response<Body>, (StatusCode, String)> {
    let request = FishSpeechRequest {
        text,
        reference_id: "default".to_string(),
        streaming: false, // For non-stream endpoint, we probably want the full file
        format: "wav".to_string(),
    };

    let config = config::app_config();
    let base = config.tts_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/tts");

    debug!(url = %url, ?request, "sending request to fish speech backend");

    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach Fish Speech backend");
            (
                StatusCode::BAD_GATEWAY,
                "TTS backend unreachable".to_string(),
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        let bytes = response.bytes().await.unwrap_or_default();
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "Fish Speech backend returned error");
        return json_error(StatusCode::BAD_GATEWAY, &message);
    }

    let bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read Fish Speech response body");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response read error".to_string(),
        )
    })?;

    // Fish Speech returns WAV directly, so we don't need pcm_to_wav
    build_audio_response(bytes.to_vec())
}

async fn handle_fish_speech_stream(text: String) -> Result<Response<Body>, (StatusCode, String)> {
    let request = FishSpeechRequest {
        text,
        reference_id: "default".to_string(),
        streaming: true,
        format: "wav".to_string(),
    };

    let config = config::app_config();
    let base = config.tts_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/tts");

    debug!(url = %url, ?request, "sending request to fish speech backend");

    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach Fish Speech backend");
            (
                StatusCode::BAD_GATEWAY,
                "TTS backend unreachable".to_string(),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let bytes = response.bytes().await.unwrap_or_default();
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "Fish Speech backend returned error");
        return json_error(StatusCode::BAD_GATEWAY, &message);
    }

    let stream = response.bytes_stream();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(
            header::CONTENT_DISPOSITION,
            "inline; filename=tts-stream.wav",
        )
        .body(Body::from_stream(stream))
        .map_err(|err| {
            error!(?err, "failed to build streaming TTS response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}


fn build_backend_request(payload: ApiTtsRequest) -> Result<BackendRequest, String> {
    let raw_text = payload.text.unwrap_or_default().trim().to_owned();

    let cleaned = sanitize_text(&raw_text);

    if cleaned.is_empty() {
        return Err("No text provided".to_string());
    }

    let voice_file = payload
        .voice_file
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
        .unwrap_or_else(|| DEFAULT_VOICE_FILE.to_string());

    Ok(BackendRequest {
        text: cleaned,
        voice_file,
    })
}

fn sanitize_text(input: &str) -> String {
    THINK_REGEX.replace_all(input, "").trim().to_string()
}

async fn post_backend(
    path: &str,
    payload: &BackendRequest,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let config = config::app_config();
    let base = config.tts_base_url.trim_end_matches('/');
    let url = format!("{base}{path}");

    HTTP_CLIENT
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach TTS backend");
            (
                StatusCode::BAD_GATEWAY,
                "TTS backend unreachable".to_string(),
            )
        })
}

fn pcm_to_wav(pcm: &[u8]) -> Vec<u8> {
    let data_len = pcm.len() as u32;
    let chunk_size = 36 + data_len;
    let block_align = CHANNELS * (BITS_PER_SAMPLE / 8);
    let byte_rate = SAMPLE_RATE_HZ * block_align as u32;

    let mut buffer = Vec::with_capacity(44 + pcm.len());
    buffer.extend_from_slice(b"RIFF");
    buffer.extend_from_slice(&chunk_size.to_le_bytes());
    buffer.extend_from_slice(b"WAVE");
    buffer.extend_from_slice(b"fmt ");
    buffer.extend_from_slice(&16u32.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes());
    buffer.extend_from_slice(&CHANNELS.to_le_bytes());
    buffer.extend_from_slice(&SAMPLE_RATE_HZ.to_le_bytes());
    buffer.extend_from_slice(&byte_rate.to_le_bytes());
    buffer.extend_from_slice(&block_align.to_le_bytes());
    buffer.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    buffer.extend_from_slice(b"data");
    buffer.extend_from_slice(&data_len.to_le_bytes());
    buffer.extend_from_slice(pcm);
    buffer
}

fn build_audio_response(bytes: Vec<u8>) -> Result<Response<Body>, (StatusCode, String)> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(header::CONTENT_DISPOSITION, "inline; filename=tts.wav")
        .body(Body::from(bytes))
        .map_err(|err| {
            error!(?err, "failed to build audio response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
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

fn extract_backend_error(status: reqwest::StatusCode, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
            if !error.trim().is_empty() {
                return error.trim().to_string();
            }
        }
    }

    if let Ok(text) = std::str::from_utf8(body) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    status
        .canonical_reason()
        .unwrap_or("TTS backend error")
        .to_string()
}