use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use axum::{
    body::{self, Body},
    extract::Path,
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{config, session};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error};

const MAX_BODY_BYTES: usize = 512 * 1024;
const DEFAULT_VOICE_FILE: &str = "voices/default.wav";
const SAMPLE_RATE_HZ: u32 = 24_000;
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

static PENDING_TTS: Lazy<RwLock<HashMap<String, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));

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

    // Generate a temporary token and store the cleaned text
    let mut token_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut token_bytes);
    let token = token_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    {
        let mut map = PENDING_TTS.write().expect("tts lock");
        map.insert(token.clone(), cleaned);
    }

    // Return the token as JSON
    let payload = json!({ "token": token });
    let body = serde_json::to_vec(&payload).map_err(|err| {
        error!(?err, "failed to serialize tts token response");
        (StatusCode::INTERNAL_SERVER_ERROR, "serialization error".to_string())
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|err| {
            error!(?err, "failed to build tts token response");
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error".to_string())
        })
}

pub async fn handle_tts_stream(
    Path(token): Path<String>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let cleaned = {
        let mut map = PENDING_TTS.write().expect("tts lock");
        map.remove(&token).ok_or_else(|| {
            debug!(token = %token, "invalid or expired TTS token");
            (StatusCode::NOT_FOUND, "Invalid or expired token".to_string())
        })?
    };

    let config = config::app_config();
    debug!(provider = %config.tts_provider, "handling /tts_stream request");
    if config.tts_provider == "fish" {
        return handle_fish_speech(cleaned).await;
    }

    debug!("using default/kokoro backend for /tts_stream");
    let backend_request = BackendRequest {
        text: cleaned,
        voice_file: DEFAULT_VOICE_FILE.to_string(),
    };

    // We use the non-streaming endpoint to get the full bytes so we can apply a fade
    let response = match post_backend("/api/tts", &backend_request).await {
        Ok(response) => response,
        Err((status, message)) => {
            error!(?status, ?message, "failed to reach TTS backend for /tts_stream");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed");
        }
    };

    let status = response.status();
    let mut bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read /tts_stream backend response body");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response read error".to_string(),
        )
    })?.to_vec();

    if !status.is_success() {
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "TTS backend returned error for /tts_stream");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed");
    }

    // Check for RIFF header and strip it if present to get raw PCM
    if bytes.len() >= 44 && &bytes[0..4] == b"RIFF" {
        debug!("stripping existing WAV header from backend response");
        bytes = bytes.split_off(44);
    }

    // Apply a tiny fade to the PCM data to eliminate clicks
    apply_pcm_fade(&mut bytes, SAMPLE_RATE_HZ);

    let wav_bytes = pcm_to_wav(&bytes);

    build_audio_response(wav_bytes)
}

fn apply_pcm_fade(pcm: &mut [u8], sample_rate: u32) {
    let fade_ms = 5;
    let fade_samples = (sample_rate as f32 * (fade_ms as f32 / 1000.0)) as usize;
    let num_samples = pcm.len() / 2;
    if num_samples < fade_samples * 2 {
        return;
    }

    for i in 0..fade_samples {
        // Fade In
        let start_bytes = [pcm[i * 2], pcm[i * 2 + 1]];
        let mut sample = i16::from_le_bytes(start_bytes);
        sample = (sample as f32 * (i as f32 / fade_samples as f32)) as i16;
        let out_bytes = sample.to_le_bytes();
        pcm[i * 2] = out_bytes[0];
        pcm[i * 2 + 1] = out_bytes[1];

        // Fade Out
        let end_idx = num_samples - 1 - i;
        let end_bytes = [pcm[end_idx * 2], pcm[end_idx * 2 + 1]];
        let mut sample = i16::from_le_bytes(end_bytes);
        sample = (sample as f32 * (i as f32 / fade_samples as f32)) as i16;
        let out_bytes = sample.to_le_bytes();
        pcm[end_idx * 2] = out_bytes[0];
        pcm[end_idx * 2 + 1] = out_bytes[1];
    }
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
    let response = post_backend("/api/tts/stream", &backend_request).await?;
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

    // For Kokoro, we need to prepend a WAV header because it returns raw PCM.
    let header_bytes = pcm_to_wav_header(0x7FFF_FFFF);
    let header_stream = futures_util::stream::once(async move {
        Ok::<_, reqwest::Error>(axum::body::Bytes::from(header_bytes))
    });
    let combined_stream = futures_util::stream::StreamExt::chain(header_stream, stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(
            header::CONTENT_DISPOSITION,
            "inline; filename=tts-stream.wav",
        )
        .body(Body::from_stream(combined_stream))
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
        streaming: false,
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
    let no_think = THINK_REGEX.replace_all(input, "");
    
    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    let parser = pulldown_cmark::Parser::new_ext(&no_think, options);
    
    let mut cleaned = String::with_capacity(no_think.len());
    for event in parser {
        match event {
            pulldown_cmark::Event::Text(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::Code(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::SoftBreak | pulldown_cmark::Event::HardBreak => cleaned.push(' '),
            _ => {}
        }
    }
    
    cleaned.trim().to_string()
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

fn pcm_to_wav_header(data_len: u32) -> Vec<u8> {
    let chunk_size = 36u32.saturating_add(data_len);
    let block_align = CHANNELS * (BITS_PER_SAMPLE / 8);
    let byte_rate = SAMPLE_RATE_HZ * block_align as u32;

    let mut buffer = Vec::with_capacity(44);
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
    buffer
}

fn pcm_to_wav(pcm: &[u8]) -> Vec<u8> {
    let data_len = pcm.len() as u32;
    let mut header = pcm_to_wav_header(data_len);
    header.extend_from_slice(pcm);
    header
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
