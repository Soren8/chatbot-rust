//! TTS provider synthesis returning owned audio.
//!
//! Given sanitized text, providers return raw mono 16-bit PCM plus its
//! sample rate. Token lifetime, access policy, codec conversion and HTTP
//! rendering stay in the parent module.

use std::time::Duration;

use axum::http::StatusCode;
use chatbot_core::config;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, error};

use crate::http_error::{api_error, HttpError};

const SAMPLE_RATE_HZ: u32 = 25_200;

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
});

/// ~0.1 s of raw PCM silence. Served for payloads that sanitize to
/// nothing (e.g. a trailing `---` rule, marker-only chunks, raw HTML): a 500
/// there is deterministic, so the client retry storm cannot fix it — the
/// sentence must become a brief silence instead of a failure.
static SILENT_PCM: Lazy<Vec<u8>> = Lazy::new(|| {
    let silent_samples = (SAMPLE_RATE_HZ as usize) / 10;
    vec![0_u8; silent_samples * 2]
});

/// Raw synthesis output: mono 16-bit PCM bytes at `sample_rate` Hz.
pub(super) struct SynthesizedPcm {
    pub(super) pcm: Vec<u8>,
    pub(super) sample_rate: u32,
}

#[derive(Debug, Serialize)]
struct BackendRequest {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    voice_file: Option<String>,
}

#[derive(Debug, Serialize)]
struct FishSpeechRequest {
    text: String,
    reference_id: String,
    streaming: bool,
    format: String,
}

#[derive(Debug, Serialize)]
struct KokoroTtsRequest {
    text: String,
    voice: String,
}

pub(super) async fn synthesize_pcm(cleaned: String) -> Result<SynthesizedPcm, HttpError> {
    if cleaned.is_empty() {
        return Ok(SynthesizedPcm {
            pcm: SILENT_PCM.clone(),
            sample_rate: SAMPLE_RATE_HZ,
        });
    }
    let config = config::app_config();
    debug!(provider = %config.tts_provider, "handling /tts_stream request");
    if config.tts_provider == "kokoro" {
        return handle_kokoro_tts(cleaned, &config).await;
    }
    // DEPRECATED: legacy external TTS provider
    if config.tts_provider == "fish" {
        return handle_fish_speech(cleaned).await;
    }

    debug!("using legacy external backend for /tts_stream");
    let backend_request = BackendRequest {
        text: cleaned,
        voice_file: config.tts_voice.clone(),
    };

    // We use the non-streaming endpoint to get the full bytes so we can apply a fade
    let response = match post_backend("/api/tts", &backend_request).await {
        Ok(response) => response,
        Err(err) => {
            error!(?err, "failed to reach TTS backend for /tts_stream");
            return Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed"));
        }
    };

    let status = response.status();
    let mut bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read /tts_stream backend response body");
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "response read error")
    })?.to_vec();

    if !status.is_success() {
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "TTS backend returned error for /tts_stream");
        return Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS generation failed"));
    }

    // Check for RIFF header and strip it if present to get raw PCM
    if bytes.len() >= 44 && &bytes[0..4] == b"RIFF" {
        debug!("stripping existing WAV header from backend response");
        bytes = bytes.split_off(44);
    }

    // Apply a tiny fade to the PCM data to eliminate clicks
    apply_pcm_fade(&mut bytes, SAMPLE_RATE_HZ);

    Ok(SynthesizedPcm {
        pcm: bytes,
        sample_rate: SAMPLE_RATE_HZ,
    })
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

async fn handle_fish_speech(text: String) -> Result<SynthesizedPcm, HttpError> {
    let request = FishSpeechRequest {
        text,
        reference_id: "default".to_string(),
        streaming: false,
        format: "wav".to_string(),
    };

    let config = config::app_config();
    let base = config.tts_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/tts");

    debug!(url = %url, "sending request to fish speech backend");

    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach Fish Speech backend");
            api_error(StatusCode::BAD_GATEWAY, "TTS backend provider unreachable")
        })?;

    let status = response.status();
    if !status.is_success() {
        let bytes = response.bytes().await.unwrap_or_default();
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "Fish Speech backend returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, "TTS backend provider error"));
    }

    let bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read Fish Speech response body");
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "response read error")
    })?;

    let (pcm, rate) = wav_pcm_and_rate(&bytes);
    Ok(SynthesizedPcm {
        pcm: pcm.to_vec(),
        sample_rate: rate,
    })
}

async fn handle_kokoro_tts(
    text: String,
    config: &config::AppConfig,
) -> Result<SynthesizedPcm, HttpError> {
    let base = config.voice_service_base_url.trim_end_matches('/');
    let url = format!("{base}/v1/tts/kokoro");

    let voice = config.tts_voice.clone().unwrap_or_else(|| "af_heart".to_string());
    let request = KokoroTtsRequest { text, voice };

    debug!(url = %url, "sending request to Kokoro TTS voice service");

    let response = HTTP_CLIENT
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "failed to reach Kokoro TTS voice service");
            api_error(StatusCode::BAD_GATEWAY, "TTS backend provider unreachable")
        })?;

    let sample_rate: u32 = response
        .headers()
        .get("X-Sample-Rate")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(24_000);

    let status = response.status();
    let mut bytes = response
        .bytes()
        .await
        .map_err(|err| {
            error!(?err, "failed to read Kokoro TTS response body");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "response read error")
        })?
        .to_vec();

    if !status.is_success() {
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "Kokoro TTS voice service returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, "TTS backend provider error"));
    }

    apply_pcm_fade(&mut bytes, sample_rate);
    Ok(SynthesizedPcm {
        pcm: bytes,
        sample_rate,
    })
}

async fn post_backend(
    path: &str,
    payload: &BackendRequest,
) -> Result<reqwest::Response, HttpError> {
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
            api_error(StatusCode::BAD_GATEWAY, "TTS backend provider unreachable")
        })
}

/// Split backend WAV bytes into raw PCM plus its declared rate. Passes
/// headerless PCM through with the default rate.
fn wav_pcm_and_rate(bytes: &[u8]) -> (&[u8], u32) {
    if bytes.len() >= 44 && &bytes[0..4] == b"RIFF" {
        let rate = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let rate = if rate > 0 { rate } else { SAMPLE_RATE_HZ };
        (&bytes[44..], rate)
    } else {
        (bytes, SAMPLE_RATE_HZ)
    }
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
        .unwrap_or("TTS backend provider error")
        .to_string()
}
