//! TTS provider synthesis returning owned audio.
//!
//! Given sanitized text, providers return raw mono 16-bit PCM plus its
//! sample rate. Token lifetime, access policy, codec conversion and HTTP
//! rendering stay in the parent module.

use std::time::Duration;

use axum::http::StatusCode;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, error};

use crate::http_error::{api_error, HttpError};
use crate::policy::TtsPolicy;

const SAMPLE_RATE_HZ: u32 = 24_000;

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
struct SpeechRequest {
    model: String,
    input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    voice: Option<String>,
    response_format: &'static str,
}

/// Synthesize through an OpenAI-compatible `POST {base_url}/audio/speech`
/// with `response_format: "pcm"`. The rate comes from `X-Sample-Rate` when
/// the provider sends it, else the configured `sample_rate`.
pub(super) async fn synthesize_pcm(
    cleaned: String,
    policy: &TtsPolicy,
) -> Result<SynthesizedPcm, HttpError> {
    if cleaned.is_empty() {
        return Ok(SynthesizedPcm {
            pcm: SILENT_PCM.clone(),
            sample_rate: SAMPLE_RATE_HZ,
        });
    }
    let synthesis = policy.synthesis();
    let url = format!("{}/audio/speech", synthesis.base_url.trim_end_matches('/'));
    debug!(url = %url, model = %synthesis.model, "sending TTS request");

    let request = SpeechRequest {
        model: synthesis.model,
        input: cleaned,
        voice: synthesis.voice,
        response_format: "pcm",
    };
    let mut builder = HTTP_CLIENT.post(&url).json(&request);
    if let Some(key) = synthesis.api_key.as_deref() {
        builder = builder.bearer_auth(key);
    }
    let response = builder.send().await.map_err(|err| {
        error!(?err, "failed to reach TTS backend");
        api_error(StatusCode::BAD_GATEWAY, "TTS backend provider unreachable")
    })?;

    let sample_rate: u32 = response
        .headers()
        .get("X-Sample-Rate")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .filter(|rate| *rate > 0)
        .unwrap_or(synthesis.sample_rate);

    let status = response.status();
    let mut bytes = response
        .bytes()
        .await
        .map_err(|err| {
            error!(?err, "failed to read TTS response body");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "response read error")
        })?
        .to_vec();

    if !status.is_success() {
        let message = extract_backend_error(status, &bytes);
        error!(?status, error_len = message.len(), "TTS backend returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, "TTS backend provider error"));
    }

    apply_pcm_fade(&mut bytes, sample_rate);
    Ok(SynthesizedPcm {
        pcm: bytes,
        sample_rate,
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
