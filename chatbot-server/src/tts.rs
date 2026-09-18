use axum::{
    body::{self, Body},
    extract::{Extension, Path},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{
    account_service::AccountService,
    config::{self, TtsAccess},
};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error};

use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_response_build_err,
    map_serialization_err, map_session_err, map_user_store_err, HttpError,
};
use crate::identity::RequestIdentity;
use crate::services::AppServices;
use crate::tts_opus;

mod backend;
pub(crate) mod store;
mod text;
use store::{BeginOutcome, PendingTtsStore, TtsWireAudio};
use text::sanitize_text;

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_TTS_AUDIO_BYTES: usize = 8 * 1024 * 1024;
const CHANNELS: u16 = 1;
const BITS_PER_SAMPLE: u16 = 16;

static PENDING_TTS: Lazy<PendingTtsStore> = Lazy::new(PendingTtsStore::new);

/// Process-global pending-token store for compatibility routers. Owned
/// routers built via `build_router_with_services` use their own store from
/// `AppServices` instead; all three TTS endpoints on one router always share
/// that router's store.
pub(crate) fn global_pending_store() -> &'static PendingTtsStore {
    &PENDING_TTS
}

#[derive(Debug, Deserialize)]
struct ApiTtsRequest {
    #[serde(default)]
    text: Option<String>,
}

pub async fn handle_tts(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let headers = parts.headers;

    let cookie_header = crate::request_context::extract_cookie(&headers);

    let csrf_token = crate::request_context::extract_csrf(&headers);

    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "tts::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let username = ensure_tts_access(services.accounts(), &identity, cookie_header.as_deref())?;
    let ip = crate::request_context::get_ip(&headers, &parts.extensions);

    tracing::info!(username = %username, ip = %ip, "TTS token request");

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase());

    let is_json = content_type
        .as_deref()
        .map(|value| value.contains("application/json"))
        .unwrap_or(false);

    if !is_json {
        return Err(api_error(StatusCode::BAD_REQUEST, "JSON body required"));
    }

    let body_bytes = body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|err| map_body_read_err(err, "tts::post"))?;

    if body_bytes.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "No text provided"));
    }

    let payload: ApiTtsRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "tts::post"))?;

    let raw_text = match payload.text {
        Some(text) if !text.is_empty() => text,
        _ => return Err(api_error(StatusCode::BAD_REQUEST, "No text provided")),
    };

    debug!(raw_text_len = raw_text.len(), raw_text_preview = ?raw_text.get(..100.min(raw_text.len())), "handle_tts: received text");

    let cleaned = sanitize_text(&raw_text);
    if cleaned.is_empty() {
        tracing::warn!(
            raw_text_preview = ?raw_text.get(..100.min(raw_text.len())),
            "sanitized /tts payload is empty; streaming silence instead of failing the sentence"
        );
    }

    // Generate a temporary token and store the cleaned text
    let mut token_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut token_bytes);
    let token = token_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    let inserted = services.pending_tts().insert(token.clone(), cleaned);
    if !inserted {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "TTS queue is full; retry later",
        ));
    }

    // Return the token as JSON
    let payload = json!({ "token": token });
    let body = serde_json::to_vec(&payload)
        .map_err(|err| map_serialization_err(err, "tts::post::token_response"))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-TTS-Token", token.as_str())
        .body(Body::from(body))
        .map_err(|err| map_response_build_err(err, "tts::post::token_response"))
}

pub async fn handle_tts_stream(
    Path(token): Path<String>,
    Extension(services): Extension<AppServices>,
) -> Result<Response<Body>, HttpError> {
    let (cleaned, cached_audio, lease) = match services.pending_tts().begin(&token) {
        BeginOutcome::Cached(audio) => (String::new(), Some(audio), None),
        BeginOutcome::Begin { text, lease } => (text, None, Some(lease)),
        BeginOutcome::Busy => {
            return Err(api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "TTS generation already in progress",
            ));
        }
        BeginOutcome::Missing => {
            debug!(token = %token, "invalid or expired TTS token");
            return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
        }
        BeginOutcome::Exhausted => {
            return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
        }
    };

    if let Some(audio) = cached_audio {
        return build_tts_audio_response(audio);
    }

    let lease = lease.expect("begin without cached audio yields a generation lease");

    let result = backend::synthesize_pcm(cleaned.clone()).await;
    match result {
        Ok(clip) => {
            let audio = match encode_tts_wire_audio(&clip.pcm, clip.sample_rate) {
                Ok(audio) => audio,
                Err(err) => {
                    lease.fail();
                    return Err(err);
                }
            };
            // Apply the size cap to encoded bytes before caching for replay.
            if audio.bytes.len() > MAX_TTS_AUDIO_BYTES {
                lease.fail();
                let mapped = map_body_read_err(
                    format!("encoded TTS clip exceeds {MAX_TTS_AUDIO_BYTES} bytes"),
                    "tts::stream::cache",
                );
                return Err(mapped);
            }
            let audio = lease.complete(audio);
            build_tts_audio_response(audio)
        }
        Err(err) => {
            lease.fail();
            Err(err)
        }
    }
}

pub async fn handle_tts_cancel(
    Path(token): Path<String>,
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::DELETE {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only DELETE allowed"));
    }

    let (parts, _body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let cookie_header = crate::request_context::extract_cookie(&parts.headers);
    let csrf_token = crate::request_context::extract_csrf(&parts.headers);
    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "tts::cancel::csrf"))?;
    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    services.pending_tts().cancel(&token);
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "tts::cancel"))?)
}

/// Enforce deploy-time `tts_access` policy. Returns a log label (username or "guest").
fn ensure_tts_access(
    accounts: &AccountService,
    identity: &RequestIdentity,
    cookie_header: Option<&str>,
) -> Result<String, HttpError> {
    let username = identity
        .session_context(cookie_header)
        .ok()
        .and_then(|ctx| ctx.username);
    let label = username
        .clone()
        .unwrap_or_else(|| "guest".to_string());

    match config::app_config().tts_access {
        TtsAccess::Anyone => Ok(label),
        TtsAccess::Authenticated => {
            if username.is_none() {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "TTS requires login",
                ));
            }
            Ok(label)
        }
        TtsAccess::Premium => {
            let Some(name) = username.as_deref() else {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "TTS requires a Premium account",
                ));
            };
            let store = accounts.users().map_err(|err| {
                map_user_store_err(err, "tts::access::open_store", "Unable to check TTS access")
            })?;
            let tier = store.user_tier(name).map_err(|err| {
                map_user_store_err(err, "tts::access::user_tier", "Unable to check TTS access")
            })?;
            if !tier.eq_ignore_ascii_case("premium") {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "TTS requires a Premium account",
                ));
            }
            Ok(label)
        }
    }
}

fn pcm_to_wav_header(data_len: u32, sample_rate: u32) -> Vec<u8> {
    let chunk_size = 36u32.saturating_add(data_len);
    let block_align = CHANNELS * (BITS_PER_SAMPLE / 8);
    let byte_rate = sample_rate * block_align as u32;

    let mut buffer = Vec::with_capacity(44);
    buffer.extend_from_slice(b"RIFF");
    buffer.extend_from_slice(&chunk_size.to_le_bytes());
    buffer.extend_from_slice(b"WAVE");
    buffer.extend_from_slice(b"fmt ");
    buffer.extend_from_slice(&16u32.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes());
    buffer.extend_from_slice(&CHANNELS.to_le_bytes());
    buffer.extend_from_slice(&sample_rate.to_le_bytes());
    buffer.extend_from_slice(&byte_rate.to_le_bytes());
    buffer.extend_from_slice(&block_align.to_le_bytes());
    buffer.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    buffer.extend_from_slice(b"data");
    buffer.extend_from_slice(&data_len.to_le_bytes());
    buffer
}

fn pcm_to_wav(pcm: &[u8], sample_rate: u32) -> Vec<u8> {
    let data_len = pcm.len() as u32;
    let mut header = pcm_to_wav_header(data_len, sample_rate);
    header.extend_from_slice(pcm);
    header
}

/// Encode raw mono 16-bit PCM (`sample_rate` Hz) into the configured wire
/// codec: Ogg-Opus by default, WAV when `tts_codec: wav` is set for players
/// without an Opus decoder.
fn encode_tts_wire_audio(pcm: &[u8], sample_rate: u32) -> Result<TtsWireAudio, HttpError> {
    if config::app_config().tts_codec == "opus" {
        // chunks_exact drops a trailing odd byte; backends emit whole
        // 16-bit samples so there is never one.
        let samples: Vec<i16> = pcm
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let ogg = tts_opus::encode_pcm_to_opus_ogg(&samples, sample_rate).map_err(|err| {
            error!(?err, "opus encode of TTS clip failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "TTS encoding failed")
        })?;
        Ok(TtsWireAudio {
            bytes: ogg,
            content_type: "audio/ogg;codecs=opus".to_string(),
            filename: "tts.opus".to_string(),
        })
    } else {
        Ok(TtsWireAudio {
            bytes: pcm_to_wav(pcm, sample_rate),
            content_type: "audio/wav".to_string(),
            filename: "tts.wav".to_string(),
        })
    }
}

fn build_tts_audio_response(audio: TtsWireAudio) -> Result<Response<Body>, HttpError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, audio.content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("inline; filename={}", audio.filename),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(audio.bytes))
        .map_err(|err| map_response_build_err(err, "tts::audio_response"))
}
