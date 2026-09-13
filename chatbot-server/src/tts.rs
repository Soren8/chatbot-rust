use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::{
    body::{self, Body},
    extract::Path,
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{
    config::{self, TtsAccess},
    session,
    user_store::UserStore,
};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error};

use crate::http_error::{
    api_error, map_body_read_err, map_json_parse_err, map_response_build_err,
    map_serialization_err, map_session_err, map_user_store_err, HttpError,
};
use crate::tts_opus;

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_TTS_AUDIO_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_TTS: usize = 128;
const TTS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_TTS_REPLAYS: u8 = 2;
const SAMPLE_RATE_HZ: u32 = 25_200;
const CHANNELS: u16 = 1;
const BITS_PER_SAMPLE: u16 = 16;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?s)<think>.*?</think>").expect("valid think regex"));

static EMOJI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\p{Emoji_Presentation}\p{Extended_Pictographic}\u{200d}\u{FE0F}]")
        .expect("valid emoji regex")
});

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://[^\s]+|www\.[^\s]+").expect("valid url regex")
});

// Matches citation markers like [1], [2], [[1]], [[2]] (with optional surrounding whitespace)
static CITATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[?\[(\d+)\]\]?").expect("valid citation regex")
});

// ~100 / ≈100 -> "about 100"
static APPROX_NUMBER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[~≈][ \t]*(\d[\d,]*)").expect("valid approx number regex"));

// Tight-coupled magnitude suffixes: 10k / 2.5M / 2B / 4bn -> thousand/million/billion
static MAGNITUDE_SUFFIX_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\d[\d,]*(?:\.\d+)?)(bn|b|m|k)\b").expect("valid magnitude suffix regex")
});

// Dotted numbers read wrong by TTS (3.6 sounds like a sentence end): spell as words
static DECIMAL_NUMBER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d[\d,]*(?:\.\d+)+\b").expect("valid decimal number regex"));

// Standalone two-digit integers read smoother as words ("fifty eight"). The
// token grab includes comma groups so 25,000 is never split mid-number.
static INTEGER_TOKEN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d+(?:,\d+)*)\b").expect("valid integer token regex"));

// Matches currency with magnitude words or suffixes: $12.6 billion, $12.6B, €5M, £10k, $12.6 billion dollars
static CURRENCY_MAGNITUDE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*(?:\.\d+)?)\s*(trillion|billion|million|thousand|bn|b|m|k)\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency magnitude regex")
});

// Matches cents-only currency: $0.50, $0.01, €0.75, £0.25
static CURRENCY_CENTS_ONLY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*0\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency cents only regex")
});

// Matches currency with decimal cents: $12.50, $1.00, €5.20, £2.50
static CURRENCY_DECIMAL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*)\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency decimal regex")
});

// Matches integer currency amounts: $5, $1, $100,000, €1, £5
static CURRENCY_INT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)([\$€£])\s*(\d[\d,]*)\b(?:\s*(dollars?|euros?|pounds?))?")
        .expect("valid currency int regex")
});

// Matches dotted initialisms like U.S., U.S.A., A.I., D.C., Ph.D.
static DOTTED_INITIALISM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Z][a-z]?)\.([A-Z][a-z]?)\.(?:([A-Z][a-z]?)\.)*")
        .expect("valid dotted initialism regex")
});

// Common Latin abbreviations: e.g., i.e., etc., vs.
static EG_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\be\.g\.,?\s*").expect("valid eg regex"));
static IE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bi\.e\.,?\s*").expect("valid ie regex"));
static ETC_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\betc(?:\.|\b)").expect("valid etc regex"));
static VS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bvs(?:\.|\b)").expect("valid vs regex"));

// Titles/honorifics
static TITLES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(Dr|Mr|Mrs|Ms|Prof|Sr|Jr|Gen|Col|Sgt|Lt|Capt)\.\s*")
        .expect("valid titles regex")
});

// Common shortened words
static ABBREV_WORDS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(approx|dept|apt|est|govt|corp|inc|ltd|co)\.\s*")
        .expect("valid abbrev words regex")
});

// Time: 10 a.m. / 10 p.m.
static AM_PM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(\d+)\s*([ap])\.m\.\b").expect("valid am pm regex")
});

// Percentage: 58% -> 58 percent
static PERCENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*%").expect("valid percent regex")
});

// Ampersand between words: AT&T -> AT and T
static AMPERSAND_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\s*&\s*(\w+)").expect("valid ampersand regex")
});

// Number sign before digits: #1 -> number 1
static NUMBER_SIGN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#(\d+)\b").expect("valid number sign regex")
});

// Temperature / angle degrees: 20°C -> 20 degrees Celsius, 70°F -> 70 degrees Fahrenheit
static DEGREE_C_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°C\b").expect("valid degree c regex")
});
static DEGREE_F_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°F\b").expect("valid degree f regex")
});
static DEGREE_SYMBOL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d+(?:\.\d+)?)\s*°\b").expect("valid degree regex")
});

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

/// Final wire bytes for one TTS clip, in whatever codec the config selects.
/// Cached verbatim for replays so synthesis and encoding both happen once.
#[derive(Debug, Clone)]
struct TtsWireAudio {
    bytes: Vec<u8>,
    content_type: String,
    filename: String,
}

struct PendingTts {
    text: String,
    audio: Option<TtsWireAudio>,
    created_at: Instant,
    replay_count: u8,
    generating: bool,
}

static PENDING_TTS: Lazy<RwLock<HashMap<String, PendingTts>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Deserialize)]
struct ApiTtsRequest {
    #[serde(default)]
    text: Option<String>,
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

pub async fn handle_tts(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
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

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "tts::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let username = ensure_tts_access(cookie_header.as_deref())?;
    let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);

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
    
    let inserted = {
        let mut map = PENDING_TTS.write().expect("tts lock");
        insert_pending_tts(
            &mut map,
            token.clone(),
            PendingTts {
                text: cleaned,
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        )
    };
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

struct GeneratingGuard<'a> {
    token: &'a str,
    active: bool,
}

impl<'a> Drop for GeneratingGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut map) = PENDING_TTS.write() {
                if let Some(pending) = map.get_mut(self.token) {
                    pending.generating = false;
                }
            }
        }
    }
}

pub async fn handle_tts_stream(
    Path(token): Path<String>,
) -> Result<Response<Body>, HttpError> {
    let (cleaned, cached_audio, _created_at) = {
        let mut map = PENDING_TTS.write().expect("tts lock");
        prune_pending_tts(&mut map);
        let pending = map.get_mut(&token).ok_or_else(|| {
            debug!(token = %token, "invalid or expired TTS token");
            api_error(StatusCode::NOT_FOUND, "Invalid or expired token")
        })?;
        let created_at = pending.created_at;
        if let Some(audio) = pending.audio.clone() {
            if pending.replay_count >= MAX_TTS_REPLAYS {
                map.remove(&token);
                return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
            }
            pending.replay_count += 1;
            (String::new(), Some(audio), created_at)
        } else {
            if pending.generating {
                return Err(api_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "TTS generation already in progress",
                ));
            }
            pending.generating = true;
            (pending.text.clone(), None, created_at)
        }
    };

    if let Some(audio) = cached_audio {
        return build_tts_audio_response(audio);
    }

    let mut generating_guard = GeneratingGuard {
        token: &token,
        active: true,
    };

    let result = synthesize_tts_stream(cleaned.clone()).await;
    match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("audio/ogg;codecs=opus")
                .to_string();
            let filename = if content_type.contains("opus") {
                "tts.opus".to_string()
            } else {
                "tts.wav".to_string()
            };
            let audio = match body::to_bytes(body, MAX_TTS_AUDIO_BYTES).await {
                Ok(bytes) => TtsWireAudio {
                    bytes: bytes.to_vec(),
                    content_type,
                    filename,
                },
                Err(err) => {
                    generating_guard.active = false;
                    let mapped = map_body_read_err(err, "tts::stream::cache");
                    let mut map = PENDING_TTS.write().expect("tts lock");
                    if let Some(pending) = map.get_mut(&token) {
                        pending.generating = false;
                    }
                    return Err(mapped);
                }
            };
            generating_guard.active = false;
            let mut map = PENDING_TTS.write().expect("tts lock");
            if let Some(pending) = map.get_mut(&token) {
                pending.text.clear();
                pending.audio = Some(audio.clone());
                pending.replay_count = 0;
                pending.generating = false;
            }
            Ok(Response::from_parts(parts, Body::from(audio.bytes)))
        }
        Err(err) => {
            generating_guard.active = false;
            let mut map = PENDING_TTS.write().expect("tts lock");
            if let Some(pending) = map.get_mut(&token) {
                pending.generating = false;
            }
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
    let cookie_header = parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());
    let csrf_token = parts
        .headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());
    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "tts::cancel::csrf"))?;
    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let mut map = PENDING_TTS.write().expect("tts lock");
    map.remove(&token);
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "tts::cancel"))?)
}

fn prune_pending_tts(map: &mut HashMap<String, PendingTts>) {
    map.retain(|_, pending| pending.created_at.elapsed() <= TTS_TOKEN_TTL);
}

fn insert_pending_tts(
    map: &mut HashMap<String, PendingTts>,
    token: String,
    pending: PendingTts,
) -> bool {
    prune_pending_tts(map);
    if !map.contains_key(&token) && map.len() >= MAX_PENDING_TTS {
        let oldest_cached = map
            .iter()
            .filter(|(_, pending)| pending.audio.is_some() && !pending.generating)
            .min_by_key(|(_, pending)| pending.created_at)
            .map(|(token, _)| token.clone());
        if let Some(oldest) = oldest_cached {
            map.remove(&oldest);
        } else {
            let stale_ungenerated = map
                .iter()
                .filter(|(_, pending)| {
                    pending.audio.is_none()
                        && !pending.generating
                        && pending.created_at.elapsed() >= Duration::from_secs(60)
                })
                .min_by_key(|(_, pending)| pending.created_at)
                .map(|(token, _)| token.clone());
            if let Some(stale) = stale_ungenerated {
                map.remove(&stale);
            } else {
                return false;
            }
        }
    }
    map.insert(token, pending);
    true
}

async fn synthesize_tts_stream(cleaned: String) -> Result<Response<Body>, HttpError> {
    if cleaned.is_empty() {
        return build_tts_audio_response(encode_tts_wire_audio(&SILENT_PCM, SAMPLE_RATE_HZ)?);
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

    build_tts_audio_response(encode_tts_wire_audio(&bytes, SAMPLE_RATE_HZ)?)
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

/// Enforce deploy-time `tts_access` policy. Returns a log label (username or "guest").
fn ensure_tts_access(cookie_header: Option<&str>) -> Result<String, HttpError> {
    let username = session::session_context(cookie_header)
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
            let store = UserStore::new().map_err(|err| {
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

async fn handle_fish_speech(text: String) -> Result<Response<Body>, HttpError> {
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
    build_tts_audio_response(encode_tts_wire_audio(pcm, rate)?)
}

async fn handle_kokoro_tts(
    text: String,
    config: &config::AppConfig,
) -> Result<Response<Body>, HttpError> {
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
    build_tts_audio_response(encode_tts_wire_audio(&bytes, sample_rate)?)
}

const DIGIT_WORDS: [&str; 10] = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
];
const TEEN_WORDS: [&str; 10] = [
    "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
    "eighteen", "nineteen",
];
const TENS_WORDS: [&str; 10] = [
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
];

/// Spells an integer 0..=999 as English words ("205" -> "two hundred five").
fn small_integer_to_words(n: u32) -> String {
    match n {
        0..=9 => DIGIT_WORDS[n as usize].to_string(),
        10..=19 => TEEN_WORDS[(n - 10) as usize].to_string(),
        20..=99 => {
            let ones = n % 10;
            let tens = format!("{}", TENS_WORDS[(n / 10) as usize]);
            if ones == 0 {
                tens
            } else {
                format!("{tens} {}", DIGIT_WORDS[ones as usize])
            }
        }
        _ => {
            let hundreds = format!("{} hundred", DIGIT_WORDS[(n / 100) as usize]);
            let rest = n % 100;
            if rest == 0 {
                hundreds
            } else {
                format!("{hundreds} {}", small_integer_to_words(rest))
            }
        }
    }
}

/// Spells an unsigned integer up to trillions as English words ("12000" -> "twelve thousand").
fn integer_to_words(n: u64) -> String {
    if n <= 999 {
        return small_integer_to_words(n as u32);
    }
    let mut parts = Vec::new();
    let trillions = n / 1_000_000_000_000;
    let billions = (n % 1_000_000_000_000) / 1_000_000_000;
    let millions = (n % 1_000_000_000) / 1_000_000;
    let thousands = (n % 1_000_000) / 1_000;
    let remainder = n % 1000;

    if trillions > 0 {
        parts.push(format!("{} trillion", small_integer_to_words(trillions as u32)));
    }
    if billions > 0 {
        parts.push(format!("{} billion", small_integer_to_words(billions as u32)));
    }
    if millions > 0 {
        parts.push(format!("{} million", small_integer_to_words(millions as u32)));
    }
    if thousands > 0 {
        parts.push(format!("{} thousand", small_integer_to_words(thousands as u32)));
    }
    if remainder > 0 {
        parts.push(small_integer_to_words(remainder as u32));
    }
    parts.join(" ")
}

/// Spells a standalone two-digit integer ("58" -> "fifty eight"); leaves
/// everything else alone.
fn two_digit_number_to_words(raw: &str) -> Option<String> {
    let n: u32 = raw.parse().ok()?;
    if !(10..=99).contains(&n) {
        return None;
    }
    Some(small_integer_to_words(n))
}

fn expand_decimal_token(raw: &str) -> String {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() == 2 {
        let int_clean = parts[0].replace(',', "");
        let int_spoken = if let Ok(n) = int_clean.parse::<u64>() {
            integer_to_words(n)
        } else {
            parts[0]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
                .collect::<Vec<_>>()
                .join(" ")
        };

        let frac_spoken = parts[1]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
            .collect::<Vec<_>>()
            .join(" ");

        format!("{int_spoken} point {frac_spoken}")
    } else {
        parts
            .iter()
            .map(|part| {
                let clean = part.replace(',', "");
                if let Ok(n) = clean.parse::<u64>() {
                    integer_to_words(n)
                } else {
                    part.chars()
                        .filter(|c| c.is_ascii_digit())
                        .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            })
            .collect::<Vec<_>>()
            .join(" point ")
    }
}

fn currency_name(symbol: &str, plural: bool) -> &'static str {
    match symbol {
        "$" => if plural { "dollars" } else { "dollar" },
        "€" => if plural { "euros" } else { "euro" },
        "£" => if plural { "pounds" } else { "pound" },
        _ => if plural { "dollars" } else { "dollar" },
    }
}

fn cents_name(symbol: &str, cents: u32) -> String {
    if symbol == "£" {
        if cents == 1 {
            "1 penny".to_string()
        } else {
            format!("{cents} pence")
        }
    } else if cents == 1 {
        "1 cent".to_string()
    } else {
        format!("{cents} cents")
    }
}

fn expand_currency(input: &str) -> String {
    // 1. Currency with magnitudes: $12.6 billion, $12.6B, $12.6 billion dollars
    let with_mag = CURRENCY_MAGNITUDE_REGEX.replace_all(input, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let amount = caps[2].replace(',', "");
        let mag_raw = caps[3].to_ascii_lowercase();
        let mag_word = match mag_raw.as_str() {
            "k" | "thousand" => "thousand",
            "m" | "million" => "million",
            "b" | "bn" | "billion" => "billion",
            "trillion" => "trillion",
            _ => mag_raw.as_str(),
        };
        let curr_word = currency_name(symbol, true);
        format!("{amount} {mag_word} {curr_word}")
    });

    // 2. Cents-only amounts: $0.50, $0.01
    let with_cents = CURRENCY_CENTS_ONLY_REGEX.replace_all(&with_mag, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let cents_str = &caps[2];
        let cents: u32 = match cents_str.len() {
            1 => cents_str.parse::<u32>().unwrap_or(0) * 10,
            _ => cents_str.parse::<u32>().unwrap_or(0),
        };
        cents_name(symbol, cents)
    });

    // 3. Dollars and cents: $12.50, $1.00
    let with_dec = CURRENCY_DECIMAL_REGEX.replace_all(&with_cents, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let int_str = caps[2].replace(',', "");
        let cents_str = &caps[3];
        let cents: u32 = match cents_str.len() {
            1 => cents_str.parse::<u32>().unwrap_or(0) * 10,
            _ => cents_str.parse::<u32>().unwrap_or(0),
        };
        let int_val: u64 = int_str.parse().unwrap_or(0);
        let int_unit = currency_name(symbol, int_val != 1);

        if cents == 0 {
            format!("{int_str} {int_unit}")
        } else {
            let cents_str_spoken = cents_name(symbol, cents);
            format!("{int_str} {int_unit} and {cents_str_spoken}")
        }
    });

    // 4. Integer currency amounts: $5, $1, $100,000
    let with_int = CURRENCY_INT_REGEX.replace_all(&with_dec, |caps: &regex::Captures| {
        let symbol = &caps[1];
        let amount = &caps[2];
        let clean = amount.replace(',', "");
        let val: u64 = clean.parse().unwrap_or(0);
        let unit = currency_name(symbol, val != 1);
        format!("{amount} {unit}")
    });

    with_int.into_owned()
}

fn is_at_sentence_end(rest: &str) -> bool {
    let trimmed = rest.trim_start_matches(|c: char| {
        c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '”' || c == '’'
    });
    let trimmed = trimmed.trim_start();
    trimmed.is_empty() || trimmed.starts_with(|c: char| c.is_ascii_uppercase())
}

fn expand_abbreviations(input: &str) -> String {
    // Latin abbreviations
    let s = EG_REGEX.replace_all(input, "for example ");
    let s = IE_REGEX.replace_all(&s, "that is ");
    let s = ETC_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let full_match = caps.get(0).unwrap();
        let rest = &s[full_match.end()..];
        if is_at_sentence_end(rest) {
            "etcetera."
        } else {
            "etcetera"
        }
    });
    let s = VS_REGEX.replace_all(&s, "versus");

    // Titles / honorifics
    let s = TITLES_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let title = match &caps[1] {
            "Dr" => "Doctor",
            "Mr" => "Mister",
            "Mrs" => "Missus",
            "Ms" => "Ms",
            "Prof" => "Professor",
            "Sr" => "Senior",
            "Jr" => "Junior",
            "Gen" => "General",
            "Col" => "Colonel",
            "Sgt" => "Sergeant",
            "Lt" => "Lieutenant",
            "Capt" => "Captain",
            other => other,
        };
        format!("{title} ")
    });

    // Common shortened words
    let s = ABBREV_WORDS_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let word = match caps[1].to_ascii_lowercase().as_str() {
            "approx" => "approximately",
            "dept" => "department",
            "apt" => "apartment",
            "est" => "established",
            "govt" => "government",
            "corp" => "corporation",
            "inc" => "incorporated",
            "ltd" => "limited",
            "co" => "company",
            _ => &caps[1],
        };
        format!("{word} ")
    });

    // Time: 10 a.m. / 10 p.m.
    let s = AM_PM_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let hour = &caps[1];
        let ap = caps[2].to_ascii_uppercase();
        format!("{hour} {ap}M")
    });

    // Symbols
    let s = DEGREE_C_REGEX.replace_all(&s, "$1 degrees Celsius");
    let s = DEGREE_F_REGEX.replace_all(&s, "$1 degrees Fahrenheit");
    let s = DEGREE_SYMBOL_REGEX.replace_all(&s, "$1 degrees");
    let s = PERCENT_REGEX.replace_all(&s, "$1 percent");
    let s = AMPERSAND_REGEX.replace_all(&s, "$1 and $2");
    let s = NUMBER_SIGN_REGEX.replace_all(&s, "number $1");

    // Dotted initialisms: U.S., U.S.A., A.I., D.C., Ph.D.
    // Preserves sentence terminator dot if followed by uppercase or sentence end.
    let result = DOTTED_INITIALISM_REGEX.replace_all(&s, |caps: &regex::Captures| {
        let full_match = caps.get(0).unwrap();
        let end_idx = full_match.end();
        let rest = &s[end_idx..];

        let letters: String = caps[0].chars().filter(|c| c.is_alphabetic()).collect();
        if is_at_sentence_end(rest) {
            format!("{letters}.")
        } else {
            letters
        }
    });

    result.into_owned()
}

fn expand_speech_numbers(input: &str) -> String {
    let with_about = APPROX_NUMBER_REGEX.replace_all(input, "about $1");

    let with_magnitudes = MAGNITUDE_SUFFIX_REGEX
        .replace_all(&with_about, |caps: &regex::Captures| {
            let number = caps[1].replace(',', "");
            let suffix = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            // Lowercase tight "m" is ambiguous (meters/miles/minutes vs
            // million): keep the letter, just spell the number as words.
            if suffix == "m" {
                let spoken = match number.parse::<u32>() {
                    Ok(n) if n <= 999 => small_integer_to_words(n),
                    _ => number.clone(),
                };
                return format!("{spoken} m");
            }
            let spoken = match suffix.to_ascii_lowercase().as_str() {
                "k" => "thousand",
                "m" => "million",
                "b" | "bn" => "billion",
                _ => return caps[0].to_string(),
            };
            format!("{number} {spoken}")
        })
        .into_owned();

    let expanded = DECIMAL_NUMBER_REGEX
        .replace_all(&with_magnitudes, |caps: &regex::Captures| {
            expand_decimal_token(&caps[0])
        })
        .into_owned();

    let expanded = INTEGER_TOKEN_REGEX
        .replace_all(&expanded, |caps: &regex::Captures| {
            two_digit_number_to_words(&caps[1]).unwrap_or_else(|| caps[1].to_string())
        })
        .into_owned();

    debug!(expanded_preview = ?expanded.get(..100.min(expanded.len())), "expand_speech_numbers: result");
    expanded
}

fn sanitize_text(input: &str) -> String {
    debug!(input_len = input.len(), input_preview = ?input.get(..100.min(input.len())), "sanitize_text: starting");
    
    let mut no_think = THINK_REGEX.replace_all(input, "").into_owned();
    
    // Robustness: if we still see </think>, it means the start tag was missing.
    // Strip everything up to and including the first </think>.
    if let Some(pos) = no_think.find("</think>") {
        no_think = no_think[pos + 8..].to_string();
    }

    // Remove URLs BEFORE markdown parsing so [text](url) links are handled correctly
    let url_matches: Vec<_> = URL_REGEX.find_iter(&no_think).collect();
    debug!(url_match_count = url_matches.len(), matches = ?url_matches.iter().map(|m| m.as_str()).collect::<Vec<_>>(), "sanitize_text: URL matches before stripping");
    
    let no_urls = URL_REGEX.replace_all(&no_think, "");
    debug!(no_urls_preview = ?no_urls.get(..100.min(no_urls.len())), "sanitize_text: after URL removal");

    let no_emoji = EMOJI_REGEX.replace_all(&no_urls, "");
    
    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    let parser = pulldown_cmark::Parser::new_ext(&no_emoji, options);
    
    let mut cleaned = String::with_capacity(no_emoji.len());
    for event in parser {
        match event {
            pulldown_cmark::Event::Text(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::Code(t) => cleaned.push_str(&t),
            pulldown_cmark::Event::SoftBreak | pulldown_cmark::Event::HardBreak => cleaned.push(' '),
            _ => {}
        }
    }
    
    // Strip citation markers like [1], [[2]] that survive markdown parsing
    let no_citations = CITATION_REGEX.replace_all(&cleaned, "");

    // Expand currencies: $12.6 billion -> 12.6 billion dollars, $5 -> 5 dollars
    let with_currency = expand_currency(&no_citations);

    // Expand abbreviations, initialisms (U.S. -> US, e.g. -> for example, Dr. -> Doctor)
    // and symbols (58% -> 58 percent, AT&T -> AT and T)
    let with_abbreviations = expand_abbreviations(&with_currency);

    // Expand numeric patterns TTS garbles: ~N approximations, k/m/b magnitude
    // suffixes, and dotted numbers like 12.6 ("twelve point six")
    let expanded = expand_speech_numbers(&with_abbreviations);

    // Collapse multiple spaces into one
    let collapsed = expanded.split_whitespace().collect::<Vec<_>>().join(" ");
    
    let result = collapsed.trim().to_string();
    debug!(result_preview = ?result.get(..100.min(result.len())), "sanitize_text: final result");
    if !result.chars().any(|c| c.is_alphanumeric()) {
        return String::new();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_text_strips_emojis() {
        let input = "Hello 🌟! How are you doing today? 😊 (Thinking: <think>I am a bot</think>)";
        // pulldown_cmark might collapse spaces or handle them in specific ways.
        // Let's match what it actually produces.
        let result = sanitize_text(input);
        assert!(!result.contains("🌟"));
        assert!(!result.contains("😊"));
        assert!(!result.contains("I am a bot"));
        assert!(result.contains("Hello !"));
        assert!(result.contains("How are you doing today?"));
    }

    #[test]
    fn test_sanitize_text_strips_complex_emojis() {
        let input = "Family: 👨‍👩‍👧‍👦, Flag: 🇺🇸, Rainbow: 🌈";
        let result = sanitize_text(input);
        // Ensure no leftover ZWJ or other emoji components
        assert_eq!(result, "Family: , Flag: , Rainbow:");
    }

    #[test]
    fn test_sanitize_text_does_not_strip_standard_text() {
        let input = "Text with numbers 123 and punctuation !@#$%^&*()_+-=[]{};':\",./<>?";
        let result = sanitize_text(input);
        assert_eq!(result, "Text with numbers 123 and punctuation !@#$%^&*()_+-=[]{};':\",./<>?");
    }

    #[test]
    fn test_text_between_emojis() {
        let input = "🚀 Hello 🚀 World 🚀";
        let result = sanitize_text(input);
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_sanitize_text_strips_urls() {
        let input = "Check out https://example.com and www.test.org for more info";
        let result = sanitize_text(input);
        assert!(!result.contains("https://example.com"));
        assert!(!result.contains("www.test.org"));
        assert!(result.contains("Check out"));
        assert!(result.contains("for more info"));
    }

    #[test]
    fn test_sanitize_text_strips_http_urls() {
        let input = "Visit http://old-site.net today!";
        let result = sanitize_text(input);
        assert!(!result.contains("http://old-site.net"));
        assert!(result.contains("Visit"));
        assert!(result.contains("today!"));
    }

    #[test]
    fn test_sanitize_text_strips_long_url() {
        let input = "Check this out: https://example.com/news/article-title-goes-here-123456";
        let result = sanitize_text(input);
        eprintln!("Result: '{}'", result);
        assert!(!result.contains("example.com"), "example.com should be stripped but result is: {}", result);
        assert!(!result.contains("https://"), "https:// should be stripped but result is: {}", result);
        assert!(result.contains("Check this out:"), "Check this out: should remain but result is: {}", result);
    }

    #[test]
    fn test_url_regex_matches_full_url() {
        let url = "https://example.com/news/article-title-goes-here-123456";
        let caps: Vec<_> = URL_REGEX.find_iter(url).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].as_str(), url);
    }

    #[test]
    fn test_sanitize_text_strips_citations() {
        let input = "Some fact [1] and another fact [[2]] here.";
        let result = sanitize_text(input);
        assert!(!result.contains("[1]"), "citation [1] should be stripped but result is: {}", result);
        assert!(!result.contains("[2]"), "citation [2] should be stripped but result is: {}", result);
        assert!(result.contains("Some fact"));
        assert!(result.contains("another fact"));
    }

    #[test]
    fn test_sanitize_text_strips_markdown_link_citations() {
        let input = "Check this [[1]](https://example.com/article) for details.";
        let result = sanitize_text(input);
        assert!(!result.contains("[1]"), "citation should be stripped but result is: {}", result);
        assert!(!result.contains("example.com"), "URL should be stripped but result is: {}", result);
        assert!(result.contains("Check this"));
        assert!(result.contains("for details."));
    }

    #[test]
    fn test_sanitize_text_strips_bold_and_italic() {
        let input = "This is **bold** and *italic* text.";
        let result = sanitize_text(input);
        assert!(!result.contains("**"), "bold markers should be stripped but result is: {}", result);
        assert!(!result.contains("*italic*"), "italic markers should be stripped but result is: {}", result);
        assert_eq!(result, "This is bold and italic text.");
    }

    #[test]
    fn test_sanitize_text_expands_version_numbers() {
        let input = "We upgraded to version 3.6 last week.";
        let result = sanitize_text(input);
        assert!(
            result.contains("three point six"),
            "version 3.6 should be spoken as 'three point six' but result is: {}",
            result
        );
        assert!(!result.contains("3.6"), "raw version number should be gone but result is: {}", result);
        assert!(result.trim_end().ends_with('.'), "sentence-ending period must be preserved but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_multi_part_versions() {
        let input = "The app now runs on Kotlin 1.2.3.";
        let result = sanitize_text(input);
        assert_eq!(result, "The app now runs on Kotlin one point two point three.");
    }

    #[test]
    fn test_sanitize_text_expands_two_digit_integers_only() {
        let input = "There are 200 cats, 7 birds, and 42 dogs here.";
        let result = sanitize_text(input);
        assert_eq!(result, "There are 200 cats, 7 birds, and forty two dogs here.");
    }

    #[test]
    fn test_sanitize_text_spells_teens_and_tens() {
        let input = "It took 13 days: 30 hours and 90 minutes in total.";
        let result = sanitize_text(input);
        assert_eq!(result, "It took thirteen days: thirty hours and ninety minutes in total.");
    }

    #[test]
    fn test_sanitize_text_keeps_lowercase_m_ambiguous() {
        let input = "He ran 200m today and swam 1500m yesterday.";
        let result = sanitize_text(input);
        assert!(
            result.contains("two hundred m"),
            "tight lowercase m should keep the letter with spelled words but result is: {}",
            result
        );
        assert!(!result.contains("million"), "ambiguous m must not expand to million but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_leaves_words_without_digits_alone() {
        let input = "This is a plain sentence with no numbers at all.";
        let result = sanitize_text(input);
        assert_eq!(result, "This is a plain sentence with no numbers at all.");
    }

    #[test]
    fn test_sanitize_text_expands_approximation_marker() {
        let input = "The cluster handles ~58m requests per day.";
        let result = sanitize_text(input);
        assert!(
            result.contains("about fifty eight m requests"),
            "~58m should become 'about fifty eight m' but result is: {}",
            result
        );
        assert!(!result.contains("~"), "tilde should be expanded but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_magnitude_suffixes() {
        let result = sanitize_text("The video got 10k views and the fund raised 2B dollars.");
        assert!(result.contains("ten thousand views"), "k suffix should expand but result is: {}", result);
        assert!(result.contains("2 billion dollars"), "B suffix should expand but result is: {}", result);
    }

    #[test]
    fn test_sanitize_text_expands_decimal_with_magnitude_suffix() {
        let result = sanitize_text("It reached 2.5M users.");
        assert_eq!(result, "It reached two point five million users.");
    }

    #[test]
    fn test_sanitize_text_does_not_expand_units_like_ms_or_km() {
        let input = "The lap took 45 seconds and the run was 5km long with 30ms latency noted.";
        let result = sanitize_text(input);
        assert!(result.contains("5km"), "km must not be mis-expanded but result is: {}", result);
        assert!(result.contains("30ms"), "ms must not be mis-expanded but result is: {}", result);
    }

    /// Sentence chunks that are pure markdown structure (rules, empty headings,
    /// blockquote markers, HTML, entities) sanitize to nothing. The handler
    /// must treat these as silence, not as a 500 the client cannot fix.
    #[test]
    fn test_sanitize_text_empties_for_marker_only_chunks() {
        for input in ["---", "***", "___", "#", ">", "<!-- note -->", "&nbsp;", ")", ":", ": - )", "... "] {
            assert!(
                sanitize_text(input).is_empty(),
                "{input:?} should sanitize to empty"
            );
        }
        // Normal sentences must never sanitize to empty (the silence fallback
        // must not swallow speakable text).
        for input in [
            "Hello.",
            "- a list item.",
            "## A heading.",
            "> a quote.",
            "Section divider follows.\n\n---\n\nNext section.",
        ] {
            assert!(
                !sanitize_text(input).is_empty(),
                "{input:?} must survive sanitization as speakable text"
            );
        }
    }

    #[test]
    fn test_sanitize_text_expands_dollar_currency() {
        // Twelve point six billion dollars as a whole unit, not dollar sign one two point six billion
        let result = sanitize_text("The company is valued at $12.6 billion.");
        assert_eq!(result, "The company is valued at twelve point six billion dollars.");

        // Tight B magnitude suffix
        let result = sanitize_text("They raised $12.6B in new capital.");
        assert_eq!(result, "They raised twelve point six billion dollars in new capital.");

        // Does not duplicate "dollars" if already in text
        let result = sanitize_text("Total assets reached $12.6 billion dollars.");
        assert_eq!(result, "Total assets reached twelve point six billion dollars.");

        // Standard integer amounts
        assert_eq!(sanitize_text("He paid $5 for coffee."), "He paid 5 dollars for coffee.");
        assert_eq!(sanitize_text("The fee is $1."), "The fee is 1 dollar.");
        assert_eq!(sanitize_text("It costs $1.00."), "It costs 1 dollar.");
        assert_eq!(sanitize_text("A prize of $100,000 was awarded."), "A prize of 100,000 dollars was awarded.");

        // Dollars and cents
        assert_eq!(sanitize_text("The total is $12.50."), "The total is twelve dollars and fifty cents.");
        assert_eq!(sanitize_text("The candy costs $0.50."), "The candy costs fifty cents.");
        assert_eq!(sanitize_text("It was only $0.01."), "It was only 1 cent.");
    }

    #[test]
    fn test_sanitize_text_expands_other_currencies() {
        assert_eq!(sanitize_text("The fund is €12.6 billion."), "The fund is twelve point six billion euros.");
        assert_eq!(sanitize_text("Cost was €1."), "Cost was 1 euro.");
        assert_eq!(sanitize_text("Price is £5."), "Price is 5 pounds.");
        assert_eq!(sanitize_text("Entry is £1."), "Entry is 1 pound.");
        assert_eq!(sanitize_text("Ticket costs £2.50."), "Ticket costs 2 pounds and fifty pence.");
    }

    #[test]
    fn test_sanitize_text_expands_whole_units_for_decimals() {
        let result = sanitize_text("The measurement was 12.6 meters.");
        assert_eq!(result, "The measurement was twelve point six meters.");

        let result = sanitize_text("The speed was 42.5 km.");
        assert_eq!(result, "The speed was forty two point five km.");
    }

    #[test]
    fn test_sanitize_text_normalizes_dotted_initialisms() {
        let result = sanitize_text("The U.S. government announced new guidelines.");
        assert_eq!(result, "The US government announced new guidelines.");

        let result = sanitize_text("We traveled across the U.S.A. last summer.");
        assert_eq!(result, "We traveled across the USA last summer.");

        let result = sanitize_text("He works on A.I. research in Washington, D.C.");
        assert_eq!(result, "He works on AI research in Washington, DC.");

        let result = sanitize_text("She completed her Ph.D. in physics.");
        assert_eq!(result, "She completed her PhD in physics.");

        // Preserves sentence terminator period when dotted initialism ends sentence
        let result = sanitize_text("They live in the U.S. It is warm there.");
        assert_eq!(result, "They live in the US. It is warm there.");
    }

    #[test]
    fn test_sanitize_text_expands_common_abbreviations() {
        assert_eq!(
            sanitize_text("Bring snacks, e.g. fruit or nuts."),
            "Bring snacks, for example fruit or nuts."
        );
        assert_eq!(
            sanitize_text("Pick the default, i.e. option one."),
            "Pick the default, that is option one."
        );
        assert_eq!(
            sanitize_text("Supplies include pens, pencils, etc."),
            "Supplies include pens, pencils, etcetera."
        );
        assert_eq!(
            sanitize_text("Game one is Team A vs. Team B."),
            "Game one is Team A versus Team B."
        );
        assert_eq!(
            sanitize_text("Dr. Smith met with Mr. Jones."),
            "Doctor Smith met with Mister Jones."
        );
    }

    #[test]
    fn test_sanitize_text_expands_symbols_and_percentages() {
        assert_eq!(
            sanitize_text("Profits increased by 58% this year."),
            "Profits increased by fifty eight percent this year."
        );
        assert_eq!(
            sanitize_text("She works at AT&T headquarters."),
            "She works at AT and T headquarters."
        );
        assert_eq!(
            sanitize_text("He is ranked #1 in the league."),
            "He is ranked number 1 in the league."
        );
    }

    #[test]
    fn pending_tts_capacity_does_not_evict_oldest_pending_entry() {
        let mut map = HashMap::new();
        for index in 0..MAX_PENDING_TTS {
            let token = format!("token-{index}");
            map.insert(
                token,
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        let oldest = map
            .iter()
            .min_by_key(|(_, pending)| pending.created_at)
            .map(|(token, _)| token.clone())
            .expect("full map has an oldest entry");

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert_eq!(map.len(), MAX_PENDING_TTS);
        assert!(!inserted);
        assert!(
            map.contains_key(&oldest),
            "a queued token must not be silently evicted when the cap is full"
        );
        assert!(
            !map.contains_key("new-token"),
            "a new token must be rejected when no safe cache entry can be evicted"
        );
    }
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
