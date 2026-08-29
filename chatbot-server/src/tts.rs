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

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_TTS_AUDIO_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_TTS: usize = 32;
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

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
});

/// ~0.1 s of silence as a valid WAV. Served for payloads that sanitize to
/// nothing (e.g. a trailing `---` rule, marker-only chunks, raw HTML): a 500
/// there is deterministic, so the client retry storm cannot fix it — the
/// sentence must become a brief silence instead of a failure.
static SILENT_WAV: Lazy<Vec<u8>> = Lazy::new(|| {
    let silent_samples = (SAMPLE_RATE_HZ as usize) / 10;
    pcm_to_wav(&vec![0_u8; silent_samples * 2], SAMPLE_RATE_HZ)
});

struct PendingTts {
    text: String,
    audio: Option<Vec<u8>>,
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
    let (entry_text, entry_audio) = if cleaned.is_empty() {
        (String::new(), Some(SILENT_WAV.clone()))
    } else {
        (cleaned, None)
    };

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
                text: entry_text,
                audio: entry_audio,
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

pub async fn handle_tts_stream(
    Path(token): Path<String>,
) -> Result<Response<Body>, HttpError> {
    let (cleaned, cached_audio, created_at) = {
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
        return build_audio_response(audio);
    }

    let result = synthesize_tts_stream(cleaned.clone()).await;
    match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let audio = match body::to_bytes(body, MAX_TTS_AUDIO_BYTES).await {
                Ok(bytes) => bytes.to_vec(),
                Err(err) => {
                    let mapped = map_body_read_err(err, "tts::stream::cache");
                    let mut map = PENDING_TTS.write().expect("tts lock");
                    if let Some(pending) = map.get_mut(&token) {
                        pending.generating = false;
                    }
                    return Err(mapped);
                }
            };
            let mut map = PENDING_TTS.write().expect("tts lock");
            if let Some(pending) = map.get_mut(&token) {
                pending.text.clear();
                pending.audio = Some(audio.clone());
                pending.replay_count = 0;
                pending.generating = false;
            }
            Ok(Response::from_parts(parts, Body::from(audio)))
        }
        Err(err) => {
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
            return false;
        }
    }
    map.insert(token, pending);
    true
}

async fn synthesize_tts_stream(cleaned: String) -> Result<Response<Body>, HttpError> {
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

    let wav_bytes = pcm_to_wav(&bytes, SAMPLE_RATE_HZ);

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
            api_error(StatusCode::BAD_GATEWAY, "TTS backend unreachable")
        })?;

    let status = response.status();
    if !status.is_success() {
        let bytes = response.bytes().await.unwrap_or_default();
        let message = extract_backend_error(status, &bytes);
        error!(?status, message, "Fish Speech backend returned error");
        return Err(api_error(StatusCode::BAD_GATEWAY, message));
    }

    let bytes = response.bytes().await.map_err(|err| {
        error!(?err, "failed to read Fish Speech response body");
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "response read error")
    })?;

    build_audio_response(bytes.to_vec())
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
            api_error(StatusCode::BAD_GATEWAY, "TTS backend unreachable")
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
        return Err(api_error(StatusCode::BAD_GATEWAY, message));
    }

    apply_pcm_fade(&mut bytes, sample_rate);
    let wav_bytes = pcm_to_wav(&bytes, sample_rate);
    build_audio_response(wav_bytes)
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

/// Spells a standalone two-digit integer ("58" -> "fifty eight"); leaves
/// everything else alone.
fn two_digit_number_to_words(raw: &str) -> Option<String> {
    let n: u32 = raw.parse().ok()?;
    if !(10..=99).contains(&n) {
        return None;
    }
    Some(small_integer_to_words(n))
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
            caps[0]
                .split('.')
                .map(|part| {
                    part.chars()
                        .filter(|c| c.is_ascii_digit())
                        .map(|d| DIGIT_WORDS[d.to_digit(10).unwrap() as usize])
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join(" point ")
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

    // Expand numeric patterns TTS garbles: ~N approximations, k/m/b magnitude
    // suffixes, and dotted numbers like 3.6 ("three point six")
    let expanded = expand_speech_numbers(&no_citations);

    // Collapse multiple spaces into one
    let collapsed = expanded.split_whitespace().collect::<Vec<_>>().join(" ");
    
    let result = collapsed.trim().to_string();
    debug!(result_preview = ?result.get(..100.min(result.len())), "sanitize_text: final result");
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
        for input in ["---", "***", "___", "#", ">", "<!-- note -->", "&nbsp;"] {
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
            api_error(StatusCode::BAD_GATEWAY, "TTS backend unreachable")
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

fn build_audio_response(bytes: Vec<u8>) -> Result<Response<Body>, HttpError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/wav")
        .header(header::CONTENT_DISPOSITION, "inline; filename=tts.wav")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
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
        .unwrap_or("TTS backend error")
        .to_string()
}
