use axum::{
    body::{self, Body},
    extract::{Extension, Path},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{account_service::AccountService, config::TtsAccess};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error};

use crate::http_error::{
    api_error, api_error_json, map_body_read_err, map_encryption_key_validation_err,
    map_json_parse_err, map_response_build_err, map_serialization_err, map_session_err,
    map_user_store_err, HttpError,
};
use crate::identity::RequestIdentity;
use crate::policy::TtsPolicy;
use crate::services::AppServices;
use crate::tts_opus;

mod backend;
pub(crate) mod store;
mod text;
use store::{BeginOutcome, PendingTtsStore, TtsBinding, TtsDestination, TtsWireAudio};
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
    #[serde(default)]
    set_id: Option<String>,
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

    let username = ensure_tts_access(
        services.accounts(),
        &identity,
        cookie_header.as_deref(),
        &services.tts_policy(),
    )?;
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

    let raw_len = raw_text.len();
    debug!(text_len = raw_len, "handle_tts: received text");

    let cleaned = sanitize_text(&raw_text);
    if cleaned.is_empty() {
        tracing::warn!(
            text_len = raw_len,
            cleaned_len = cleaned.len(),
            "sanitized /tts payload is empty; streaming silence instead of failing the sentence"
        );
    }

    // Privacy binding: guests keep existing access with no guarantee; a guest
    // must not supply a set identity. Authenticated callers either bind an
    // owned set (key required) or fall back to an immutable Private context.
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "tts::post::session",
    )?;
    let (session_context, encryption_key) = data_context.into_unverified_parts();
    let chat = services.chat().clone();
    let (binding, destination) = match session_context.username.as_deref() {
        Some(user) => {
            let tts_level = services
                .config_source()
                .destination_policy()
                .map(|policy| policy.tts)
                .unwrap_or(chatbot_core::config::PrivacyLevel::NonPrivate);
            if let Some(raw) = payload.set_id.as_deref().filter(|id| !id.trim().is_empty()) {
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
                let required = snapshot.privacy_level;
                if !chatbot_core::config::destination_is_eligible(required, tts_level) {
                    return Err(api_error_json(
                        StatusCode::FORBIDDEN,
                        serde_json::json!({"error":"privacy_restricted","destination":"tts"}),
                    ));
                }
                let destination = capture_tts_destination(&services, required);
                // Release the shared permit after admission; queued tokens
                // must not hold privacy settings locked.
                drop(permit);
                (
                    TtsBinding::Set {
                        owner: crate::tts::store::normalise_tts_owner(user),
                        set_id,
                        required,
                    },
                    destination,
                )
            } else {
                chat.validate_encryption_key_for_user(user, encryption_key.as_ref())
                    .map_err(map_encryption_key_validation_err)?;
                let required = chatbot_core::config::PrivacyLevel::Private;
                if !chatbot_core::config::destination_is_eligible(required, tts_level) {
                    return Err(api_error_json(
                        StatusCode::FORBIDDEN,
                        serde_json::json!({"error":"privacy_restricted","destination":"tts","hint":"bind_set_id"}),
                    ));
                }
                let destination = capture_tts_destination(&services, required);
                (
                    TtsBinding::LegacyPrivate {
                        owner: crate::tts::store::normalise_tts_owner(user),
                    },
                    destination,
                )
            }
        }
        None => {
            if payload
                .set_id
                .as_deref()
                .is_some_and(|id| !id.trim().is_empty())
            {
                return Err(api_error(StatusCode::BAD_REQUEST, "set_id requires login"));
            }
            (
                TtsBinding::Guest,
                capture_tts_destination(
                    &services,
                    chatbot_core::config::PrivacyLevel::NonPrivate,
                ),
            )
        }
    };

    // Generate a temporary token and store the cleaned text. The decryption
    // key is never stored in the token.
    let mut token_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut token_bytes);
    let token = token_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    let inserted = services
        .pending_tts()
        .insert_bound(token.clone(), cleaned, binding, destination);
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

fn capture_tts_destination(
    services: &AppServices,
    required: chatbot_core::config::PrivacyLevel,
) -> TtsDestination {
    let policy = services.tts_policy();
    let synthesis = policy.synthesis();
    TtsDestination {
        provider: synthesis.provider,
        voice: synthesis.voice,
        voice_service_base_url: synthesis.voice_service_base_url,
        tts_base_url: policy.tts_base_url(),
        codec: policy.codec(),
        required,
    }
}

fn current_tts_destination(services: &AppServices) -> TtsDestination {
    capture_tts_destination(
        services,
        chatbot_core::config::PrivacyLevel::NonPrivate,
    )
}

fn tts_destination_unchanged(captured: &TtsDestination, current: &TtsDestination) -> bool {
    captured.provider == current.provider
        && captured.voice == current.voice
        && captured.voice_service_base_url == current.voice_service_base_url
        && captured.tts_base_url == current.tts_base_url
        && captured.codec == current.codec
}

pub async fn handle_tts_stream(
    Path(token): Path<String>,
    Extension(services): Extension<AppServices>,
) -> Result<Response<Body>, HttpError> {
    // Snapshot the binding without holding the token-map lock across await,
    // then acquire the set permit before arbitrating generation.
    let snapshot = services.pending_tts().snapshot(&token);
    let Some((binding, captured)) = snapshot else {
        debug!("invalid or expired TTS token");
        return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
    };

    // Coordinator-before-token-map order: hold the shared set permit across
    // re-fetch and synthesis so a mode change cannot slip between them.
    let _permit = match &binding {
        TtsBinding::Set { owner, set_id, .. } => {
            Some(services.set_privacy().content(owner, *set_id).await)
        }
        TtsBinding::LegacyPrivate { .. } | TtsBinding::Guest => None,
    };

    let (cleaned, cached_audio, lease, admitted_binding, admitted_destination) =
        match services.pending_tts().begin(&token) {
            BeginOutcome::Cached(audio) => {
                (String::new(), Some(audio), None, binding, captured)
            }
            BeginOutcome::Begin {
                text,
                binding,
                destination,
                lease,
            } => (text, None, Some(lease), binding, destination),
            BeginOutcome::Busy => {
                return Err(api_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "TTS generation already in progress",
                ));
            }
            BeginOutcome::Missing => {
                debug!("invalid or expired TTS token");
                return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
            }
            BeginOutcome::Exhausted => {
                return Err(api_error(StatusCode::NOT_FOUND, "Invalid or expired token"));
            }
        };

    if let Some(audio) = cached_audio {
        // Cached clips involve no new upstream send.
        return build_tts_audio_response(audio);
    }

    let lease = lease.expect("begin without cached audio yields a generation lease");

    // Revalidate the captured destination against current config and policy.
    // A mode change invalidates queued tokens, so a surviving token must
    // still be eligible; a backend reconfiguration fails closed.
    let current = current_tts_destination(&services);
    if !tts_destination_unchanged(&admitted_destination, &current) {
        lease.fail();
        services.pending_tts().cancel(&token);
        return Err(api_error_json(
            StatusCode::CONFLICT,
            serde_json::json!({"error":"tts_config_changed"}),
        ));
    }
    match &admitted_binding {
        TtsBinding::Set { .. } | TtsBinding::LegacyPrivate { .. } => {
            let tts_level = services
                .config_source()
                .destination_policy()
                .map(|policy| policy.tts)
                .unwrap_or(chatbot_core::config::PrivacyLevel::NonPrivate);
            // The admitted destination carries the required level captured at
            // POST; a swapped binding cannot relax this check.
            if !chatbot_core::config::destination_is_eligible(
                admitted_destination.required,
                tts_level,
            ) {
                lease.fail();
                services.pending_tts().cancel(&token);
                return Err(api_error_json(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({"error":"privacy_restricted","destination":"tts"}),
                ));
            }
        }
        TtsBinding::Guest => {}
    }

    // Synthesize with the admitted destination, not a newly selected backend.
    let owned_policy = crate::policy::TtsPolicy::new(
        services.tts_policy().access(),
        admitted_destination.codec.clone(),
        admitted_destination.provider.clone(),
        admitted_destination.voice.clone(),
        admitted_destination.tts_base_url.clone(),
        admitted_destination.voice_service_base_url.clone(),
    );
    let result = backend::synthesize_pcm(cleaned.clone(), &owned_policy).await;
    match result {
        Ok(clip) => {
            let audio = match encode_tts_wire_audio(
                &clip.pcm,
                clip.sample_rate,
                &admitted_destination.codec,
            ) {
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

/// Enforce the router's `tts_access` policy. Returns a log label (username or "guest").
fn ensure_tts_access(
    accounts: &AccountService,
    identity: &RequestIdentity,
    cookie_header: Option<&str>,
    policy: &TtsPolicy,
) -> Result<String, HttpError> {
    let username = identity
        .session_context(cookie_header)
        .ok()
        .and_then(|ctx| ctx.username);
    let label = username
        .clone()
        .unwrap_or_else(|| "guest".to_string());

    match policy.access() {
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

/// Encode raw mono 16-bit PCM (`sample_rate` Hz) into the router's wire
/// codec: Ogg-Opus by default, WAV when `tts_codec: wav` is set for players
/// without an Opus decoder.
fn encode_tts_wire_audio(
    pcm: &[u8],
    sample_rate: u32,
    codec: &str,
) -> Result<TtsWireAudio, HttpError> {
    if codec == "opus" {
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
