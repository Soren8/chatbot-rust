//! Explicit TTS and rate-limit policy owners.
//!
//! [`RatePolicy`] selects the per-request rate budgets; [`TtsPolicy`] selects
//! TTS access, the wire codec, the synthesis inputs and the backend
//! endpoints. The two owners share no state: rate budgets and TTS policy are
//! configured independently via
//! [`crate::services::AppServices::with_rate_policy`] and
//! [`crate::services::AppServices::with_tts_policy`].
//!
//! The global handles touch neither config nor env on construction; each
//! operation reads live globals as needed. Owned handles carry explicit values
//! and never read ambient config or env. Production stays on the global (live) path.

use std::sync::Arc;

use chatbot_core::config::{app_config, TtsAccess};

/// Rate-budget handle: global or owned.
///
/// `Clone` shares one `Arc` of owned budgets. Global reads live config once
/// per call.
#[derive(Clone)]
pub struct RatePolicy {
    owned: Option<Arc<OwnedRatePolicy>>,
}

struct OwnedRatePolicy {
    per_user: u32,
    global: u32,
}

impl RatePolicy {
    /// Explicit owner: per-identity and global budgets per rolling minute
    /// (`0` disables). Touches no config or env; inputs are used as-is.
    pub fn new(per_user: u32, global: u32) -> Self {
        Self {
            owned: Some(Arc::new(OwnedRatePolicy { per_user, global })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation reads the live global as needed.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// Budgets as one pair: per-identity plus global per rolling minute.
    /// Global reads live config once per call.
    pub fn budgets(&self) -> (u32, u32) {
        match &self.owned {
            Some(owned) => (owned.per_user, owned.global),
            None => {
                let config = app_config();
                (
                    config.rate_limit_per_user_per_minute,
                    config.rate_limit_global_per_minute,
                )
            }
        }
    }
}

/// TTS policy handle: global or owned.
///
/// `Clone` shares one `Arc` of owned policy. Global resolves each operation
/// from live config on every call; synthesis inputs come from a single read
/// so model, voice and endpoint stay coherent.
#[derive(Clone)]
pub struct TtsPolicy {
    owned: Option<Arc<OwnedTtsPolicy>>,
}

struct OwnedTtsPolicy {
    access: TtsAccess,
    codec: String,
    synthesis: TtsSynthesis,
}

/// Coherent synthesis inputs from one config read: an OpenAI-compatible
/// `/audio/speech` endpoint plus the model, voice and fallback PCM rate.
#[derive(Clone, PartialEq, Eq)]
pub struct TtsSynthesis {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub voice: Option<String>,
    pub sample_rate: u32,
}

impl std::fmt::Debug for TtsSynthesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtsSynthesis")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("model", &self.model)
            .field("voice", &self.voice)
            .field("sample_rate", &self.sample_rate)
            .finish()
    }
}

impl TtsPolicy {
    /// Explicit owner for isolated routers. Configured values are supplied by
    /// the caller and are never resolved from ambient config or env.
    pub fn new(access: TtsAccess, codec: String, synthesis: TtsSynthesis) -> Self {
        Self {
            owned: Some(Arc::new(OwnedTtsPolicy {
                access,
                codec,
                synthesis,
            })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation reads the live global as needed.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// Deploy-time `tts_access` gate. Global reads live config on each call.
    pub fn access(&self) -> TtsAccess {
        match &self.owned {
            Some(owned) => owned.access,
            None => app_config().tts_access,
        }
    }

    /// Wire codec (`opus` or `wav`). Global reads live config on each call.
    pub fn codec(&self) -> String {
        match &self.owned {
            Some(owned) => owned.codec.clone(),
            None => app_config().tts_codec.clone(),
        }
    }

    /// Coherent dispatch inputs from one live config read.
    pub fn synthesis(&self) -> TtsSynthesis {
        match &self.owned {
            Some(owned) => owned.synthesis.clone(),
            None => {
                let config = app_config();
                TtsSynthesis {
                    base_url: config.tts.base_url.clone(),
                    api_key: config
                        .tts
                        .api_key
                        .clone()
                        .filter(|key| !key.trim().is_empty()),
                    model: config.tts.model_name.clone(),
                    voice: config.tts.voice.clone(),
                    sample_rate: config.tts.sample_rate,
                }
            }
        }
    }
}
