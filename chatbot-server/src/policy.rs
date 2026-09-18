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
//! operation delegates to the existing live globals at the original call
//! site. Owned handles carry explicit values and never read ambient config
//! or env. Production stays on the global (live) path.

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
    /// each operation delegates to the live global at the original site.
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
/// so provider, voice and endpoint stay coherent.
#[derive(Clone)]
pub struct TtsPolicy {
    owned: Option<Arc<OwnedTtsPolicy>>,
}

struct OwnedTtsPolicy {
    access: TtsAccess,
    codec: String,
    provider: String,
    voice: Option<String>,
    tts_base_url: String,
    voice_service_base_url: String,
}

/// Coherent synthesis inputs from a single read: provider selection, the
/// configured voice and the voice-service endpoint. The legacy/fish backend
/// base is resolved separately via [`TtsPolicy::tts_base_url`].
#[derive(Clone, Debug)]
pub struct TtsSynthesis {
    pub provider: String,
    pub voice: Option<String>,
    pub voice_service_base_url: String,
}

impl TtsPolicy {
    /// Explicit owner: access gate plus wire codec plus synthesis provider
    /// plus voice plus both backend endpoints. Touches no config or env;
    /// inputs are used as-is.
    pub fn new(
        access: TtsAccess,
        codec: String,
        provider: String,
        voice: Option<String>,
        tts_base_url: String,
        voice_service_base_url: String,
    ) -> Self {
        Self {
            owned: Some(Arc::new(OwnedTtsPolicy {
                access,
                codec,
                provider,
                voice,
                tts_base_url,
                voice_service_base_url,
            })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation delegates to the live global at the original site.
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

    /// Coherent dispatch inputs from one live read. Owned clones its
    /// explicit values without touching config or env.
    pub fn synthesis(&self) -> TtsSynthesis {
        match &self.owned {
            Some(owned) => TtsSynthesis {
                provider: owned.provider.clone(),
                voice: owned.voice.clone(),
                voice_service_base_url: owned.voice_service_base_url.clone(),
            },
            None => {
                let config = app_config();
                TtsSynthesis {
                    provider: config.tts_provider.clone(),
                    voice: config.tts_voice.clone(),
                    voice_service_base_url: config.voice_service_base_url.clone(),
                }
            }
        }
    }

    /// Legacy/fish backend base URL. Global reads live config on each call;
    /// owned uses only its explicit endpoint.
    pub fn tts_base_url(&self) -> String {
        match &self.owned {
            Some(owned) => owned.tts_base_url.clone(),
            None => app_config().tts_base_url.clone(),
        }
    }
}
