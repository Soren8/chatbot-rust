//! Explicit request/cookie/voice configuration.
//!
//! One [`ConfigSource`] handle selects the remaining route configuration for
//! independently configured routers: CSRF policy, session-timeout seconds,
//! the default system prompt and the voice-service endpoint. The global
//! handle touches neither config nor env on construction; each operation
//! delegates to the existing live globals at the original call site. Owned
//! handles carry explicit values and never read ambient config or env.
//! Production stays on the global (live) path with no startup snapshot.

use std::sync::Arc;

use crate::config::app_config;

/// Request configuration handle: global or owned.
///
/// `Clone` shares one `Arc` of owned values. Global reads live config once
/// per call at the same site as the original `app_config()` read.
#[derive(Clone)]
pub struct ConfigSource {
    owned: Option<Arc<OwnedRequestConfig>>,
}

struct OwnedRequestConfig {
    csrf: bool,
    session_timeout_secs: u64,
    default_system_prompt: String,
    voice_service_base_url: String,
}

impl ConfigSource {
    /// Explicit owner: CSRF flag plus raw `session_timeout` seconds plus
    /// default prompt plus voice-service base URL. Touches no config or env;
    /// inputs are used as-is. Callers apply the HTTP 60s floor (`max(60)`)
    /// at the same site as before when building cookie max-age.
    pub fn new(
        csrf: bool,
        session_timeout_secs: u64,
        default_system_prompt: String,
        voice_service_base_url: String,
    ) -> Self {
        Self {
            owned: Some(Arc::new(OwnedRequestConfig {
                csrf,
                session_timeout_secs,
                default_system_prompt,
                voice_service_base_url,
            })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation delegates to the live global at the original site.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// True when this handle carries explicit values with no ambient reads.
    pub fn is_owned(&self) -> bool {
        self.owned.is_some()
    }

    /// Explicit default prompt when owned, without touching global config.
    pub fn owned_default_system_prompt(&self) -> Option<String> {
        self.owned
            .as_ref()
            .map(|owned| owned.default_system_prompt.clone())
    }

    /// Deploy-time CSRF flag. Global reads live config on each call.
    pub fn csrf(&self) -> bool {
        match &self.owned {
            Some(owned) => owned.csrf,
            None => app_config().csrf,
        }
    }

    /// Raw `session_timeout` seconds. Global reads live config on each call.
    /// Callers apply `.max(60)` for cookie max-age as before.
    pub fn session_timeout(&self) -> u64 {
        match &self.owned {
            Some(owned) => owned.session_timeout_secs,
            None => app_config().session_timeout,
        }
    }

    /// Default system prompt for home rendering. Global reads live config on
    /// each call.
    pub fn default_system_prompt(&self) -> String {
        match &self.owned {
            Some(owned) => owned.default_system_prompt.clone(),
            None => app_config().default_system_prompt.clone(),
        }
    }

    /// Voice-service base URL for STT proxying and deep-health probing.
    /// Global reads live config on each call.
    pub fn voice_service_base_url(&self) -> String {
        match &self.owned {
            Some(owned) => owned.voice_service_base_url.clone(),
            None => app_config().voice_service_base_url.clone(),
        }
    }

    /// `Secure` cookie flag fragment (`" Secure;"` when CSRF is on, else
    /// `""`). Global resolves the flag live per call; owned uses its explicit
    /// CSRF value without touching config.
    pub fn secure_flag(&self) -> &'static str {
        let csrf = match &self.owned {
            Some(owned) => owned.csrf,
            None => app_config().csrf,
        };
        if csrf {
            " Secure;"
        } else {
            ""
        }
    }
}
