//! Explicit generation dependencies.
//!
//! One [`GenerationDeps`] handle selects the generation inputs for `/chat`
//! and `/regenerate`: provider lookup, thought defaults, and the Brave
//! client. The global handle touches neither config nor env on construction;
//! each operation delegates to the existing live globals at the original call
//! site. Owned handles carry an explicit provider map plus default plus
//! thought defaults plus Brave key and never read ambient config or env.

use std::collections::HashMap;
use std::sync::Arc;

use chatbot_core::config::{app_config, get_provider_config, ProviderConfig};

use crate::brave::{brave_client, brave_client_with_key, BraveClient};

/// Generation dependency handle: global or owned.
///
/// `Clone` shares one `Arc` of owned dependencies; two handles built from
/// separate maps share nothing. The global handle preserves the original lazy
/// boundaries: provider lookup at selection, one `app_config()` capture for
/// thought defaults at the old site, Brave env read only in the gated search
/// branches of dispatch.
#[derive(Clone)]
pub struct GenerationDeps {
    owned: Option<Arc<OwnedGenerationDeps>>,
}

struct OwnedGenerationDeps {
    providers: HashMap<String, ProviderConfig>,
    default_provider_name: String,
    save_thoughts: bool,
    send_thoughts: bool,
    brave_api_key: Option<String>,
}

impl GenerationDeps {
    /// Explicit owner: provider map plus default plus thought defaults plus
    /// optional Brave key. The map keys are provider names. Touches no
    /// config or env; inputs are used as-is.
    pub fn new(
        providers: HashMap<String, ProviderConfig>,
        default_provider_name: String,
        save_thoughts: bool,
        send_thoughts: bool,
        brave_api_key: Option<String>,
    ) -> Self {
        Self {
            owned: Some(Arc::new(OwnedGenerationDeps {
                providers,
                default_provider_name,
                save_thoughts,
                send_thoughts,
                brave_api_key: brave_api_key.filter(|key| !key.is_empty()),
            })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation delegates to the live globals at the original site.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// Provider lookup with the established backfill: an empty model selects
    /// the configured default, otherwise the named provider. The global path
    /// delegates to the original lookup at this call.
    pub fn get_provider_config(&self, model_name: Option<&str>) -> Option<ProviderConfig> {
        match &self.owned {
            Some(owned) => match model_name {
                Some(name) if !name.is_empty() => owned.providers.get(name).cloned(),
                _ => owned.providers.get(&owned.default_provider_name).cloned(),
            },
            None => get_provider_config(model_name),
        }
    }

    /// Thought defaults as one pair. Callers capture this at the old site
    /// even when the payload overrides, matching the original eager
    /// `app_config()` read. The global path reads live config once here.
    pub fn thoughts_defaults(&self) -> (bool, bool) {
        match &self.owned {
            Some(owned) => (owned.save_thoughts, owned.send_thoughts),
            None => {
                let config = app_config();
                (config.save_thoughts, config.send_thoughts)
            }
        }
    }

    /// Brave client for the gated search branches. The global path delegates
    /// to the original env lookup at this call; the owned path uses only its
    /// explicit key. Dispatch calls this only when search is gated on.
    pub fn brave_client(&self) -> Option<BraveClient> {
        match &self.owned {
            Some(owned) => brave_client_with_key(owned.brave_api_key.as_deref()),
            None => brave_client(),
        }
    }
}
