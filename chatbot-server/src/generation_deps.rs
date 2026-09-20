//! Explicit generation dependencies.
//!
//! One [`GenerationDeps`] handle selects the generation inputs for `/chat`
//! and `/regenerate`: provider lookup, thought defaults, the Brave client,
//! home model listing and the fake stream/search inputs used by tests. The
//! global handle touches neither config nor env on construction; each
//! operation delegates to the existing live globals at the original call
//! site. Owned handles carry an explicit provider map plus default plus
//! thought defaults plus Brave key plus optional fake inputs and never read
//! ambient config or env.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chatbot_core::config::{app_config, get_provider_config, ProviderConfig};

use crate::brave::{brave_client, brave_client_with_key_and_fake, BraveClient};
use crate::providers::openai::OpenAiProvider;
use crate::providers::xai::XaiProvider;

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
    fake_chunks: Option<Vec<String>>,
    fake_tool_query: Option<String>,
    fake_brave_results: Option<String>,
    fake_chunk_delay_ms: u64,
    fake_xai_key: Option<String>,
}

impl Clone for OwnedGenerationDeps {
    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            default_provider_name: self.default_provider_name.clone(),
            save_thoughts: self.save_thoughts,
            send_thoughts: self.send_thoughts,
            brave_api_key: self.brave_api_key.clone(),
            fake_chunks: self.fake_chunks.clone(),
            fake_tool_query: self.fake_tool_query.clone(),
            fake_brave_results: self.fake_brave_results.clone(),
            fake_chunk_delay_ms: self.fake_chunk_delay_ms,
            fake_xai_key: self.fake_xai_key.clone(),
        }
    }
}

/// Home model listing entry: sanitized provider name plus tier plus search
/// flag. Matches the previous `home::build_available_models` filtering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSummary {
    pub provider_name: String,
    pub tier: String,
    pub search: bool,
}

impl GenerationDeps {
    /// Explicit owner: provider map plus default plus thought defaults plus
    /// optional Brave key. The map keys are provider names. Touches no
    /// config or env; inputs are used as-is. Fake stream/search inputs default
    /// to none (isolated, no env reads); use [`GenerationDeps::new_with_fake`]
    /// or the `with_fake_*` builders for explicit fakes.
    pub fn new(
        providers: HashMap<String, ProviderConfig>,
        default_provider_name: String,
        save_thoughts: bool,
        send_thoughts: bool,
        brave_api_key: Option<String>,
    ) -> Self {
        Self::new_with_fake(
            providers,
            default_provider_name,
            save_thoughts,
            send_thoughts,
            brave_api_key,
            None,
            None,
            None,
            0,
            None,
        )
    }

    /// Explicit owner with fake stream/search inputs. All fakes are used
    /// as-is with no env reads; `None` means no fake (isolated, not live).
    /// `fake_chunk_delay_ms` applies to fake-chunk streams only.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_fake(
        providers: HashMap<String, ProviderConfig>,
        default_provider_name: String,
        save_thoughts: bool,
        send_thoughts: bool,
        brave_api_key: Option<String>,
        fake_chunks: Option<Vec<String>>,
        fake_tool_query: Option<String>,
        fake_brave_results: Option<String>,
        fake_chunk_delay_ms: u64,
        fake_xai_key: Option<String>,
    ) -> Self {
        Self {
            owned: Some(Arc::new(OwnedGenerationDeps {
                providers,
                default_provider_name,
                save_thoughts,
                send_thoughts,
                brave_api_key: brave_api_key.filter(|key| !key.is_empty()),
                fake_chunks,
                fake_tool_query: fake_tool_query.filter(|q| !q.is_empty()),
                fake_brave_results,
                fake_chunk_delay_ms,
                fake_xai_key,
            })),
        }
    }

    /// Owned builder: explicit fake stream chunks overriding
    /// `provider.test_chunks` with no env read.
    pub fn with_fake_chunks(self, chunks: Vec<String>) -> Self {
        self.with_fake(|owned| owned.fake_chunks = Some(chunks))
    }

    /// Owned builder: explicit fake tool-call query with no env read.
    pub fn with_fake_tool_query(self, query: String) -> Self {
        if query.is_empty() {
            return self;
        }
        self.with_fake(|owned| owned.fake_tool_query = Some(query))
    }

    /// Owned builder: explicit fake Brave results with no env read or HTTP.
    pub fn with_fake_brave_results(self, results: String) -> Self {
        self.with_fake(|owned| owned.fake_brave_results = Some(results))
    }

    /// Owned builder: explicit fake per-chunk delay with no env read.
    pub fn with_fake_chunk_delay_ms(self, delay_ms: u64) -> Self {
        self.with_fake(|owned| owned.fake_chunk_delay_ms = delay_ms)
    }

    /// Owned builder: explicit XAI key fallback with no env read.
    pub fn with_fake_xai_key(self, key: String) -> Self {
        self.with_fake(|owned| owned.fake_xai_key = Some(key))
    }

    fn with_fake(mut self, apply: impl FnOnce(&mut OwnedGenerationDeps)) -> Self {
        let owned = self
            .owned
            .as_ref()
            .expect("with_fake_* requires an owned GenerationDeps");
        let mut next = (**owned).clone();
        apply(&mut next);
        self.owned = Some(Arc::new(next));
        self
    }

    /// Compatibility handle. Constructing it touches neither config nor env;
    /// each operation delegates to the live globals at the original site.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// True when this handle carries explicit values with no ambient reads.
    pub fn is_owned(&self) -> bool {
        self.owned.is_some()
    }

    /// Explicit thought defaults when owned, without touching global config.
    pub(crate) fn owned_thoughts_defaults(&self) -> Option<(bool, bool)> {
        self.owned
            .as_ref()
            .map(|owned| (owned.save_thoughts, owned.send_thoughts))
    }

    /// Explicit model listing when owned, without touching global config.
    pub(crate) fn owned_provider_summaries(
        &self,
        user_tier: &str,
    ) -> Option<Vec<ProviderSummary>> {
        let owned = self.owned.as_ref()?;
        let mut names: Vec<&String> = owned.providers.keys().collect();
        names.sort();
        let mut out = Vec::new();
        for name in names {
            let Some(provider) = owned.providers.get(name) else {
                continue;
            };
            let tier = provider
                .tier
                .clone()
                .unwrap_or_else(|| "free".to_string());
            if tier.eq_ignore_ascii_case("premium") && !user_tier.eq_ignore_ascii_case("premium")
            {
                continue;
            }
            out.push(ProviderSummary {
                provider_name: provider.provider_name.clone(),
                tier,
                search: provider.search,
            });
        }
        Some(out)
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
    /// explicit key plus optional fake results with no env read or HTTP.
    /// Dispatch calls this only when search is gated on.
    pub fn brave_client(&self) -> Option<BraveClient> {
        match &self.owned {
            Some(owned) => brave_client_with_key_and_fake(
                owned.brave_api_key.as_deref(),
                owned.fake_brave_results.clone(),
                true,
            ),
            None => brave_client(),
        }
    }

    /// Home model listing with the established premium filtering. The global
    /// path captures one live config at this call; the owned path iterates
    /// only its explicit map (sorted for determinism) with no config read.
    pub fn provider_summaries(&self, user_tier: &str) -> Vec<ProviderSummary> {
        match &self.owned {
            Some(_) => self
                .owned_provider_summaries(user_tier)
                .expect("owned summaries"),
            None => summaries_from_live(&app_config(), user_tier),
        }
    }

    /// Concrete OpenAI provider for `config`. The global path delegates to
    /// [`OpenAiProvider::new`] at this call (original env-chunk timing); the
    /// owned path uses only explicit fake inputs with no env reads.
    pub fn openai_provider(&self, config: &ProviderConfig) -> Result<OpenAiProvider> {
        match &self.owned {
            Some(owned) => OpenAiProvider::new_owned(
                config,
                owned.fake_chunks.clone(),
                owned.fake_chunk_delay_ms,
                owned.fake_tool_query.clone(),
            ),
            None => OpenAiProvider::new(config),
        }
    }

    /// Concrete XAI provider for `config`. The global path delegates to
    /// [`XaiProvider::new`] (env fallback at stream time); the owned path
    /// uses only its explicit key fallback with no env read.
    pub fn xai_provider(&self, config: &ProviderConfig) -> Result<XaiProvider> {
        match &self.owned {
            Some(owned) => XaiProvider::new_owned(config, owned.fake_xai_key.clone()),
            None => XaiProvider::new(config),
        }
    }
}

/// Pure home-listing projection over one captured config: same premium
/// filtering and config-order iteration as the original home site, with no
/// config read of its own. Both [`GenerationDeps::provider_summaries`] (live)
/// and [`crate::services::AppServices::home_settings`] (blended) use it.
pub(crate) fn summaries_from_live(
    config: &chatbot_core::config::AppConfig,
    user_tier: &str,
) -> Vec<ProviderSummary> {
    let mut out = Vec::new();
    for name in config.provider_names() {
        let Some(provider) = config.provider(name) else {
            continue;
        };
        let tier = provider
            .tier
            .clone()
            .unwrap_or_else(|| "free".to_string());
        if tier.eq_ignore_ascii_case("premium") && !user_tier.eq_ignore_ascii_case("premium") {
            continue;
        }
        out.push(ProviderSummary {
            provider_name: provider.provider_name.clone(),
            tier,
            search: provider.search,
        });
    }
    out
}
