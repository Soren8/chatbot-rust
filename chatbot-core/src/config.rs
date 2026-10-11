use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

#[path = "agent_egress.rs"]
pub mod agent_egress;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExternalConnectionsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub allow_public_https: bool,
    #[serde(default)]
    pub targets: Vec<ExternalTarget>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExternalTarget {
    pub id: String,
    pub base_url: String,
    pub allowed_users: Vec<String>,
    pub allowed_ips: Vec<IpAddr>,
    #[serde(default)]
    pub allow_tunneled_http: bool,
}

impl ExternalTarget {
    pub fn canonical_base_url(&self) -> &str { &self.base_url }
    pub fn port(&self) -> u16 {
        agent_egress::CanonicalBase::parse(&self.base_url)
            .expect("validated external target URL").port()
    }
}

impl ExternalConnectionsConfig {
    /// Validate operator policy independently of feature activation; fail closed at boot.
    pub fn validate(mut self) -> Result<Self, &'static str> {
        let mut eligible = HashSet::new();
        for user in &self.allowed_users {
            if crate::names::normalise_username(user).as_deref() != Ok(user.as_str()) || !eligible.insert(user.clone()) {
                return Err("invalid or duplicate external_connections.allowed_users");
            }
        }
        let mut ids = HashSet::new();
        let mut urls = HashSet::new();
        let mut reserved = HashMap::new();
        for target in &mut self.targets {
            let base = agent_egress::CanonicalBase::parse(&target.base_url).map_err(|_| "invalid external_connections target URL")?;
            if target.id.trim().is_empty() || !ids.insert(target.id.clone()) || !urls.insert(base.as_str().to_owned()) {
                return Err("duplicate or invalid external_connections target");
            }
            target.base_url = base.as_str().to_owned();
            if !base.is_https() && !target.allow_tunneled_http {
                return Err("HTTP target requires an approved encrypted tunnel");
            }
            if target.allowed_users.is_empty() || target.allowed_ips.is_empty() {
                return Err("external target requires users and exact IPs");
            }
            let mut users = HashSet::new();
            for user in &target.allowed_users {
                if !eligible.contains(user) || !users.insert(user) {
                    return Err("external target users must be unique eligible accounts");
                }
            }
            for ip in &target.allowed_ips {
                let key = (*ip, base.port());
                if let Some(previous_users) = reserved.insert(key, users.clone()) {
                    if previous_users != users { return Err("conflicting reserved IP/port accounts"); }
                }
            }
        }
        Ok(self)
    }
}

/// Operator classification of a chat or outbound destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLevel {
    Private,
    Standard,
    NonPrivate,
}

impl PrivacyLevel {
    pub const fn default_chat() -> Self { Self::Private }
    pub const fn default_destination() -> Self { Self::NonPrivate }
}

impl Default for PrivacyLevel {
    fn default() -> Self { Self::default_destination() }
}

/// Whether a destination may receive content for the requested chat mode.
pub const fn destination_is_eligible(task: PrivacyLevel, destination: PrivacyLevel) -> bool {
    match task {
        PrivacyLevel::Private => matches!(destination, PrivacyLevel::Private),
        PrivacyLevel::Standard => !matches!(destination, PrivacyLevel::NonPrivate),
        PrivacyLevel::NonPrivate => true,
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderConfig {
    #[serde(default = "PrivacyLevel::default_destination")]
    pub privacy_level: PrivacyLevel,
    #[serde(alias = "name")]
    pub provider_name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default)]
    pub tier: Option<String>,
    pub model_name: String,
    #[serde(default)]
    pub context_size: Option<u32>,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_allowed_providers")]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub request_timeout: Option<f64>,
    /// Extra attempts after an upstream `429 Too Many Requests`. Defaults to 5;
    /// 0 disables retrying.
    #[serde(default)]
    pub rate_limit_retries: Option<u32>,
    /// Upper bound (seconds) a single rate-limit retry may wait, capping any
    /// upstream `Retry-After` hint. Defaults to 30.
    #[serde(default)]
    pub rate_limit_max_wait_secs: Option<f64>,
    #[serde(default)]
    pub test_chunks: Option<Vec<String>>,
    #[serde(default)]
    pub search: bool,
    /// When true (default), XAI providers use XAI's own web_search tool via the
    /// Responses API. When false, Brave Search is used instead (requires BRAVE_API_KEY).
    /// Ignored for non-XAI providers.
    #[serde(default = "default_true")]
    pub xai_search: bool,
    /// When true, XAI Responses API calls set `store: false` so the request/response
    /// are not retained for conversation chaining. Full team-level Zero Data Retention
    /// (no 30-day audit logs) is enabled in the xAI Console and is confirmed via the
    /// `x-zero-data-retention` response header. Ignored for non-XAI providers.
    #[serde(default)]
    pub xai_zdr: bool,
}

/// Privacy classification of search services, independent of model selection.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchProvidersConfig {
    #[serde(default)]
    pub brave: SearchProviderConfig,
    #[serde(default)]
    pub xai_native: SearchProviderConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchProviderConfig {
    #[serde(default = "PrivacyLevel::default_destination")]
    pub privacy_level: PrivacyLevel,
}

fn default_true() -> bool {
    true
}

impl ProviderConfig {
    fn finalize(mut self) -> Self {
        self.provider_type = self.provider_type.trim().to_ascii_lowercase();
        self.tier = self
            .tier
            .map(|tier| tier.trim().to_ascii_lowercase());

        if self.base_url.contains("openrouter.ai") {
            if let Ok(openrouter_key) = env::var("OPENROUTER_API_KEY") {
                if !openrouter_key.trim().is_empty() {
                    self.api_key = Some(openrouter_key);
                }
            }
        }

        if self.provider_type == "xai" || self.base_url.contains("api.x.ai") {
            if let Ok(xai_key) = env::var("XAI_API_KEY") {
                if !xai_key.trim().is_empty() {
                    self.api_key = Some(xai_key);
                }
            }
        }

        if self
            .api_key
            .as_ref()
            .map(|key| key.trim().is_empty())
            .unwrap_or(false)
        {
            self.api_key = None;
        }

        self.allowed_providers = self
            .allowed_providers
            .into_iter()
            .map(|entry| entry.trim().to_owned())
            .filter(|entry| !entry.is_empty())
            .collect();

        self
    }
}

/// Who may call the webserver `POST /tts` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtsAccess {
    /// Guests and logged-in users (default; good for LAN / local models).
    Anyone,
    /// Session must have a logged-in username.
    Authenticated,
    /// Logged-in user with `premium` tier in the user store.
    Premium,
}

impl TtsAccess {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "anyone" | "guest" | "all" => Self::Anyone,
            "authenticated" | "auth" | "logged_in" | "login" => Self::Authenticated,
            "premium" => Self::Premium,
            other => panic!(
                "invalid tts_access '{other}'; expected one of: anyone, authenticated, premium"
            ),
        }
    }
}

/// OpenAI-compatible text-to-speech provider (`POST {base_url}/audio/speech`).
#[derive(Debug, Clone, Deserialize)]
pub struct TtsConfig {
    #[serde(rename = "type", default = "default_voice_type")]
    pub provider_type: String,
    #[serde(default = "default_voice_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_tts_model")]
    pub model_name: String,
    #[serde(default)]
    pub voice: Option<String>,
    /// PCM rate used when the provider sends no `X-Sample-Rate` header.
    #[serde(default = "default_tts_sample_rate")]
    pub sample_rate: u32,
    #[serde(default = "PrivacyLevel::default_destination")]
    pub privacy_level: PrivacyLevel,
    #[serde(default)]
    pub health_url: Option<String>,
}

/// OpenAI-compatible speech-to-text provider
/// (`POST {base_url}/audio/transcriptions`).
#[derive(Debug, Clone, Deserialize)]
pub struct SttConfig {
    #[serde(rename = "type", default = "default_voice_type")]
    pub provider_type: String,
    #[serde(default = "default_voice_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_stt_model")]
    pub model_name: String,
    #[serde(default = "PrivacyLevel::default_destination")]
    pub privacy_level: PrivacyLevel,
    #[serde(default)]
    pub health_url: Option<String>,
}

/// An omitted `tts:` block targets the local chatbot-voice service.
impl Default for TtsConfig {
    fn default() -> Self {
        Self {
            provider_type: default_voice_type(),
            base_url: default_voice_base_url(),
            api_key: None,
            model_name: default_tts_model(),
            voice: None,
            sample_rate: default_tts_sample_rate(),
            privacy_level: PrivacyLevel::default_destination(),
            health_url: Some(DEFAULT_VOICE_HEALTH_URL.to_string()),
        }
    }
}

/// An omitted `stt:` block targets the local chatbot-voice service.
impl Default for SttConfig {
    fn default() -> Self {
        Self {
            provider_type: default_voice_type(),
            base_url: default_voice_base_url(),
            api_key: None,
            model_name: default_stt_model(),
            privacy_level: PrivacyLevel::default_destination(),
            health_url: Some(DEFAULT_VOICE_HEALTH_URL.to_string()),
        }
    }
}

const DEFAULT_VOICE_HEALTH_URL: &str = "http://localhost:5100/health";

fn default_voice_type() -> String {
    "openai".to_string()
}

fn default_voice_base_url() -> String {
    "http://localhost:5100/v1".to_string()
}

fn default_tts_model() -> String {
    "kokoro".to_string()
}

fn default_stt_model() -> String {
    "parakeet-tdt-0.6b-v2".to_string()
}

fn default_tts_sample_rate() -> u32 {
    24_000
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub external_connections: ExternalConnectionsConfig,
    pub secret_key: String,
    pub host_data_dir: PathBuf,
    pub log_level: String,
    pub tts: TtsConfig,
    pub stt: SttConfig,
    /// Wire codec for /tts_stream responses: "opus" (Ogg-Opus, default) or
    /// "wav" (uncompressed PCM fallback for players without an Opus decoder).
    pub tts_codec: String,
    /// Policy for who may use TTS on the webserver.
    pub tts_access: TtsAccess,
    pub default_system_prompt: String,
    pub session_timeout: u64,
    pub csrf: bool,
    pub save_thoughts: bool,
    pub send_thoughts: bool,
    pub brave_api_key: Option<String>,
    pub search_providers: SearchProvidersConfig,
    /// Max requests per identity per rolling minute (`0` disables).
    pub rate_limit_per_user_per_minute: u32,
    /// Max requests across all identities per rolling minute (`0` disables).
    pub rate_limit_global_per_minute: u32,
    provider_order: Vec<String>,
    providers_by_name: HashMap<String, ProviderConfig>,
    default_provider_name: String,
}

impl AppConfig {
    pub fn provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers_by_name.get(name)
    }

    pub fn default_provider(&self) -> &ProviderConfig {
        self.providers_by_name
            .get(&self.default_provider_name)
            .expect("default provider is always present")
    }

    pub fn provider_names(&self) -> &[String] {
        &self.provider_order
    }
}

enum ConfigState {
    Uninitialized,
    Ready(Arc<AppConfig>),
}

static APP_CONFIG: Lazy<RwLock<ConfigState>> =
    Lazy::new(|| RwLock::new(ConfigState::Uninitialized));

pub fn app_config() -> Arc<AppConfig> {
    {
        let guard = APP_CONFIG
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let ConfigState::Ready(config) = &*guard {
            return Arc::clone(config);
        }
    }

    let mut guard = APP_CONFIG
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let ConfigState::Ready(config) = &*guard {
        return Arc::clone(config);
    }

    let config = Arc::new(load_app_config());
    *guard = ConfigState::Ready(Arc::clone(&config));
    config
}

pub fn get_provider_config(model_name: Option<&str>) -> Option<ProviderConfig> {
    let config = app_config();

    match model_name {
        Some(name) if !name.is_empty() => config.provider(name).cloned(),
        _ => Some(config.default_provider().clone()),
    }
}

pub fn reset() {
    let mut guard = APP_CONFIG
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = ConfigState::Uninitialized;
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
struct RawConfig {
    #[serde(default)]
    external_connections: ExternalConnectionsConfig,
    #[serde(default)]
    llms: Vec<ProviderConfig>,
    #[serde(default)]
    search_providers: SearchProvidersConfig,
    #[serde(default)]
    tts: TtsConfig,
    #[serde(default)]
    stt: SttConfig,
    #[serde(default)]
    default_llm: Option<String>,
    #[serde(default)]
    default_system_prompt: Option<String>,
    #[serde(default)]
    session_timeout: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_bool_flexible")]
    csrf: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_bool_flexible",
        alias = "saveThoughts"
    )]
    save_thoughts: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_bool_flexible",
        alias = "sendThoughts"
    )]
    send_thoughts: Option<bool>,
    #[serde(default)]
    tts_codec: Option<String>,
    #[serde(default)]
    tts_access: Option<String>,
    #[serde(default)]
    rate_limit_per_user_per_minute: Option<u32>,
    #[serde(default)]
    rate_limit_global_per_minute: Option<u32>,
}

fn deserialize_bool_flexible<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoolVisitor;

    impl<'de> serde::de::Visitor<'de> for BoolVisitor {
        type Value = Option<bool>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("boolean or string ('on'/'off', 'true'/'false')")
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match value.to_lowercase().as_str() {
                "on" | "true" => Ok(Some(true)),
                "off" | "false" => Ok(Some(false)),
                _ => Err(serde::de::Error::custom(format!(
                    "invalid boolean string: {}",
                    value
                ))),
            }
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(BoolVisitor)
}

/// Reserved placeholder secret key; never accepted as the configured `SECRET_KEY`.
const FORBIDDEN_SECRET_KEYS: &[&str] = &["default_secret_key"];

/// Require a non-default `SECRET_KEY` from the environment. Fail closed at boot.
fn require_secret_key() -> String {
    match env::var("SECRET_KEY") {
        Ok(key) => {
            let trimmed = key.trim();
            if trimmed.is_empty() {
                panic!(
                    "SECRET_KEY is set but empty; set a non-empty secret via the environment"
                );
            }
            if FORBIDDEN_SECRET_KEYS.contains(&trimmed) {
                panic!(
                    "SECRET_KEY must not be the insecure default value; set a unique secret via the environment"
                );
            }
            key
        }
        Err(_) => panic!(
            "SECRET_KEY environment variable is required; refusing to start with a default"
        ),
    }
}

fn load_app_config() -> AppConfig {
    if dotenvy::dotenv().is_ok() {
        debug!("loaded environment variables from .env");
    }

    let secret_key = require_secret_key();
    let host_data_dir =
        PathBuf::from(env::var("HOST_DATA_DIR").unwrap_or_else(|_| "./data".to_string()));
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
    let raw_config = load_yaml_config().unwrap_or_default();
    validate_voice_config(&raw_config.tts, &raw_config.stt);

    let mut providers = raw_config
        .llms
        .into_iter()
        .map(|provider| provider.finalize())
        .collect::<Vec<_>>();

    if providers.is_empty() {
        warn!("no LLM providers configured; using fallback provider");
        providers.push(fallback_provider());
    }

    let mut providers_by_name = HashMap::new();
    let mut provider_order = Vec::new();

    for provider in providers {
        let name = provider.provider_name.clone();
        if providers_by_name.contains_key(&name) {
            warn!(provider = %name, "duplicate provider name detected; last definition wins");
        } else {
            provider_order.push(name.clone());
        }
        providers_by_name.insert(name, provider);
    }

    let default_provider_name = match raw_config.default_llm {
        Some(name) if providers_by_name.contains_key(&name) => name,
        Some(name) => {
            panic!("default_llm '{name}' not found in provider list");
        }
        None => provider_order
            .first()
            .cloned()
            .expect("at least one provider is always present"),
    };

    let default_system_prompt = raw_config.default_system_prompt.unwrap_or_else(|| {
        "You are a helpful AI assistant. Provide clear and concise answers to user queries."
            .to_string()
    });

    let session_timeout = raw_config.session_timeout.unwrap_or(3600);
    let csrf = if let Ok(env_csrf) = env::var("CSRF") {
        let lowered = env_csrf.to_lowercase();
        lowered == "on" || lowered == "true"
    } else {
        raw_config.csrf.unwrap_or(true)
    };

    let save_thoughts = raw_config.save_thoughts.unwrap_or(true);
    let send_thoughts = raw_config.send_thoughts.unwrap_or(false);
    let tts_codec = if let Ok(env_value) = env::var("TTS_CODEC") {
        validate_tts_codec(&env_value);
        env_value.trim().to_ascii_lowercase()
    } else if let Some(ref value) = raw_config.tts_codec {
        validate_tts_codec(value);
        value.trim().to_ascii_lowercase()
    } else {
        "opus".to_string()
    };
    let tts_access = if let Ok(env_value) = env::var("TTS_ACCESS") {
        TtsAccess::parse(&env_value)
    } else if let Some(ref value) = raw_config.tts_access {
        TtsAccess::parse(value)
    } else {
        TtsAccess::Anyone
    };

    let brave_api_key = env::var("BRAVE_API_KEY").ok().filter(|v| !v.is_empty());

    let rate_limit_per_user_per_minute = parse_u32_env("RATE_LIMIT_PER_USER_PER_MINUTE")
        .or(raw_config.rate_limit_per_user_per_minute)
        .unwrap_or(60);
    let rate_limit_global_per_minute = parse_u32_env("RATE_LIMIT_GLOBAL_PER_MINUTE")
        .or(raw_config.rate_limit_global_per_minute)
        .unwrap_or(600);

    info!(
        effective_save = save_thoughts,
        effective_send = send_thoughts,
        "effective config values for thinking tokens"
    );


    if brave_api_key.is_some() {
        info!("Brave Search configured");
    } else {
        info!("Brave Search not configured (BRAVE_API_KEY not set)");
    }

    info!(
        providers = providers_by_name.len(),
        default_provider = %default_provider_name,
        csrf_enabled = csrf,
        tts_access = ?tts_access,
        rate_limit_per_user_per_minute,
        rate_limit_global_per_minute,
        "configuration loaded"
    );

    AppConfig {
        external_connections: raw_config.external_connections.validate().unwrap_or_else(|e| panic!("{e}")),
        secret_key,
        host_data_dir,
        log_level,
        tts: raw_config.tts.clone(),
        stt: raw_config.stt.clone(),
        tts_codec,
        tts_access,
        default_system_prompt,
        session_timeout,
        csrf,
        save_thoughts,
        send_thoughts,
        brave_api_key,
        search_providers: raw_config.search_providers,
        rate_limit_per_user_per_minute,
        rate_limit_global_per_minute,
        provider_order,
        providers_by_name,
        default_provider_name,
    }
}

fn parse_u32_env(name: &str) -> Option<u32> {
    env::var(name).ok().and_then(|v| {
        let trimmed = v.split('#').next().unwrap_or(&v).trim();
        if trimmed.is_empty() {
            None
        } else {
            trimmed.parse().ok()
        }
    })
}

fn load_yaml_config() -> Option<RawConfig> {
    let path = Path::new(".config.yml");

    if !path.exists() {
        warn!(
            "configuration file {} not found; using defaults",
            path.display()
        );
        return None;
    }

    if !path.is_file() {
        warn!(
            "configuration path {} is not a file; using defaults",
            path.display()
        );
        return None;
    }

    load_yaml_config_from_read(fs::read_to_string(path))
}

/// Shared read→parse entry used by boot and tests (so I/O failures can be mocked).
fn load_yaml_config_from_read(result: Result<String, std::io::Error>) -> Option<RawConfig> {
    match result {
        Ok(contents) => Some(parse_yaml_config_contents(&contents)),
        Err(err) => {
            panic!("failed to read .config.yml: {err}");
        }
    }
}

fn parse_yaml_config_contents(contents: &str) -> RawConfig {
    match serde_yaml::from_str::<Value>(contents) {
        Ok(value) => {
            refuse_removed_voice_keys(&value);
            // Fail closed before substitution so plaintext secrets never load.
            refuse_plaintext_provider_secrets(&value);

            // Extract user-defined vars from the top-level `vars:` mapping.
            // These are substituted like env vars but env vars take precedence.
            let user_vars = extract_user_vars(&value);
            let replaced = replace_vars(value, &user_vars);
            match serde_yaml::from_value::<RawConfig>(replaced) {
                Ok(config) => {
                    validate_raw_config(&config);
                    config
                }
                Err(err) => {
                    panic!("invalid .config.yml schema: {err}");
                }
            }
        }
        Err(err) => {
            panic!("failed to parse .config.yml YAML: {err}");
        }
    }
}
const ALLOWED_PROVIDER_TYPES: &[&str] = &["openai", "xai", "stub"];

const ALLOWED_PROVIDER_TIERS: &[&str] = &["free", "premium"];

/// Upper bound for the per-provider `rate_limit_retries` key; guards against a
/// pathological config hammering an upstream that is already rejecting us.
const MAX_PROVIDER_RATE_LIMIT_RETRIES: u32 = 10;
const ALLOWED_TTS_CODECS: &[&str] = &["opus", "wav"];

fn validate_tts_codec(value: &str) {
    let normalized = value.trim().to_lowercase();
    if !ALLOWED_TTS_CODECS.contains(&normalized.as_str()) {
        panic!(
            "invalid tts_codec '{value}'; expected one of {}",
            ALLOWED_TTS_CODECS.join(", ")
        );
    }
}

fn validate_raw_config(config: &RawConfig) {
    if let Some(timeout) = config.session_timeout {
        if timeout == 0 {
            panic!("session_timeout must be greater than 0");
        }
    }

    if let Some(access) = config.tts_access.as_deref() {
        let _ = TtsAccess::parse(access);
    }

    for (idx, provider) in config.llms.iter().enumerate() {
        let provider_type = provider.provider_type.trim().to_lowercase();
        if !ALLOWED_PROVIDER_TYPES.contains(&provider_type.as_str()) {
            panic!(
                "llms[{idx}].type '{}' is invalid; expected one of {}",
                provider.provider_type,
                ALLOWED_PROVIDER_TYPES.join(", ")
            );
        }
        if provider.provider_name.trim().is_empty() {
            panic!("llms[{idx}].provider_name must not be empty");
        }
        if provider.model_name.trim().is_empty() {
            panic!("llms[{idx}].model_name must not be empty");
        }
        if let Some(tier) = provider.tier.as_deref() {
            let normalized = tier.trim().to_lowercase();
            if !ALLOWED_PROVIDER_TIERS.contains(&normalized.as_str()) {
                panic!(
                    "llms[{idx}].tier '{tier}' is invalid; expected one of {}",
                    ALLOWED_PROVIDER_TIERS.join(", ")
                );
            }
        }
        if let Some(timeout) = provider.request_timeout {
            if timeout <= 0.0 || !timeout.is_finite() {
                panic!("llms[{idx}].request_timeout must be a positive finite number");
            }
        }
        if let Some(retries) = provider.rate_limit_retries {
            if retries > MAX_PROVIDER_RATE_LIMIT_RETRIES {
                panic!(
                    "llms[{idx}].rate_limit_retries must be at most {MAX_PROVIDER_RATE_LIMIT_RETRIES}"
                );
            }
        }
        if let Some(wait) = provider.rate_limit_max_wait_secs {
            if wait <= 0.0 || !wait.is_finite() {
                panic!("llms[{idx}].rate_limit_max_wait_secs must be a positive finite number");
            }
        }
    }
}

/// Top-level voice keys replaced by the `tts:` and `stt:` provider blocks.
const REMOVED_VOICE_KEYS: &[&str] = &[
    "tts_provider",
    "tts_voice",
    "voice_service_host",
    "voice_service_port",
    "voice_gpu_device",
    "stt_enabled",
    "stt_privacy_level",
    "tts_privacy_level",
];

fn refuse_removed_voice_keys(value: &Value) {
    let Value::Mapping(root) = value else {
        return;
    };
    for key in REMOVED_VOICE_KEYS {
        if root.contains_key(Value::String((*key).to_string())) {
            panic!("deprecated config key {key}; configure voice in the tts: and stt: blocks");
        }
    }
}

fn validate_secret_value(api_key_val: &Value, path: &str, user_vars: &HashMap<String, String>) {
    match api_key_val {
        Value::Null => {}
        Value::String(raw) if raw.trim().is_empty() => {}
        Value::String(raw) => match env_var_ref_name(raw) {
            Some(var_name) if user_vars.contains_key(var_name) => panic!(
                "{path}.api_key references vars:{var_name}; API keys must use environment variables only"
            ),
            Some(_) => {}
            None => panic!(
                "{path}.api_key must be an environment variable reference, not a plaintext secret"
            ),
        },
        _ => panic!(
            "{path}.api_key must be a string environment variable reference, got a non-string value"
        ),
    }
}

fn validate_voice_config(tts: &TtsConfig, stt: &SttConfig) {
    for (name, kind) in [("tts", &tts.provider_type), ("stt", &stt.provider_type)] {
        if kind.trim().to_ascii_lowercase() != "openai" {
            panic!("{name}.type must be openai");
        }
    }
    if tts.sample_rate == 0 {
        panic!("tts.sample_rate must be positive");
    }
}

/// If `value` is exactly `${VAR}`, return `VAR`. Otherwise `None`.
fn env_var_ref_name(value: &str) -> Option<&str> {
    static ENV_REF_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$").expect("env ref regex"));
    ENV_REF_RE
        .captures(value.trim())
        .map(|caps| caps.get(1).expect("capture").as_str())
}

/// Reject plaintext provider `api_key` values in `.config.yml`.
/// Keys must be omitted, empty, or a single `${ENV_VAR}` reference that is not
/// supplied via the YAML `vars:` map (environment only).
fn refuse_plaintext_provider_secrets(value: &Value) {
    let Value::Mapping(root) = value else {
        return;
    };
    let user_vars = extract_user_vars(value);
    for block in ["tts", "stt"] {
        if let Some(Value::Mapping(provider)) = root.get(Value::String(block.to_string())) {
            if let Some(key) = provider.get(Value::String("api_key".to_string())) {
                validate_secret_value(key, block, &user_vars);
            }
        }
    }
    let Some(Value::Sequence(llms)) = root.get(Value::String("llms".to_string())) else {
        return;
    };

    for (idx, entry) in llms.iter().enumerate() {
        let Value::Mapping(provider) = entry else {
            continue;
        };
        let Some(api_key_val) = provider.get(Value::String("api_key".to_string())) else {
            continue;
        };
        match api_key_val {
            Value::Null => continue,
            Value::String(raw) if raw.trim().is_empty() => continue,
            Value::String(raw) => match env_var_ref_name(raw) {
                Some(var_name) if user_vars.contains_key(var_name) => {
                    panic!(
                        "llms[{idx}].api_key references vars:{var_name}; API keys must use environment variables only (e.g. api_key: \"${{OPENAI_API_KEY}}\")"
                    );
                }
                Some(_) => {}
                None => {
                    panic!(
                        "llms[{idx}].api_key must be an environment variable reference like \"${{OPENAI_API_KEY}}\", not a plaintext secret"
                    );
                }
            },
            _ => {
                panic!(
                    "llms[{idx}].api_key must be a string environment variable reference, got a non-string value"
                );
            }
        }
    }
}

/// Extract the `vars:` mapping from the top level of the config YAML.
fn extract_user_vars(value: &Value) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    if let Value::Mapping(map) = value {
        if let Some(Value::Mapping(vars_map)) = map.get(&Value::String("vars".to_string())) {
            for (k, v) in vars_map {
                if let (Value::String(key), Value::String(val)) = (k, v) {
                    vars.insert(key.clone(), val.clone());
                }
                // Also handle numeric values (e.g. port: 1234)
                if let (Value::String(key), Value::Number(num)) = (k, v) {
                    vars.insert(key.clone(), num.to_string());
                }
            }
        }
    }
    vars
}

/// Recursively substitute `${VAR}` references. Env vars take precedence
/// over user-defined vars, so secrets in the environment always win.
/// The `vars` key itself is stripped from the output.
fn replace_vars(value: Value, user_vars: &HashMap<String, String>) -> Value {
    match value {
        Value::String(s) => Value::String(replace_in_str(&s, user_vars)),
        Value::Sequence(seq) => {
            Value::Sequence(seq.into_iter().map(|v| replace_vars(v, user_vars)).collect())
        }
        Value::Mapping(map) => {
            let mut replaced = Mapping::new();
            for (key, value) in map.into_iter() {
                // Strip the vars key — it's not a real config field
                if key == Value::String("vars".to_string()) {
                    continue;
                }
                let key = match key {
                    Value::String(s) => Value::String(replace_in_str(&s, user_vars)),
                    other => other,
                };
                replaced.insert(key, replace_vars(value, user_vars));
            }
            Value::Mapping(replaced)
        }
        other => other,
    }
}

fn replace_in_str(input: &str, user_vars: &HashMap<String, String>) -> String {
    static VAR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\$\{([^}]+)\}").expect("var regex"));
    VAR_RE
        .replace_all(input, |caps: &regex::Captures<'_>| {
            let name = &caps[1];
            // Env vars win (secrets), then user-defined vars, then empty string
            env::var(name).unwrap_or_else(|_| {
                user_vars.get(name).cloned().unwrap_or_default()
            })
        })
        .to_string()
}

pub fn fallback_provider() -> ProviderConfig {
    ProviderConfig {
        provider_name: "default".to_string(),
        privacy_level: PrivacyLevel::default_destination(),
        provider_type: "openai".to_string(),
        tier: Some("free".to_string()),
        model_name: "local-model".to_string(),
        context_size: Some(8192),
        base_url: "http://127.0.0.1:11434/v1".to_string(),
        api_key: None,
        allowed_providers: Vec::new(),
        request_timeout: None,
        rate_limit_retries: None,
        rate_limit_max_wait_secs: None,
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn deserialize_allowed_providers<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AllowedVisitor;

    impl<'de> serde::de::Visitor<'de> for AllowedVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(AllowedVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::env;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct CwdGuard {
        original: PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &Path) -> Self {
            let original = env::current_dir().expect("current dir");
            env::set_current_dir(path).expect("change dir");
            Self { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.original);
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var(key).ok();
            env::set_var(key, value);
            Self { key, original }
        }

        fn remove(key: &'static str) -> Self {
            let original = env::var(key).ok();
            env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                env::set_var(self.key, value);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn replaces_env_vars_in_yaml() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'env-model'\n    type: 'stub'\n    model_name: '${{MODEL}}'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _model_guard = EnvVarGuard::set("MODEL", "injected-model");

        reset();
        let config = app_config();
        let provider = config.default_provider();
        assert_eq!(provider.model_name, "injected-model");

        reset();
    }

    #[test]
    fn loads_csrf_config() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");

        // Test with boolean false
        {
            let mut file = fs::File::create(&path).expect("create config");
            writeln!(file, "csrf: false").expect("write config");
            let _cwd_guard = CwdGuard::change_to(dir.path());
            reset();
            let config = app_config();
            assert!(!config.csrf);
        }

        // Test with string "off"
        {
            let mut file = fs::File::create(&path).expect("create config");
            writeln!(file, "csrf: 'off'").expect("write config");
            let _cwd_guard = CwdGuard::change_to(dir.path());
            reset();
            let config = app_config();
            assert!(!config.csrf);
        }

        let _cwd_guard = CwdGuard::change_to(dir.path());

        // Test environment variable override
        let _csrf_guard = EnvVarGuard::set("CSRF", "on");
        reset();
        let config = app_config();
        assert!(config.csrf);

        reset();
    }

    #[test]
    fn returns_fallback_when_missing_file() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let provider_type = app_config().default_provider().provider_type.clone();
        assert_eq!(provider_type, "openai");
        reset();
    }

    #[test]
    fn parses_thinking_config() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(file, "save_thoughts: false\nsend_thoughts: true").expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();

        assert_eq!(config.save_thoughts, false);
        assert_eq!(config.send_thoughts, true);
        reset();
    }

    #[test]
    #[should_panic(expected = "SECRET_KEY environment variable is required")]
    fn refuses_missing_secret_key() {
        let _lock = test_lock();
        let _secret_guard = EnvVarGuard::remove("SECRET_KEY");
        let _ = require_secret_key();
    }

    #[test]
    #[should_panic(expected = "SECRET_KEY must not be the insecure default value")]
    fn refuses_default_secret_key() {
        let _lock = test_lock();
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "default_secret_key");
        let _ = require_secret_key();
    }

    #[test]
    #[should_panic(expected = "SECRET_KEY is set but empty")]
    fn refuses_empty_secret_key() {
        let _lock = test_lock();
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "   ");
        let _ = require_secret_key();
    }

    #[test]
    #[should_panic(expected = "not a plaintext secret")]
    fn refuses_plaintext_api_key_in_yaml() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    api_key: 'sk-plaintext'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "API keys must use environment variables only")]
    fn refuses_api_key_from_vars_map() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "vars:\n  PROVIDER_KEY: sk-from-vars\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    api_key: '${{PROVIDER_KEY}}'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    fn accepts_env_var_api_key_reference() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    api_key: '${{OPENAI_API_KEY}}'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _key_guard = EnvVarGuard::set("OPENAI_API_KEY", "sk-from-env");
        reset();
        let config = app_config();
        assert_eq!(
            config.default_provider().api_key.as_deref(),
            Some("sk-from-env")
        );
        reset();
    }

    #[test]
    fn ignores_unknown_top_level_field() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(file, "not_a_real_field: true\nllms: []").expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        // Unknown top-level keys are tolerated at runtime (forward-compatible
        // config); `llms: []` still triggers the fallback provider.
        assert_eq!(config.default_provider().provider_name, "default");
        reset();
    }

    #[test]
    #[should_panic(expected = "type 'bogus' is invalid")]
    fn refuses_invalid_provider_type() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'p'\n    type: 'bogus'\n    model_name: 'm'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "deprecated config key tts_provider")]
    fn refuses_invalid_tts_provider() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(file, "tts_provider: nope\nllms: []").expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "default_llm 'missing' not found")]
    fn refuses_missing_default_llm() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "default_llm: missing\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    fn accepts_valid_enums_without_voice_blocks() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    tier: free\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert_eq!(config.tts.model_name, "kokoro");
        assert_eq!(config.default_provider().tier.as_deref(), Some("free"));
        reset();
    }

    #[test]
    fn validated_provider_type_and_tier_are_normalized_for_runtime_use() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: ' OpenAI '\n    model_name: 'm'\n    tier: ' Premium '\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let provider = app_config().default_provider().clone();
        assert_eq!(provider.provider_type, "openai");
        assert_eq!(provider.tier.as_deref(), Some("premium"));
        reset();
    }

    #[test]
    fn loads_xai_zdr_config() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'grok'\n    type: 'xai'\n    model_name: 'grok-3'\n    xai_zdr: true\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        let provider = config.default_provider();
        assert!(provider.xai_zdr);
        // Default remains false when omitted
        reset();

        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'grok'\n    type: 'xai'\n    model_name: 'grok-3'\n"
        )
        .expect("write config");
        reset();
        let config = app_config();
        assert!(!config.default_provider().xai_zdr);
        reset();
    }

    fn write_config(dir: &Path, contents: &str) {
        fs::write(dir.join(".config.yml"), contents).expect("write config");
    }

    fn config_yml_example_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.config.yml.example")
    }

    fn config_yml_example_contents() -> String {
        fs::read_to_string(config_yml_example_path())
            .expect("read shipped .config.yml.example fixture")
    }

    #[test]
    fn accepts_shipped_config_yml_example() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), &config_yml_example_contents());
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _openai_guard = EnvVarGuard::set("OPENAI_API_KEY", "test-openai");
        let _xai_guard = EnvVarGuard::set("XAI_API_KEY", "test-xai");
        reset();
        let config = app_config();
        assert_eq!(config.tts.model_name, "kokoro");
        assert_eq!(config.session_timeout, 3600);
        assert!(config.csrf);
        assert_eq!(config.tts_access, TtsAccess::Anyone);
        assert_eq!(
            config.default_provider().provider_name,
            "Local LLM (Free Tier)"
        );
        assert_eq!(config.provider_names().len(), 3);
        reset();
    }

    #[test]
    #[should_panic(expected = "failed to read .config.yml")]
    fn refuses_unreadable_config_file() {
        let _lock = test_lock();
        // Use the shipped example as the canonical mock payload: it must be a
        // valid config when readable, but a read I/O error still fails closed.
        let example = config_yml_example_contents();
        assert!(
            parse_yaml_config_contents(&example)
                .llms
                .iter()
                .any(|p| p.provider_name == "Local LLM (Free Tier)")
        );
        let _ = load_yaml_config_from_read(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied (mocked read of .config.yml.example)",
        )));
    }

    #[test]
    fn accepts_valid_secret_key() {
        let _lock = test_lock();
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        assert_eq!(require_secret_key(), "unit_test_secret");
    }

    #[test]
    fn ignores_unknown_provider_field() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    not_a_provider_field: true\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        // Unknown provider entry keys are tolerated at runtime; the rest of
        // the entry still parses.
        assert_eq!(config.default_provider().provider_name, "p");
        reset();
    }

    #[test]
    fn config_example_has_no_unknown_keys() {
        // Strictness lives in CI, not at runtime: the shipped example must
        // parse without any ignored (unknown) keys so typos in the schema
        // are caught here instead of silently degrading on a live server.
        let value: Value =
            serde_yaml::from_str(&config_yml_example_contents()).expect("parse example YAML");
        let user_vars = extract_user_vars(&value);
        let replaced = replace_vars(value, &user_vars);

        let mut unknown = Vec::new();
        let config: RawConfig = serde_ignored::deserialize(replaced, |path| {
            unknown.push(path.to_string());
        })
        .expect("deserialize example config");

        assert!(
            unknown.is_empty(),
            ".config.yml.example contains unknown keys (fix the example or extend RawConfig): {unknown:?}"
        );
        assert!(!config.llms.is_empty());
    }

    #[test]
    #[should_panic(expected = "tier 'enterprise' is invalid")]
    fn refuses_invalid_provider_tier() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    tier: enterprise\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "session_timeout must be greater than 0")]
    fn refuses_zero_session_timeout() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), "session_timeout: 0\nllms: []\n");
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "request_timeout must be a positive finite number")]
    fn refuses_non_positive_request_timeout() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    request_timeout: 0\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "rate_limit_retries must be at most")]
    fn refuses_excessive_rate_limit_retries() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    rate_limit_retries: 11\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "request_timeout must be a positive finite number")]
    fn refuses_negative_request_timeout() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    request_timeout: -1\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "provider_name must not be empty")]
    fn refuses_empty_provider_name() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: '   '\n    type: 'openai'\n    model_name: 'm'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "model_name must not be empty")]
    fn refuses_empty_model_name() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: ''\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    #[should_panic(expected = "deprecated config key tts_voice")]
    fn refuses_removed_tts_voice_key() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "tts_voice: af_heart\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    fn refuses_every_removed_voice_key() {
        for key in REMOVED_VOICE_KEYS {
            let contents = format!("{key}: x\nllms: []\n");
            let panic = std::panic::catch_unwind(|| parse_yaml_config_contents(&contents))
                .expect_err("removed voice key must panic");
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default();
            assert!(
                message.contains(&format!("deprecated config key {key}")),
                "{key}: {message}"
            );
        }
    }

    #[test]
    fn omitted_voice_blocks_target_local_voice_service() {
        let raw = parse_yaml_config_contents("llms: []\n");
        assert_eq!(raw.tts.base_url, "http://localhost:5100/v1");
        assert_eq!(raw.tts.model_name, "kokoro");
        assert_eq!(raw.tts.sample_rate, 24_000);
        assert_eq!(raw.tts.api_key, None);
        assert_eq!(raw.tts.health_url.as_deref(), Some("http://localhost:5100/health"));
        assert_eq!(raw.stt.base_url, "http://localhost:5100/v1");
        assert_eq!(raw.stt.model_name, "parakeet-tdt-0.6b-v2");
        assert_eq!(raw.stt.health_url.as_deref(), Some("http://localhost:5100/health"));
    }

    #[test]
    fn parses_openrouter_voice_blocks_with_env_keys() {
        let _lock = test_lock();
        let _key_guard = EnvVarGuard::set("OPENROUTER_VOICE_TEST_KEY", "or-test-key");
        let raw = parse_yaml_config_contents(
            "tts:\n  type: openai\n  base_url: https://openrouter.ai/api/v1\n  api_key: '${OPENROUTER_VOICE_TEST_KEY}'\n  model_name: openai/gpt-4o-mini-tts\n  voice: alloy\n  privacy_level: non_private\nstt:\n  base_url: https://openrouter.ai/api/v1\n  api_key: '${OPENROUTER_VOICE_TEST_KEY}'\n  model_name: openai/whisper-large-v3-turbo\nllms: []\n",
        );
        assert_eq!(raw.tts.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(raw.tts.api_key.as_deref(), Some("or-test-key"));
        assert_eq!(raw.tts.model_name, "openai/gpt-4o-mini-tts");
        assert_eq!(raw.tts.voice.as_deref(), Some("alloy"));
        assert_eq!(raw.tts.sample_rate, 24_000);
        assert_eq!(raw.tts.privacy_level, PrivacyLevel::NonPrivate);
        assert_eq!(raw.tts.health_url, None);
        assert_eq!(raw.stt.api_key.as_deref(), Some("or-test-key"));
        assert_eq!(raw.stt.model_name, "openai/whisper-large-v3-turbo");
        assert_eq!(raw.stt.health_url, None);
    }

    #[test]
    #[should_panic(expected = "tts.api_key must be an environment variable reference")]
    fn refuses_plaintext_tts_api_key() {
        parse_yaml_config_contents("tts:\n  api_key: sk-plaintext\nllms: []\n");
    }

    #[test]
    #[should_panic(expected = "stt.api_key references vars:VOICE_KEY")]
    fn refuses_vars_backed_stt_api_key() {
        parse_yaml_config_contents(
            "vars:\n  VOICE_KEY: sk-plaintext\nstt:\n  api_key: '${VOICE_KEY}'\nllms: []\n",
        );
    }

    #[test]
    #[should_panic(expected = "stt.type must be openai")]
    fn refuses_non_openai_voice_type() {
        validate_voice_config(
            &TtsConfig::default(),
            &SttConfig {
                provider_type: "fish".to_string(),
                ..SttConfig::default()
            },
        );
    }

    #[test]
    #[should_panic(expected = "not a plaintext secret")]
    fn refuses_partial_env_var_api_key() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    api_key: 'prefix-${OPENAI_API_KEY}'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    fn refuses_non_string_api_key() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    api_key: 12345\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let payload = std::panic::catch_unwind(|| {
            let _ = app_config();
        })
        .expect_err("non-string api_key must panic");
        let msg = panic_message(payload.as_ref());
        assert!(
            msg.contains("must be a string environment variable reference"),
            "{msg}"
        );
        assert!(
            !msg.contains("12345"),
            "api_key value must not appear in the panic message: {msg}"
        );
    }

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            String::from("<non-string panic payload>")
        }
    }

    #[test]
    #[should_panic(expected = "failed to parse .config.yml YAML")]
    fn refuses_invalid_yaml() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(dir.path(), "llms: [\n  - this is : : not: valid yaml\n");
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
    }

    #[test]
    fn uses_defaults_when_config_path_is_directory() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join(".config.yml")).expect("mkdir .config.yml");
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert_eq!(config.default_provider().provider_type, "openai");
        reset();
    }

    #[test]
    fn accepts_omitted_empty_and_null_api_key() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'no-key'\n    type: 'openai'\n    model_name: 'm'\n  - provider_name: 'empty-key'\n    type: 'openai'\n    model_name: 'm'\n    api_key: ''\n  - provider_name: 'null-key'\n    type: 'openai'\n    model_name: 'm'\n    api_key: null\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert!(config.provider("no-key").unwrap().api_key.is_none());
        assert!(config.provider("empty-key").unwrap().api_key.is_none());
        assert!(config.provider("null-key").unwrap().api_key.is_none());
        reset();
    }

    #[test]
    fn accepts_xai_premium_and_tts_env_override() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "default_llm: grok\nllms:\n  - provider_name: grok\n    type: xai\n    model_name: grok-3\n    tier: premium\n    api_key: '${XAI_API_KEY}'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _xai_guard = EnvVarGuard::set("XAI_API_KEY", "xai-test-key");
        reset();
        let config = app_config();
        assert_eq!(config.default_provider().provider_type, "xai");
        assert_eq!(config.default_provider().tier.as_deref(), Some("premium"));
        assert_eq!(
            config.default_provider().api_key.as_deref(),
            Some("xai-test-key")
        );
        reset();
    }

    #[test]
    fn accepts_provider_name_alias() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - name: aliased\n    type: openai\n    model_name: m\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert_eq!(config.default_provider().provider_name, "aliased");
        reset();
    }

    #[test]
    fn accepts_positive_session_and_request_timeout() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "session_timeout: 120\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    request_timeout: 30.5\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert_eq!(config.session_timeout, 120);
        assert_eq!(config.default_provider().request_timeout, Some(30.5));
        reset();
    }
}
