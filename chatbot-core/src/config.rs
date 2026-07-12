use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProviderConfig {
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
    #[serde(default)]
    pub test_chunks: Option<Vec<String>>,
    #[serde(default)]
    pub search: bool,
    /// When true (default), XAI providers use XAI's own web_search tool via the
    /// Responses API. When false, Brave Search is used instead (requires BRAVE_API_KEY).
    /// Ignored for non-XAI providers.
    #[serde(default = "default_true")]
    pub xai_search: bool,
}

fn default_true() -> bool {
    true
}

impl ProviderConfig {
    fn finalize(mut self) -> Self {
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

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub secret_key: String,
    pub host_data_dir: PathBuf,
    pub log_level: String,
    pub tts_base_url: String,
    pub tts_provider: String,
    pub tts_voice: Option<String>,
    pub voice_service_base_url: String,
    pub stt_enabled: bool,
    pub default_system_prompt: String,
    pub session_timeout: u64,
    pub csrf: bool,
    pub save_thoughts: bool,
    pub send_thoughts: bool,
    pub cdn_sri: HashMap<String, String>,
    pub brave_api_key: Option<String>,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    llms: Vec<ProviderConfig>,
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
    tts_provider: Option<String>,
    #[serde(default)]
    tts_voice: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_flexible")]
    stt_enabled: Option<bool>,
    #[serde(default)]
    voice_service_host: Option<String>,
    #[serde(default)]
    voice_service_port: Option<u16>,
    /// Consumed by Compose / voice-service; accepted so schema validation stays
    /// aligned with `.config.yml.example`.
    #[serde(default)]
    #[allow(dead_code)]
    voice_gpu_device: Option<u32>,
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

/// Insecure placeholder previously used when `SECRET_KEY` was unset.
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
    let tts_host = env::var("TTS_HOST").unwrap_or_else(|_| "localhost".to_string());
    let tts_port = env::var("TTS_PORT").unwrap_or_else(|_| "5000".to_string());
    let tts_base_url = format!("http://{tts_host}:{tts_port}");

    let cdn_sri = build_cdn_sri_map();

    let raw_config = load_yaml_config().unwrap_or_default();

    let voice_service_host = raw_config
        .voice_service_host
        .as_deref()
        .unwrap_or("localhost")
        .to_string();
    let voice_service_port = raw_config.voice_service_port.unwrap_or(5100);
    let voice_service_base_url = format!("http://{voice_service_host}:{voice_service_port}");

    // TTS provider: env var overrides YAML, which defaults to kokoro
    let tts_provider: String = if let Ok(env_value) = env::var("TTS_PROVIDER") {
        env_value
            .split('#')
            .next()
            .unwrap_or("kokoro")
            .trim()
            .to_lowercase()
    } else if let Some(yaml_value) = raw_config.tts_provider {
        yaml_value.to_lowercase()
    } else {
        "kokoro".to_string()
    };
    validate_tts_provider(&tts_provider);

    debug!(tts_provider = %tts_provider, "loaded TTS provider configuration");

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
        env_csrf.to_lowercase() == "on" || env_csrf.to_lowercase() == "true"
    } else {
        raw_config.csrf.unwrap_or(true)
    };

    let save_thoughts = raw_config.save_thoughts.unwrap_or(true);
    let send_thoughts = raw_config.send_thoughts.unwrap_or(false);
    let tts_voice = raw_config.tts_voice;
    let stt_enabled = raw_config.stt_enabled.unwrap_or(true);

    let brave_api_key = env::var("BRAVE_API_KEY").ok().filter(|v| !v.is_empty());

    info!(
        effective_save = save_thoughts,
        effective_send = send_thoughts,
        "effective config values for thinking tokens"
    );

    debug!(tts_voice = ?tts_voice, "loaded TTS voice configuration");

    if brave_api_key.is_some() {
        info!("Brave Search configured");
    } else {
        info!("Brave Search not configured (BRAVE_API_KEY not set)");
    }

    info!(
        providers = providers_by_name.len(),
        default_provider = %default_provider_name,
        csrf_enabled = csrf,
        "configuration loaded"
    );

    AppConfig {
        secret_key,
        host_data_dir,
        log_level,
        tts_base_url,
        tts_provider,
        tts_voice,
        voice_service_base_url,
        stt_enabled,
        default_system_prompt,
        session_timeout,
        csrf,
        save_thoughts,
        send_thoughts,
        cdn_sri,
        brave_api_key,
        provider_order,
        providers_by_name,
        default_provider_name,
    }
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
const ALLOWED_TTS_PROVIDERS: &[&str] = &["kokoro", "qwen", "fish"];

fn validate_tts_provider(value: &str) {
    let normalized = value.trim().to_lowercase();
    if !ALLOWED_TTS_PROVIDERS.contains(&normalized.as_str()) {
        panic!(
            "invalid tts_provider '{value}'; expected one of {}",
            ALLOWED_TTS_PROVIDERS.join(", ")
        );
    }
}

fn validate_raw_config(config: &RawConfig) {
    if let Some(timeout) = config.session_timeout {
        if timeout == 0 {
            panic!("session_timeout must be greater than 0");
        }
    }

    if let Some(tts) = config.tts_provider.as_deref() {
        validate_tts_provider(tts);
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
    let Some(Value::Sequence(llms)) = root.get(Value::String("llms".to_string())) else {
        return;
    };
    let user_vars = extract_user_vars(value);

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
            other => {
                panic!(
                    "llms[{idx}].api_key must be a string environment variable reference, got {other:?}"
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

fn build_cdn_sri_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(
        "jquery".to_string(),
        env::var("SRI_JQUERY").unwrap_or_else(|_| {
            "sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK".to_string()
        }),
    );
    map.insert(
        "bootstrap_css".to_string(),
        env::var("SRI_BOOTSTRAP_CSS").unwrap_or_else(|_| {
            "sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM".to_string()
        }),
    );
    map.insert(
        "bootstrap_js".to_string(),
        env::var("SRI_BOOTSTRAP_JS").unwrap_or_else(|_| {
            "sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz".to_string()
        }),
    );
    map.insert(
        "bootstrap_icons_css".to_string(),
        env::var("SRI_BOOTSTRAP_ICONS_CSS").unwrap_or_else(|_| {
            "sha384-Ay26V7L8bsJTsX9Sxclnvsn+hkdiwRnrjZJXqKmkIDobPgIIWBOVguEcQQLDuhfN".to_string()
        }),
    );
    map
}

fn fallback_provider() -> ProviderConfig {
    ProviderConfig {
        provider_name: "default".to_string(),
        provider_type: "openai".to_string(),
        tier: Some("free".to_string()),
        model_name: "local-model".to_string(),
        context_size: Some(8192),
        base_url: "http://127.0.0.1:11434/v1".to_string(),
        api_key: None,
        allowed_providers: Vec::new(),
        request_timeout: None,
        test_chunks: None,
        search: false,
        xai_search: true,
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
    #[should_panic(expected = "unknown field")]
    fn refuses_unknown_top_level_field() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(file, "not_a_real_field: true\nllms: []").expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
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
    #[should_panic(expected = "invalid tts_provider")]
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
    fn accepts_voice_gpu_device_and_valid_enums() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "tts_provider: kokoro\nvoice_gpu_device: 0\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    tier: free\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let config = app_config();
        assert_eq!(config.tts_provider, "kokoro");
        assert_eq!(config.default_provider().tier.as_deref(), Some("free"));
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
        assert_eq!(config.tts_provider, "kokoro");
        assert_eq!(config.session_timeout, 3600);
        assert!(!config.csrf);
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
    #[should_panic(expected = "unknown field")]
    fn refuses_unknown_provider_field() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "llms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n    not_a_provider_field: true\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        reset();
        let _ = app_config();
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
    #[should_panic(expected = "invalid tts_provider")]
    fn refuses_invalid_tts_provider_env_override() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        write_config(
            dir.path(),
            "tts_provider: kokoro\nllms:\n  - provider_name: 'p'\n    type: 'openai'\n    model_name: 'm'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _tts_guard = EnvVarGuard::set("TTS_PROVIDER", "not-a-provider");
        reset();
        let _ = app_config();
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
    #[should_panic(expected = "must be a string environment variable reference")]
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
        let _ = app_config();
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
            "tts_provider: kokoro\ndefault_llm: grok\nllms:\n  - provider_name: grok\n    type: xai\n    model_name: grok-3\n    tier: premium\n    api_key: '${XAI_API_KEY}'\n",
        );
        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _secret_guard = EnvVarGuard::set("SECRET_KEY", "unit_test_secret");
        let _xai_guard = EnvVarGuard::set("XAI_API_KEY", "xai-test-key");
        let _tts_guard = EnvVarGuard::set("TTS_PROVIDER", "fish");
        reset();
        let config = app_config();
        assert_eq!(config.tts_provider, "fish");
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
