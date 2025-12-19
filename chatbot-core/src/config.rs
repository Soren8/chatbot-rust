use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default, deserialize_with = "deserialize_allowed_providers")]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub request_timeout: Option<f64>,
    #[serde(default)]
    pub test_chunks: Option<Vec<String>>,
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
    pub default_system_prompt: String,
    pub session_timeout: u64,
    pub csrf: bool,
    pub cdn_sri: HashMap<String, String>,
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
        let guard = APP_CONFIG.read().expect("config read lock");
        if let ConfigState::Ready(config) = &*guard {
            return Arc::clone(config);
        }
    }

    let mut guard = APP_CONFIG.write().expect("config write lock");
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
    let mut guard = APP_CONFIG.write().expect("config write lock");
    *guard = ConfigState::Uninitialized;
}

#[derive(Debug, Default, Deserialize)]
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

fn load_app_config() -> AppConfig {
    if dotenvy::dotenv().is_ok() {
        debug!("loaded environment variables from .env");
    }

    let secret_key = env::var("SECRET_KEY").unwrap_or_else(|_| "default_secret_key".to_string());
    let host_data_dir =
        PathBuf::from(env::var("HOST_DATA_DIR").unwrap_or_else(|_| "./data".to_string()));
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
    let tts_host = env::var("TTS_HOST").unwrap_or_else(|_| "localhost".to_string());
    let tts_port = env::var("TTS_PORT").unwrap_or_else(|_| "5000".to_string());
    let tts_base_url = format!("http://{tts_host}:{tts_port}");

    let cdn_sri = build_cdn_sri_map();

    let raw_config = load_yaml_config().unwrap_or_default();

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

    let default_provider_name = raw_config
        .default_llm
        .and_then(|name| {
            if providers_by_name.contains_key(&name) {
                Some(name)
            } else {
                warn!(provider = %name, "default_llm not found in provider list");
                None
            }
        })
        .or_else(|| provider_order.first().cloned())
        .unwrap();

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
        default_system_prompt,
        session_timeout,
        csrf,
        cdn_sri,
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

    match fs::read_to_string(path) {
        Ok(contents) => match serde_yaml::from_str::<Value>(&contents) {
            Ok(value) => {
                let replaced = replace_env_vars(value);
                match serde_yaml::from_value::<RawConfig>(replaced) {
                    Ok(config) => Some(config),
                    Err(err) => {
                        error!(?err, "invalid configuration content; using defaults");
                        None
                    }
                }
            }
            Err(err) => {
                error!(?err, "failed to parse configuration YAML; using defaults");
                None
            }
        },
        Err(err) => {
            error!(?err, "failed to read configuration file; using defaults");
            None
        }
    }
}

fn replace_env_vars(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(replace_env_in_str(&s)),
        Value::Sequence(seq) => Value::Sequence(seq.into_iter().map(replace_env_vars).collect()),
        Value::Mapping(map) => {
            let mut replaced = Mapping::new();
            for (key, value) in map.into_iter() {
                let key = match key {
                    Value::String(s) => Value::String(replace_env_in_str(&s)),
                    other => other,
                };
                replaced.insert(key, replace_env_vars(value));
            }
            Value::Mapping(replaced)
        }
        other => other,
    }
}

fn replace_env_in_str(input: &str) -> String {
    static ENV_VAR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\$\{([^}]+)\}").expect("env var regex"));
    ENV_VAR_RE
        .replace_all(input, |caps: &regex::Captures<'_>| {
            env::var(&caps[1]).unwrap_or_default()
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
        provider_type: "ollama".to_string(),
        tier: Some("free".to_string()),
        model_name: "dolphin3.1-8b".to_string(),
        context_size: Some(8192),
        base_url: String::new(),
        api_key: None,
        template: None,
        allowed_providers: Vec::new(),
        request_timeout: None,
        test_chunks: None,
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
        let _lock = TEST_MUTEX.lock().expect("test mutex");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        let mut file = fs::File::create(&path).expect("create config");
        writeln!(
            file,
            "llms:\n  - provider_name: 'env-model'\n    type: 'stub'\n    model_name: '${{MODEL}}'\n"
        )
        .expect("write config");

        let _cwd_guard = CwdGuard::change_to(dir.path());
        let _model_guard = EnvVarGuard::set("MODEL", "injected-model");

        reset();
        let config = app_config();
        let provider = config.default_provider();
        assert_eq!(provider.model_name, "injected-model");

        reset();
    }

    #[test]
    fn loads_csrf_config() {
        let _lock = TEST_MUTEX.lock().expect("test mutex");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".config.yml");
        
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
        let _lock = TEST_MUTEX.lock().expect("test mutex");
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd_guard = CwdGuard::change_to(dir.path());
        reset();
        let provider_type = app_config().default_provider().provider_type.clone();
        assert_eq!(provider_type, "ollama");
        reset();
    }
}
