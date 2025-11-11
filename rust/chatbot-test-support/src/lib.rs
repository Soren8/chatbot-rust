use chatbot_core::{config, persistence::DataPersistence, user_store::UserStore};
use regex::Regex;
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Once,
};
use tempfile::TempDir;
use tracing_subscriber::EnvFilter;

static TRACING_INIT: Once = Once::new();

/// Initialise tracing once for tests; additional calls become no-ops.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}

pub fn extract_csrf_token(html: &str) -> Option<String> {
    let re = Regex::new(r#"name="csrf_token" value="([^"]+)""#).unwrap();
    re.captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
}

pub fn extract_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

pub struct TestWorkspace {
    temp_dir: TempDir,
    original_cwd: PathBuf,
    previous_host_data_dir: Option<String>,
}

impl TestWorkspace {
    pub fn with_openai_provider() -> Self {
        const CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;

        Self::with_config(CONFIG)
    }

    pub fn with_config(config: &str) -> Self {
        let original_cwd = env::current_dir().expect("missing current dir");
        let temp_dir = TempDir::new().expect("tempdir");

        let config_path = temp_dir.path().join(".config.yml");
        fs::write(&config_path, config).expect("write config");

        env::set_current_dir(temp_dir.path()).expect("set current dir");
        let previous_host_data_dir = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", temp_dir.path());

        config::reset();

        // Initialise core data directories so tests can assume they exist.
        UserStore::new().expect("initialise user store");
        DataPersistence::new().expect("initialise data persistence");

        Self {
            temp_dir,
            original_cwd,
            previous_host_data_dir,
        }
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.original_cwd);
        if let Some(previous) = &self.previous_host_data_dir {
            env::set_var("HOST_DATA_DIR", previous);
        } else {
            env::remove_var("HOST_DATA_DIR");
        }
    }
}
