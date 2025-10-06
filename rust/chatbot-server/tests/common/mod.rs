use chatbot_core::config;
use pyo3::prelude::*;
use regex::Regex;
use std::{env, fs, path::Path, path::PathBuf, sync::Once};
use tempfile::TempDir;

static PYTHONPATH_INIT: Once = Once::new();
static TRACING_INIT: Once = Once::new();

/// Ensure the Python sources from the workspace are on PYTHONPATH so bridge calls succeed.
pub fn ensure_pythonpath() {
    PYTHONPATH_INIT.call_once(|| {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("workspace root");

        let mut entries: Vec<String> = Vec::new();

        if let Ok(current) = env::var("PYTHONPATH") {
            if !current.is_empty() {
                entries.push(current);
            }
        }

        entries.push(repo_root.to_str().expect("utf8 path").to_owned());

        if let Ok(venv_root) = env::var("VIRTUAL_ENV") {
            let site_packages = PathBuf::from(&venv_root)
                .join("lib")
                .join("python3.11")
                .join("site-packages");
            if site_packages.exists() {
                entries.push(site_packages.to_string_lossy().into_owned());
            }
        } else {
            let default_site = PathBuf::from("/opt/venv/lib/python3.11/site-packages");
            if default_site.exists() {
                entries.push(default_site.to_string_lossy().into_owned());
            }
        }

        let joined = entries.join(":");
        env::set_var("PYTHONPATH", joined);
    });
}

/// Ensure Flask is importable; returns false when the dependency is missing so
/// callers can gracefully skip integration tests.
pub fn ensure_flask_available() -> bool {
    ensure_pythonpath();
    Python::with_gil(|py| py.import("flask").is_ok())
}

/// Initialise tracing once for tests; additional calls become no-ops.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        let original_cwd = env::current_dir().expect("missing current dir");
        let temp_dir = TempDir::new().expect("tempdir");
        write_openai_config(temp_dir.path());

        env::set_current_dir(temp_dir.path()).expect("set current dir");
        let previous_host_data_dir = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", temp_dir.path());

        config::reset();

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

fn write_openai_config(dir: &Path) {
    const CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;

    let path = dir.join(".config.yml");
    fs::write(path, CONFIG).expect("write config");
}
