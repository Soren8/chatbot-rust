use std::{env, path::PathBuf, sync::Once};

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

/// Initialise tracing once for tests; additional calls become no-ops.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}
