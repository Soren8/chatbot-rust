//! MOD003 review: free-function lazy-init freeze sequence.
//!
//! The compatibility delegates must not initialize the process-global store
//! on paths the original returned early: CSRF-disabled/missing/empty
//! validation and missing/malformed rate-limit lookups. This single test owns
//! its process binary, so the global starts uninitialized: rejected lookups
//! under config A (timeout 3600) must not freeze the timeout, and the later
//! bootstrap under config B must resolve timeout 7200.

use std::env;
use std::fs;
use std::path::PathBuf;

use chatbot_core::config;
use chatbot_core::session_identity::{
    prepare_home_context, rate_limit_identity, validate_csrf_token,
};

struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    fn change_to(path: &std::path::Path) -> Self {
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

struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = env::var(key).ok();
        env::set_var(key, value);
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            env::set_var(self.key, value);
        } else {
            env::remove_var(self.key);
        }
    }
}

fn use_config(dir: &std::path::Path, contents: &str) {
    fs::write(dir.join(".config.yml"), contents).expect("write config");
    config::reset();
}

#[test]
fn rejected_and_disabled_lookups_do_not_freeze_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _cwd = CwdGuard::change_to(dir.path());
    let _secret = EnvGuard::set("SECRET_KEY", "lazy_init_test_secret");

    // Config A: CSRF disabled. Validation passes without touching the store.
    use_config(dir.path(), "session_timeout: 3600\ncsrf: false\n");

    assert_eq!(
        validate_csrf_token(Some("session=mod003-lazy"), Some("mod003-lazy"))
            .expect("disabled csrf validates"),
        true
    );

    // Config A still (timeout 3600), CSRF back on: missing/empty tokens reject
    // and missing/malformed rate lookups miss, all without store init.
    use_config(dir.path(), "session_timeout: 3600\ncsrf: true\n");

    assert_eq!(
        validate_csrf_token(Some("session=mod003-lazy"), None).expect("missing token rejects"),
        false
    );
    assert_eq!(
        validate_csrf_token(Some("session=mod003-lazy"), Some("")).expect("empty token rejects"),
        false
    );
    assert_eq!(rate_limit_identity(None), None);
    assert_eq!(rate_limit_identity(Some("no-cookie-here")), None);
    assert_eq!(rate_limit_identity(Some("session=")), None);

    // Config B: a later real bootstrap must resolve B's timeout, proving none
    // of the rejected/disabled lookups above froze the global at A's 3600.
    use_config(dir.path(), "session_timeout: 7200\ncsrf: true\n");

    let bootstrap = prepare_home_context(None).expect("bootstrap under config B");
    assert!(
        bootstrap.set_cookie.contains("Max-Age=7200"),
        "global must freeze at first real use (config B), got {}",
        bootstrap.set_cookie
    );

    config::reset();
}
