//! MOD-003 owned purge ownership.
//!
//! The owned purge path must leave the global HTTP store uninitialized. This
//! binary initializes the global HTTP store only in the final bootstrap,
//! which asserts the owned purge left it alone.

use std::{
    env,
    sync::{Arc, Mutex, OnceLock},
};

use chatbot_core::session_identity::HttpSessionStore;
use chatbot_server::identity::RequestIdentity;

mod common;

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn setup_with_timeout(session_timeout: u64) -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_config(&format!(
        "\nllms:\n  - provider_name: \"default\"\n    type: \"openai\"\n    model_name: \"gpt-test\"\n    base_url: \"https://api.openai.com/v1\"\n    api_key: \"${{OPENAI_API_KEY}}\"\n    context_size: 4096\nsession_timeout: {session_timeout}\n"
    ))
}

#[tokio::test]
async fn owned_purge_leaves_global_http_uninitialized() {
    common::init_tracing();
    let _guard = lock_tests();

    {
        let _workspace = setup_with_timeout(3600);
        let store = Arc::new(HttpSessionStore::new(3600));
        let identity = RequestIdentity::with_store_and_csrf(store, true);
        let (http_removed, _) = identity.purge_for_background();
        assert_eq!(http_removed, 0, "empty owned store purges nothing");
    }

    let _workspace = setup_with_timeout(7200);
    let bootstrap = chatbot_core::session::prepare_home_context(None).expect("global bootstrap");
    assert!(
        bootstrap.set_cookie.contains("Max-Age=7200"),
        "global must freeze at first real use under the second config, got {}",
        bootstrap.set_cookie
    );

    chatbot_core::config::reset();
}
