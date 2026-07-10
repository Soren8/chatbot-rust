use chatbot_core::session::{self, SessionPurgeStats};
use std::{env, sync::Mutex, sync::OnceLock};

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn purge_expired_sessions_keeps_active_chat_sessions() {
    let _guard = test_mutex().lock().unwrap();
    env::set_var("SECRET_KEY", "integration_test_secret");

    let config = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;

    let _workspace = common::TestWorkspace::with_config(config);

    let bootstrap = session::prepare_home_context(None).expect("bootstrap session");
    let _ = session::session_history(&bootstrap.session_id);

    let stats = session::purge_expired_sessions();
    assert_eq!(
        stats.chat_sessions_removed, 0,
        "active chat session should not be purged: {stats:?}"
    );
}

#[test]
fn session_purge_stats_total_removed_sums_components() {
    let stats = SessionPurgeStats {
        http_sessions_removed: 2,
        chat_sessions_removed: 3,
    };
    assert_eq!(stats.total_removed(), 5);
}