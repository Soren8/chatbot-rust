use chatbot_core::session;
use std::{env, time::Duration};
use tracing::info;

pub fn spawn_session_purge_task() {
    let interval_secs = env::var("SESSION_PURGE_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(300);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let stats = session::purge_expired_sessions();
            if stats.total_removed() > 0 {
                info!(
                    http_sessions_removed = stats.http_sessions_removed,
                    chat_sessions_removed = stats.chat_sessions_removed,
                    "background session purge completed"
                );
            }
        }
    });
}