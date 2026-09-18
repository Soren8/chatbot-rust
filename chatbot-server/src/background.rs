use std::{env, time::Duration};
use tracing::info;

/// Background purge for the router's identity: expired records are purged
/// from that same HTTP store instance, plus the shared chat store.
pub fn spawn_session_purge_task_with_identity(
    identity: crate::identity::RequestIdentity,
) {
    let interval_secs = purge_interval_secs();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let (http_sessions_removed, chat_sessions_removed) = identity.purge_for_background();
            let remember_removed = chatbot_core::remember_store::RememberStore::new()
                .map(|store| store.purge_expired())
                .unwrap_or(0);
            if http_sessions_removed + chat_sessions_removed > 0 || remember_removed > 0 {
                info!(
                    http_sessions_removed,
                    chat_sessions_removed,
                    remember_tokens_removed = remember_removed,
                    "background session purge completed"
                );
            }
        }
    });
}

/// Background purge for a fully composed router: expired records are purged
/// from that same [`crate::services::AppServices`] identity plus that same
/// chat service plus that same account remember store, so an owned production
/// router never initializes or purges the unrelated global HTTP/chat/remember
/// stores. Compatibility routers carry the global account service, preserving
/// the previous global remember behavior.
pub fn spawn_session_purge_task_with_services(services: crate::services::AppServices) {
    let interval_secs = purge_interval_secs();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let (http_sessions_removed, chat_sessions_removed) =
                services.purge_for_background();
            let remember_removed = services.purge_remember_for_background();
            if http_sessions_removed + chat_sessions_removed > 0 || remember_removed > 0 {
                info!(
                    http_sessions_removed,
                    chat_sessions_removed,
                    remember_tokens_removed = remember_removed,
                    "background session purge completed"
                );
            }
        }
    });
}

fn purge_interval_secs() -> u64 {
    env::var("SESSION_PURGE_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(300)
}
