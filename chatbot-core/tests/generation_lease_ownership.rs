//! MOD006 acquired-entry ownership: locked generations survive expiry.
//!
//! Given a locked generation entry, when expiry purge runs, then the entry
//! must be retained and a second prepare must still report busy. Evicting a
//! locked entry lets expiry recreate a fresh entry while the old lease is
//! outstanding, so the old lease later settles (persists/unlocks) the new
//! entry instead of its own.

use std::sync::Arc;

use chatbot_core::config::ProviderConfig;
use chatbot_core::history::HistoryService;
use chatbot_core::session::{
    ChatRequestData, ChatService, ChatSessionStore, PrepareError, PreparePolicyError,
    SessionContext,
};

fn test_provider() -> ProviderConfig {
    ProviderConfig {
        provider_name: "default".to_string(),
        provider_type: "openai".to_string(),
        tier: None,
        model_name: "default".to_string(),
        context_size: Some(4096),
        base_url: "http://localhost".to_string(),
        api_key: None,
        allowed_providers: vec![],
        request_timeout: None,
        rate_limit_retries: None,
        rate_limit_max_wait_secs: None,
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn chat_request<'a>(message: &'a str) -> ChatRequestData<'a> {
    ChatRequestData {
        message,
        system_prompt: None,
        set_name: Some("default"),
        set_id: None,
        model_name: None,
        encrypted: false,
        send_thoughts: false,
    }
}

struct OwnedService {
    _temp: tempfile::TempDir,
    service: ChatService,
}

fn make_service_with_timeout(timeout_secs: u64, secret: &str) -> OwnedService {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_root = temp.path().join("accounts");
    let redb_path = temp.path().join("history.redb");
    let data_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&data_dir).expect("legacy dir");
    let history =
        HistoryService::open_with_data_dir(&redb_path, &data_dir, "You are helpful.".to_string())
            .expect("open history");
    let sessions = Arc::new(ChatSessionStore::new(3600, "You are helpful.".to_string()));
    // Timeout is owned by the session store; rebuild it with the requested
    // timeout so expiry is deterministic without touching globals.
    let sessions = Arc::new(ChatSessionStore::new(
        timeout_secs,
        sessions.default_prompt().to_owned(),
    ));
    let service = ChatService::new(
        Arc::clone(&sessions),
        Arc::new(history),
        account_root,
        secret.to_string(),
    );
    OwnedService {
        _temp: temp,
        service,
    }
}

#[test]
fn locked_generation_entries_survive_expiry_purge() {
    let store = ChatSessionStore::new(0, "prompt".to_string());
    let session_id = "guest_mod006_retain_locked";

    assert!(store.try_acquire_generation(session_id));

    std::thread::sleep(std::time::Duration::from_millis(5));

    let removed = store.purge_expired();

    assert_eq!(
        removed, 0,
        "locked entries must be retained, not evicted"
    );
    assert!(
        !store.try_acquire_generation(session_id),
        "locked entry must stay busy across purge"
    );

    store.release_generation(session_id);
}

#[test]
fn second_chat_prepare_stays_busy_across_expiry() {
    let owned = make_service_with_timeout(0, "mod006-busy-across-expiry");
    let session = SessionContext {
        session_id: "guest_mod006_busy_across_expiry".to_string(),
        username: None,
    };
    let provider = test_provider();

    let first = owned
        .service
        .chat_prepare_leased(&session, &chat_request("hello"), &provider, None);
    assert!(first.error.is_none());
    assert!(first.context.is_some());
    let lease = first.lease.expect("first prepare must mint a lease");

    std::thread::sleep(std::time::Duration::from_millis(5));

    let second = owned
        .service
        .chat_prepare(&session, &chat_request("hello again"), &provider, None);

    assert!(
        matches!(
            second.error,
            Some(PrepareError::Policy(PreparePolicyError::Busy))
        ),
        "second prepare must stay busy while the first lease is outstanding, got: {:?}",
        second.error
    );

    lease.release_without_persist();
}
