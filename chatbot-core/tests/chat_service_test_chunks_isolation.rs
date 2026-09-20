//! MOD-003 follow-up: owned `ChatService` test-chunk isolation.
//!
//! Given an owned `ChatService` built from explicit temp stores, when ambient
//! `CHATBOT_TEST_OPENAI_CHUNKS` is poisoned with a decoy, then guest
//! `chat_prepare` and `regenerate_prepare` must report only the explicit
//! `provider.test_chunks` (or `None` when the provider carries none) with no
//! decoy leak. Given the global handle, when the same env is poisoned, then
//! both prepares keep the established lazy env precedence (env wins) so live
//! compatibility timing is unchanged.
//!
//! Generation itself never reads `ChatContext.test_chunks`: the server builds
//! providers through `GenerationDeps` (`OpenAiProvider::new` for global with
//! the original env timing, `new_owned` for owned with explicit fakes only).
//! These tests pin the prepare population only. Guest sessions avoid history,
//! account, and config IO; no `TestWorkspace`, `.env`, `.config.yml`, or
//! `data/` is touched. Env mutation is serialized through a shared static
//! mutex held for the whole poisoned window and restored on drop.

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

use chatbot_core::config::ProviderConfig;
use chatbot_core::history::HistoryService;
use chatbot_core::session::{
    ChatRequestData, ChatService, ChatSessionStore, RegenerateRequestData, SessionContext,
};

fn env_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Holds the env mutex while `CHATBOT_TEST_OPENAI_CHUNKS` carries a poisoned
/// payload; restores the previous value on drop.
struct PoisonGuard {
    _held: MutexGuard<'static, ()>,
    previous: Option<String>,
}

impl PoisonGuard {
    fn poisoned(chunks_json: &str) -> Self {
        let held = env_mutex()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = env::var("CHATBOT_TEST_OPENAI_CHUNKS").ok();
        env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", chunks_json);
        Self {
            _held: held,
            previous,
        }
    }
}

impl Drop for PoisonGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var("CHATBOT_TEST_OPENAI_CHUNKS", value),
            None => env::remove_var("CHATBOT_TEST_OPENAI_CHUNKS"),
        }
    }
}

fn provider_with_chunks(chunks: Option<Vec<&str>>) -> ProviderConfig {
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
        test_chunks: chunks.map(|items| items.into_iter().map(str::to_owned).collect()),
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn owned_service() -> (tempfile::TempDir, ChatService) {
    let temp = tempfile::tempdir().expect("tempdir");
    let redb_path = temp.path().join("history.redb");
    let data_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&data_dir).expect("legacy dir");
    let history =
        HistoryService::open_with_data_dir(&redb_path, &data_dir, "prompt-mod003".to_string())
            .expect("open history");
    let sessions = std::sync::Arc::new(ChatSessionStore::new(3600, "prompt-mod003".to_string()));
    let service = ChatService::new(
        std::sync::Arc::clone(&sessions),
        std::sync::Arc::new(history),
        temp.path().join("accounts"),
        "mod003-chunks-secret".to_string(),
    );
    (temp, service)
}

fn guest_context(session_id: &str) -> SessionContext {
    SessionContext {
        session_id: session_id.to_string(),
        username: None,
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

fn regenerate_request<'a>(message: &'a str) -> RegenerateRequestData<'a> {
    RegenerateRequestData {
        message,
        system_prompt: None,
        set_name: Some("default"),
        set_id: None,
        model_name: None,
        encrypted: false,
        pair_index: Some(0),
        send_thoughts: false,
    }
}

#[test]
fn owned_chat_prepare_uses_provider_chunks_not_poisoned_env() {
    let (_temp, service) = owned_service();
    let _poison = PoisonGuard::poisoned(r#"["env-poison-chat-chunk"]"#);
    let session = guest_context("guest_mod003_chunks_owned_chat_explicit");
    let provider = provider_with_chunks(Some(vec!["explicit-chat-chunk"]));

    let prepared = service.chat_prepare(&session, &chat_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("chat context");
    assert_eq!(
        context.test_chunks,
        Some(vec!["explicit-chat-chunk".to_string()]),
        "owned chat must report provider chunks, not the poisoned env"
    );
    service.release_session_lock(&session.session_id);
}

#[test]
fn owned_regenerate_prepare_uses_provider_chunks_not_poisoned_env() {
    let (_temp, service) = owned_service();
    let _poison = PoisonGuard::poisoned(r#"["env-poison-regen-chunk"]"#);
    let session = guest_context("guest_mod003_chunks_owned_regen_explicit");
    let provider = provider_with_chunks(Some(vec!["explicit-regen-chunk"]));

    let prepared =
        service.regenerate_prepare(&session, &regenerate_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("regenerate context");
    assert_eq!(
        context.test_chunks,
        Some(vec!["explicit-regen-chunk".to_string()]),
        "owned regenerate must report provider chunks, not the poisoned env"
    );
    service.release_session_lock(&session.session_id);
}

#[test]
fn owned_chat_prepare_with_no_provider_chunks_stays_none_under_poisoned_env() {
    let (_temp, service) = owned_service();
    let _poison = PoisonGuard::poisoned(r#"["env-poison-chat-chunk"]"#);
    let session = guest_context("guest_mod003_chunks_owned_chat_none");
    let provider = provider_with_chunks(None);

    let prepared = service.chat_prepare(&session, &chat_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("chat context");
    assert_eq!(
        context.test_chunks, None,
        "owned chat with no provider chunks must stay None under poisoned env"
    );
    service.release_session_lock(&session.session_id);
}

#[test]
fn owned_regenerate_prepare_with_no_provider_chunks_stays_none_under_poisoned_env() {
    let (_temp, service) = owned_service();
    let _poison = PoisonGuard::poisoned(r#"["env-poison-regen-chunk"]"#);
    let session = guest_context("guest_mod003_chunks_owned_regen_none");
    let provider = provider_with_chunks(None);

    let prepared =
        service.regenerate_prepare(&session, &regenerate_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("regenerate context");
    assert_eq!(
        context.test_chunks, None,
        "owned regenerate with no provider chunks must stay None under poisoned env"
    );
    service.release_session_lock(&session.session_id);
}

#[test]
fn global_chat_prepare_keeps_env_precedence_over_provider_chunks() {
    let _poison = PoisonGuard::poisoned(r#"["env-poison-chat-chunk"]"#);
    let service = ChatService::global();
    let session = guest_context("guest_mod003_chunks_global_chat");
    let provider = provider_with_chunks(Some(vec!["explicit-chat-chunk"]));

    let prepared = service.chat_prepare(&session, &chat_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("chat context");
    assert_eq!(
        context.test_chunks,
        Some(vec!["env-poison-chat-chunk".to_string()]),
        "global chat must keep lazy env precedence"
    );
    service.release_session_lock(&session.session_id);
}

#[test]
fn global_regenerate_prepare_keeps_env_precedence_over_provider_chunks() {
    let _poison = PoisonGuard::poisoned(r#"["env-poison-regen-chunk"]"#);
    let service = ChatService::global();
    let session = guest_context("guest_mod003_chunks_global_regen");
    let provider = provider_with_chunks(Some(vec!["explicit-regen-chunk"]));

    let prepared =
        service.regenerate_prepare(&session, &regenerate_request("hello"), &provider, None);

    assert!(prepared.error.is_none(), "prepare must succeed");
    let context = prepared.context.expect("regenerate context");
    assert_eq!(
        context.test_chunks,
        Some(vec!["env-poison-regen-chunk".to_string()]),
        "global regenerate must keep lazy env precedence"
    );
    service.release_session_lock(&session.session_id);
}
