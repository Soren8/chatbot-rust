//! Characterization of chat/regenerate finalization stream extras (MOD-006).
//!
//! Given a prepared or ad-hoc session, when chat/regenerate finalization runs,
//! then the returned stream-error extras must match the long-standing rendered
//! strings: guest success and missing sessions return no extras, missing or
//! wrong keys share one missing-key string, stale captures conflict, empty
//! user text reports its detail, and unknown-set fallbacks report a generic
//! store failure. Regenerate replaces without extras.
//!
//! These tests pin the actual existing `Vec<String>` behavior before the typed
//! outcome extraction; they must pass unchanged before and after.

use std::path::PathBuf;
use std::sync::Arc;

use chatbot_core::config::ProviderConfig;
use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::HistoryService;
use chatbot_core::session::{
    ChatRequestData, ChatService, ChatSessionStore, FinalizeOutcome, SessionContext,
};
use chatbot_core::user_store::UserStore;

const MISSING_KEY_EXTRA: &str = "\n[Error] Failed to save chat history: missing encryption key";
const CONFLICT_EXTRA: &str = "\n[Error] Chat history conflict — reload the set and retry.";
const GENERIC_FAILURE_EXTRA: &str = "\n[Error] Failed to save chat history";

fn test_provider() -> ProviderConfig {
    ProviderConfig {
        privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
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

fn test_key() -> EncryptionKey {
    EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
        .expect("test key")
}

fn wrong_key() -> EncryptionKey {
    EncryptionKey::from_header_value("d3Jvbmcta2V5LW1hdGVyaWFsLTAwMDAwMDAwMDAwMDAwMDA=")
        .expect("wrong key")
}

fn guest_context(session_id: &str) -> SessionContext {
    SessionContext {
        session_id: session_id.to_string(),
        username: None,
    }
}

fn authed_context(username: &str) -> SessionContext {
    SessionContext {
        session_id: username.to_string(),
        username: Some(username.to_string()),
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
    account_root: PathBuf,
    secret: String,
}

fn make_service(secret: &str) -> OwnedService {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_root = temp.path().join("accounts");
    let redb_path = temp.path().join("history.redb");
    let data_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&data_dir).expect("legacy dir");
    let history =
        HistoryService::open_with_data_dir(&redb_path, &data_dir, "You are a helpful assistant.")
            .expect("open history");
    let sessions = Arc::new(ChatSessionStore::new(3600, "You are a helpful assistant.".to_string()));
    let service = ChatService::new(
        Arc::clone(&sessions),
        Arc::new(history),
        account_root.clone(),
        secret.to_string(),
    );
    UserStore::open(&account_root).expect("open account store");
    OwnedService {
        _temp: temp,
        service,
        account_root,
        secret: secret.to_string(),
    }
}

fn enroll(owned: &OwnedService, username: &str, key: &EncryptionKey) {
    UserStore::open(&owned.account_root)
        .expect("open store")
        .ensure_key_verifier_with_secret(username, key.as_bytes(), owned.secret.as_bytes())
        .expect("enroll verifier");
}

#[test]
fn guest_chat_finalize_appends_without_extras() {
    let owned = make_service("char-secret-guest-ok");
    let session_id = "guest_mod006_char_guest_ok";
    let session = guest_context(session_id);

    assert!(owned.service.try_acquire_generation(session_id));

    let extras = owned
        .service
        .chat_finalize(&session, "default", "hi", "hello", None);

    assert!(extras.is_empty(), "guest success must return no extras: {extras:?}");
    assert_eq!(
        owned.service.session_history(session_id),
        vec![("hi".to_string(), "hello".to_string())]
    );
}

#[test]
fn chat_finalize_without_entry_is_noop_without_extras() {
    let owned = make_service("char-secret-missing");
    let session = guest_context("guest_mod006_char_missing_never_created_9f3a");

    let extras = owned
        .service
        .chat_finalize(&session, "default", "hi", "hello", None);

    assert!(extras.is_empty(), "missing session must be a no-op: {extras:?}");
    assert!(owned.service.session_history(&session.session_id).is_empty());
}

#[test]
fn authed_chat_finalize_without_key_reports_missing_key() {
    let owned = make_service("char-secret-nokey");
    let username = "mod006_char_nokey";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    assert!(owned.service.try_acquire_generation(username));

    let extras = owned
        .service
        .chat_finalize(&session, "default", "hi", "hello", None);

    assert_eq!(extras, vec![MISSING_KEY_EXTRA.to_string()]);
}

#[test]
fn authed_chat_finalize_with_wrong_key_reports_same_missing_key() {
    let owned = make_service("char-secret-wrongkey");
    let username = "mod006_char_wrongkey";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    assert!(owned.service.try_acquire_generation(username));

    let extras = owned.service.chat_finalize(
        &session,
        "default",
        "hi",
        "hello",
        Some(&wrong_key()),
    );

    assert_eq!(
        extras,
        vec![MISSING_KEY_EXTRA.to_string()],
        "wrong key must share the missing-key string intentionally"
    );
}

#[test]
fn authed_chat_finalize_with_stale_capture_reports_conflict() {
    let owned = make_service("char-secret-conflict");
    let username = "mod006_char_conflict";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);
    let provider = test_provider();

    let prepared = owned
        .service
        .chat_prepare_leased(&session, &chat_request("first"), &provider, Some(&key));
    assert!(prepared.error.is_none());
    let capture = prepared.context.expect("context").prepare_capture.expect("capture");
    let lease = prepared.lease.expect("lease");
    let first_extras = lease.complete_chat("default", "first", "a1", Some(&key), Some(capture.clone()));
    assert!(first_extras.is_empty());

    let extras = owned.service.chat_finalize_with_capture(
        &session,
        "default",
        "stale-msg",
        "stale-ai",
        Some(&key),
        Some(capture),
    );

    assert_eq!(extras, vec![CONFLICT_EXTRA.to_string()]);
}

#[test]
fn authed_chat_finalize_with_empty_user_reports_invalid_input_detail() {
    let owned = make_service("char-secret-invalid");
    let username = "mod006_char_invalid";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);
    let provider = test_provider();

    let prepared = owned
        .service
        .chat_prepare_leased(&session, &chat_request("valid"), &provider, Some(&key));
    assert!(prepared.error.is_none());
    let capture = prepared.context.expect("context").prepare_capture.expect("capture");
    prepared.lease.expect("lease").release_without_persist();

    let extras = owned.service.chat_finalize_with_capture(
        &session,
        "default",
        "",
        "resp",
        Some(&key),
        Some(capture),
    );

    assert_eq!(
        extras,
        vec!["\n[Error] Failed to save chat history: empty user message".to_string()]
    );
}

#[test]
fn authed_chat_finalize_without_capture_for_unknown_set_reports_store_failure() {
    let owned = make_service("char-secret-storefail");
    let username = "mod006_char_storefail";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    assert!(owned.service.try_acquire_generation(username));

    let extras = owned.service.chat_finalize(
        &session,
        "no-such-set-xyz",
        "hi",
        "hello",
        Some(&key),
    );

    assert_eq!(extras, vec![GENERIC_FAILURE_EXTRA.to_string()]);
}

#[test]
fn guest_regenerate_finalize_replaces_without_extras() {
    let owned = make_service("char-secret-regen");
    let session_id = "guest_mod006_char_regen_ok";
    let session = guest_context(session_id);

    owned
        .service
        .update_session_history(session_id, &[("u1".to_string(), "a1".to_string())]);
    assert!(owned.service.try_acquire_generation(session_id));

    let extras = owned.service.regenerate_finalize(&session, "default", "u1", "a2", Some(0), None);

    assert!(extras.is_empty(), "guest regenerate must return no extras: {extras:?}");
    assert_eq!(
        owned.service.session_history(session_id),
        vec![("u1".to_string(), "a2".to_string())]
    );
}

// Typed outcome assertions after extraction: same scenarios return the
// canonical enum, and lease typed completion settles exactly once.

#[test]
fn typed_guest_chat_finalize_returns_guest_updated() {
    let owned = make_service("typed-secret-guest-ok");
    let session_id = "guest_mod006_typed_guest_ok";
    let session = guest_context(session_id);
    assert!(owned.service.try_acquire_generation(session_id));

    let outcome = owned
        .service
        .chat_finalize_outcome(&session, "default", "hi", "hello", None);

    assert_eq!(outcome, FinalizeOutcome::GuestUpdated);
    assert_eq!(
        owned.service.session_history(session_id),
        vec![("hi".to_string(), "hello".to_string())]
    );
}

#[test]
fn typed_chat_finalize_without_entry_returns_no_session() {
    let owned = make_service("typed-secret-missing");
    let session = guest_context("guest_mod006_typed_missing_never_created_7c1d");

    let outcome = owned
        .service
        .chat_finalize_outcome(&session, "default", "hi", "hello", None);

    assert_eq!(outcome, FinalizeOutcome::NoSession);
}

#[test]
fn typed_authed_finalize_key_failures_share_key_validation_failed() {
    let owned = make_service("typed-secret-nokey");
    let username = "mod006_typed_nokey";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    assert!(owned.service.try_acquire_generation(username));
    let missing = owned
        .service
        .chat_finalize_outcome(&session, "default", "hi", "hello", None);
    assert_eq!(missing, FinalizeOutcome::KeyValidationFailed);

    assert!(owned.service.try_acquire_generation(username));
    let wrong = owned.service.chat_finalize_outcome(
        &session,
        "default",
        "hi",
        "hello",
        Some(&wrong_key()),
    );
    assert_eq!(wrong, FinalizeOutcome::KeyValidationFailed);
}

#[test]
fn typed_authed_finalize_with_stale_capture_returns_conflict() {
    let owned = make_service("typed-secret-conflict");
    let username = "mod006_typed_conflict";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);
    let provider = test_provider();

    let prepared = owned
        .service
        .chat_prepare_leased(&session, &chat_request("first"), &provider, Some(&key));
    assert!(prepared.error.is_none());
    let capture = prepared.context.expect("context").prepare_capture.expect("capture");
    let lease = prepared.lease.expect("lease");
    let first = lease.complete_chat_outcome("default", "first", "a1", Some(&key), Some(capture.clone()));
    assert_eq!(first, FinalizeOutcome::DurableCommitted);

    let outcome = owned.service.chat_finalize_outcome_with_capture(
        &session,
        "default",
        "stale-msg",
        "stale-ai",
        Some(&key),
        Some(capture),
    );
    assert_eq!(outcome, FinalizeOutcome::Conflict);
}

#[test]
fn typed_authed_finalize_with_empty_user_returns_invalid_input() {
    let owned = make_service("typed-secret-invalid");
    let username = "mod006_typed_invalid";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);
    let provider = test_provider();

    let prepared = owned
        .service
        .chat_prepare_leased(&session, &chat_request("valid"), &provider, Some(&key));
    assert!(prepared.error.is_none());
    let capture = prepared.context.expect("context").prepare_capture.expect("capture");
    prepared.lease.expect("lease").release_without_persist();

    let outcome = owned.service.chat_finalize_outcome_with_capture(
        &session,
        "default",
        "",
        "resp",
        Some(&key),
        Some(capture),
    );
    assert_eq!(
        outcome,
        FinalizeOutcome::InvalidInput("empty user message".to_string())
    );
}

#[test]
fn typed_authed_finalize_without_capture_for_unknown_set_returns_store_failure() {
    let owned = make_service("typed-secret-storefail");
    let username = "mod006_typed_storefail";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);
    assert!(owned.service.try_acquire_generation(username));

    let outcome = owned.service.chat_finalize_outcome(
        &session,
        "no-such-set-xyz",
        "hi",
        "hello",
        Some(&key),
    );
    assert_eq!(outcome, FinalizeOutcome::StoreFailure);
}

#[test]
fn typed_guest_regenerate_finalize_returns_guest_updated() {
    let owned = make_service("typed-secret-regen");
    let session_id = "guest_mod006_typed_regen_ok";
    let session = guest_context(session_id);
    owned
        .service
        .update_session_history(session_id, &[("u1".to_string(), "a1".to_string())]);
    assert!(owned.service.try_acquire_generation(session_id));

    let outcome =
        owned
            .service
            .regenerate_finalize_outcome(&session, "default", "u1", "a2", Some(0), None);
    assert_eq!(outcome, FinalizeOutcome::GuestUpdated);
    assert_eq!(
        owned.service.session_history(session_id),
        vec![("u1".to_string(), "a2".to_string())]
    );
}

#[test]
fn typed_lease_complete_settles_exactly_once() {
    let owned = make_service("typed-secret-lease-once");
    let session_id = "guest_mod006_typed_lease_once";
    let session = guest_context(session_id);
    let provider = test_provider();

    let prepared =
        owned
            .service
            .chat_prepare_leased(&session, &chat_request("hello"), &provider, None);
    assert!(prepared.error.is_none());
    let lease = prepared.lease.expect("lease");

    let outcome = lease.complete_chat_outcome("default", "hello", "hi there", None, None);
    assert_eq!(outcome, FinalizeOutcome::GuestUpdated);
    assert_eq!(
        owned.service.session_history(session_id),
        vec![("hello".to_string(), "hi there".to_string())]
    );

    let retry = owned
        .service
        .chat_prepare(&session, &chat_request("hello"), &provider, None);
    assert!(retry.error.is_none());
    owned.service.release_session_lock(session_id);
}
