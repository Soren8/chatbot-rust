//! MOD003: owned chat service isolation.
//!
//! Two `ChatService`s built from separate ephemeral session stores, redb
//! roots, account roots and verifier secrets share nothing, even for the
//! same guest/authed session IDs. Owned orchestration (prepare/finalize,
//! leases, key validation, regenerate capture) uses only those explicit
//! dependencies; the only remaining ambient read on this path is the
//! explicit `CHATBOT_TEST_OPENAI_CHUNKS` / `provider.test_chunks`
//! compatibility hook in `resolve_test_chunks`.
//!
//! These tests never touch the process-global stores or config: providers
//! are explicit, stores are opened from tempdirs, and verifiers use explicit
//! secrets.

use std::path::PathBuf;
use std::sync::Arc;

use chatbot_core::config::ProviderConfig;
use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::HistoryService;
use chatbot_core::session::{
    ChatRequestData, ChatService, ChatSessionStore, PrepareError, PreparePolicyError,
    PrepareValidationError, RegenerateRequestData, SessionContext,
};
use chatbot_core::user_store::UserStore;

struct OwnedService {
    _temp: tempfile::TempDir,
    service: ChatService,
    account_root: PathBuf,
    secret: String,
}

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

fn test_key() -> EncryptionKey {
    EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
        .expect("test key")
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

fn make_service(default_prompt: &str, secret: &str) -> OwnedService {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_root = temp.path().join("accounts");
    let redb_path = temp.path().join("history.redb");
    let data_dir = temp.path().join("legacy");
    std::fs::create_dir_all(&data_dir).expect("legacy dir");
    let history =
        HistoryService::open_with_data_dir(&redb_path, &data_dir, default_prompt.to_string())
            .expect("open history");
    let sessions = Arc::new(ChatSessionStore::new(3600, default_prompt.to_string()));
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

fn create_user_with_tier(owned: &OwnedService, username: &str, tier: &str) {
    let hash = bcrypt::hash("mod003-password", 4).expect("hash password");
    let mut store = UserStore::open(&owned.account_root).expect("open store");
    match store.create_user(username, &hash) {
        Ok(_) => {}
        Err(err) => panic!("create user: {err}"),
    }
    let path = owned.account_root.join("users.json");
    let raw = std::fs::read_to_string(&path).expect("read users.json");
    let mut users: serde_json::Value = serde_json::from_str(&raw).expect("parse users.json");
    users[username]["tier"] = serde_json::json!(tier);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&users).expect("serialize users.json"),
    )
    .expect("write users.json");
}

fn premium_provider() -> ProviderConfig {
    let mut provider = test_provider();
    provider.tier = Some("premium".to_string());
    provider
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

#[test]
fn guest_prepare_lease_finalize_isolates_history_for_same_session_id() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-B", "svc-secret-b");
    let session_id = "guest_mod003_svc_shared_chat";
    let session = guest_context(session_id);
    let provider = test_provider();

    let prepared_a = a.service.chat_prepare_leased(
        &session,
        &chat_request("hello-a"),
        &provider,
        None,
    );
    assert!(prepared_a.error.is_none());
    let context_a = prepared_a.context.expect("context A");
    assert_eq!(context_a.system_prompt, "prompt-A");
    let lease_a = prepared_a.lease.expect("lease A");

    let prepared_b = b.service.chat_prepare_leased(
        &session,
        &chat_request("hello-b"),
        &provider,
        None,
    );
    assert!(prepared_b.error.is_none());
    let context_b = prepared_b.context.expect("context B");
    assert_eq!(context_b.system_prompt, "prompt-B");
    let lease_b = prepared_b.lease.expect("lease B");

    let extras_a = lease_a.complete_chat(session_id, "hello-a", "answer-a", None, None);
    assert!(extras_a.is_empty());
    let extras_b = lease_b.complete_chat(session_id, "hello-b", "answer-b", None, None);
    assert!(extras_b.is_empty());

    assert_eq!(
        a.service.session_history(session_id),
        vec![("hello-a".to_string(), "answer-a".to_string())]
    );
    assert_eq!(
        b.service.session_history(session_id),
        vec![("hello-b".to_string(), "answer-b".to_string())]
    );
}

#[test]
fn peer_generation_locks_are_service_scoped_for_same_session_id() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-B", "svc-secret-b");
    let session_id = "guest_mod003_svc_shared_lock";
    let session = guest_context(session_id);
    let provider = test_provider();

    assert!(a.service.try_acquire_generation(session_id));
    assert!(
        !a.service.try_acquire_generation(session_id),
        "same service must report busy while held"
    );
    assert!(
        b.service.try_acquire_generation(session_id),
        "peer service has an independent lock"
    );
    a.service.release_session_lock(session_id);
    assert!(
        a.service.try_acquire_generation(session_id),
        "release frees the owning service only"
    );
    assert!(
        !b.service.try_acquire_generation(session_id),
        "peer still holds its lock"
    );
    a.service.release_session_lock(session_id);
    b.service.release_session_lock(session_id);

    let prepared_a =
        a.service
            .chat_prepare_leased(&session, &chat_request("hi"), &provider, None);
    assert!(prepared_a.error.is_none());
    let lease_a = prepared_a.lease.expect("lease A");

    let busy_a = a.service.chat_prepare(&session, &chat_request("hi"), &provider, None);
    assert!(
        matches!(
            busy_a.error,
            Some(PrepareError::Policy(PreparePolicyError::Busy))
        ),
        "same service stays busy while its lease is outstanding"
    );
    let prepared_b =
        b.service
            .chat_prepare_leased(&session, &chat_request("hi"), &provider, None);
    assert!(
        prepared_b.error.is_none(),
        "peer service prepares independently: {:?}",
        prepared_b.error
    );
    let lease_b = prepared_b.lease.expect("lease B");

    lease_a.release_without_persist();
    assert!(a.service.session_history(session_id).is_empty());
    let retry_a = a.service.chat_prepare(&session, &chat_request("hi"), &provider, None);
    assert!(retry_a.error.is_none());
    a.service.release_session_lock(session_id);

    let busy_b = b.service.chat_prepare(&session, &chat_request("hi"), &provider, None);
    assert!(
        matches!(
            busy_b.error,
            Some(PrepareError::Policy(PreparePolicyError::Busy))
        ),
        "completing A must leave B locked"
    );
    lease_b.release_without_persist();
    let retry_b = b.service.chat_prepare(&session, &chat_request("hi"), &provider, None);
    assert!(retry_b.error.is_none());
    b.service.release_session_lock(session_id);
}

#[test]
fn dropping_one_lease_leaves_peer_locked_without_persisting() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-B", "svc-secret-b");
    let session_id = "guest_mod003_svc_drop_peer";
    let session = guest_context(session_id);
    let provider = test_provider();

    let prepared_a =
        a.service
            .chat_prepare_leased(&session, &chat_request("hi-a"), &provider, None);
    assert!(prepared_a.error.is_none());
    let lease_a = prepared_a.lease.expect("lease A");
    let prepared_b =
        b.service
            .chat_prepare_leased(&session, &chat_request("hi-b"), &provider, None);
    assert!(prepared_b.error.is_none());
    let lease_b = prepared_b.lease.expect("lease B");

    drop(lease_a);
    assert!(
        a.service.session_history(session_id).is_empty(),
        "dropped lease must not persist"
    );
    let retry_a = a.service.chat_prepare(&session, &chat_request("hi-a"), &provider, None);
    assert!(retry_a.error.is_none());
    a.service.release_session_lock(session_id);

    let busy_b = b.service.chat_prepare(&session, &chat_request("hi-b"), &provider, None);
    assert!(
        matches!(
            busy_b.error,
            Some(PrepareError::Policy(PreparePolicyError::Busy))
        ),
        "dropping A must leave B locked: {:?}",
        busy_b.error
    );
    lease_b.release_without_persist();
    let retry_b = b.service.chat_prepare(&session, &chat_request("hi-b"), &provider, None);
    assert!(retry_b.error.is_none());
    b.service.release_session_lock(session_id);
}

#[test]
fn key_validation_is_root_and_secret_scoped() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("svc-default", "svc-secret-b");
    let username = "mod003_svc_bob";
    let key = test_key();
    let wrong = EncryptionKey::from_header_value("d3Jvbmcta2V5LW1hdGVyaWFsLTAwMDAwMDAwMDAwMDAwMDA=")
        .expect("wrong key");

    enroll(&a, username, &key);

    assert!(
        a.service
            .validate_encryption_key_for_user(username, Some(&key))
            .is_ok(),
        "own root plus own secret validates"
    );
    assert!(
        a.service
            .validate_encryption_key_for_user(username, Some(&wrong))
            .is_err(),
        "wrong key must not validate"
    );
    assert!(
        a.service
            .validate_encryption_key_for_user(username, None)
            .is_err(),
        "missing key must not validate"
    );

    assert!(
        b.service
            .validate_encryption_key_for_user(username, Some(&key))
            .is_err(),
        "peer root must not see A's enrollment"
    );

    enroll(&b, username, &key);
    assert!(
        b.service
            .validate_encryption_key_for_user(username, Some(&key))
            .is_ok(),
        "peer validates after its own enrollment"
    );
    assert!(
        a.service
            .validate_encryption_key_for_user(username, Some(&key))
            .is_ok(),
        "peer enrollment must not disturb the owner"
    );

    let store_a = UserStore::open(&a.account_root).expect("open A");
    assert!(
        !store_a
            .verify_encryption_key_with_secret(username, key.as_bytes(), b"svc-secret-b")
            .expect("verify foreign secret"),
        "same key under a foreign secret must fail"
    );
}

#[test]
fn premium_gate_uses_owned_account_root() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-A", "svc-secret-b");
    let username = "mod003_svc_prem";
    let session = authed_context(username);
    let key = test_key();
    create_user_with_tier(&a, username, "premium");
    create_user_with_tier(&b, username, "free");
    enroll(&a, username, &key);
    enroll(&b, username, &key);
    let premium = premium_provider();

    let ok_a = a
        .service
        .chat_prepare(&session, &chat_request("hi"), &premium, Some(&key));
    assert!(
        ok_a.error.is_none(),
        "owned premium user must pass the owned tier gate: {:?}",
        ok_a.error
    );
    a.service.release_session_lock(&session.session_id);

    let denied_b = b
        .service
        .chat_prepare(&session, &chat_request("hi"), &premium, Some(&key));
    assert!(
        matches!(
            denied_b.error,
            Some(PrepareError::Policy(PreparePolicyError::PremiumRequired))
        ),
        "peer free tier must fail the owned gate: {:?}",
        denied_b.error
    );

    let retry_b = b
        .service
        .chat_prepare(&session, &chat_request("hi"), &test_provider(), Some(&key));
    assert!(retry_b.error.is_none());
    b.service.release_session_lock(&session.session_id);
}

#[test]
fn authed_prepare_lease_finalize_isolates_durable_history() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-A", "svc-secret-b");
    let username = "mod003_svc_alice";
    let session = authed_context(username);
    let provider = test_provider();
    let key = test_key();
    enroll(&a, username, &key);
    enroll(&b, username, &key);

    let prepared_a = a.service.chat_prepare_leased(
        &session,
        &chat_request("hello-a"),
        &provider,
        Some(&key),
    );
    assert!(prepared_a.error.is_none());
    let context_a = prepared_a.context.expect("context A");
    assert!(
        context_a.prepare_capture.is_some(),
        "authed prepare must capture durable state"
    );
    let capture_a = context_a.prepare_capture.clone().expect("capture");
    let lease_a = prepared_a.lease.expect("lease A");
    let extras_a = lease_a.complete_chat(
        "default",
        "hello-a",
        "answer-a",
        Some(&key),
        Some(capture_a),
    );
    assert!(extras_a.is_empty());

    let history_a = a
        .service
        .history()
        .expect("history handle")
        .load(username, context_a.set_id.expect("set id"), &key)
        .expect("load A");
    assert_eq!(
        history_a.history,
        vec![("hello-a".to_string(), "answer-a".to_string())]
    );
    assert!(
        a.service.session_history(&session.session_id).is_empty(),
        "authed session mirror keeps small fields only"
    );

    let peer_history_before = b
        .service
        .history()
        .expect("history handle")
        .ensure_default_set(username, &key)
        .expect("peer default");
    assert!(
        peer_history_before.history.is_empty(),
        "peer durable history starts empty"
    );

    let prepared_b = b.service.chat_prepare_leased(
        &session,
        &chat_request("hello-b"),
        &provider,
        Some(&key),
    );
    assert!(prepared_b.error.is_none());
    let context_b = prepared_b.context.expect("context B");
    let capture_b = context_b.prepare_capture.clone().expect("capture");
    let lease_b = prepared_b.lease.expect("lease B");
    let extras_b = lease_b.complete_chat(
        "default",
        "hello-b",
        "answer-b",
        Some(&key),
        Some(capture_b),
    );
    assert!(extras_b.is_empty());

    let reloaded_a = a
        .service
        .history()
        .expect("history handle")
        .load(username, context_a.set_id.expect("set id"), &key)
        .expect("reload A");
    assert_eq!(
        reloaded_a.history,
        vec![("hello-a".to_string(), "answer-a".to_string())],
        "peer commit must not disturb the owner"
    );
    let reloaded_b = b
        .service
        .history()
        .expect("history handle")
        .load(username, context_b.set_id.expect("set id"), &key)
        .expect("reload B");
    assert_eq!(
        reloaded_b.history,
        vec![("hello-b".to_string(), "answer-b".to_string())]
    );
}

#[test]
fn authed_regenerate_uses_capture_without_disturbing_peer() {
    let a = make_service("prompt-A", "svc-secret-a");
    let b = make_service("prompt-A", "svc-secret-b");
    let username = "mod003_svc_erin";
    let session = authed_context(username);
    let provider = test_provider();
    let key = test_key();
    enroll(&a, username, &key);
    enroll(&b, username, &key);

    for (user, assistant) in [("u1", "a1"), ("u2", "a2")] {
        let prepared = a.service.chat_prepare_leased(
            &session,
            &chat_request(user),
            &provider,
            Some(&key),
        );
        assert!(prepared.error.is_none());
        let context = prepared.context.expect("context");
        let capture = context.prepare_capture.clone().expect("capture");
        let lease = prepared.lease.expect("lease");
        let extras = lease.complete_chat("default", user, assistant, Some(&key), Some(capture));
        assert!(extras.is_empty());
    }

    let regen_request = RegenerateRequestData {
        message: "u2",
        system_prompt: None,
        set_name: Some("default"),
        set_id: None,
        model_name: None,
        encrypted: false,
        pair_index: Some(1),
        send_thoughts: false,
    };
    let prepared = a.service.regenerate_prepare_leased(
        &session,
        &regen_request,
        &provider,
        Some(&key),
    );
    assert!(prepared.error.is_none());
    assert_eq!(prepared.insertion_index, Some(1));
    let context = prepared.context.expect("context");
    assert_eq!(context.history.len(), 1);
    assert_eq!(context.history[0].0, "u1");
    let capture = context.prepare_capture.clone().expect("capture carries set");
    assert_eq!(capture.insertion_index, Some(1));
    let lease = prepared.lease.expect("lease");

    let durable_before = a
        .service
        .history()
        .expect("history")
        .load(username, context.set_id.expect("set"), &key)
        .expect("load before");
    assert_eq!(durable_before.history.len(), 2);

    let extras = lease.complete_regenerate(
        "default",
        "u2",
        "new-a2",
        Some(1),
        Some(&key),
        Some(capture),
    );
    assert!(extras.is_empty());
    let after = a
        .service
        .history()
        .expect("history")
        .load(username, context.set_id.expect("set"), &key)
        .expect("load after");
    assert_eq!(after.history.len(), 2);
    assert_eq!(after.history[1], ("u2".into(), "new-a2".into()));

    let peer_default = b
        .service
        .history()
        .expect("history")
        .ensure_default_set(username, &key)
        .expect("peer default");
    assert!(
        peer_default.history.is_empty(),
        "regenerate on A must not create peer history"
    );
}

#[test]
fn owned_prepare_rejects_empty_message_and_releases_lock() {
    let owned = make_service("prompt-A", "svc-secret-a");
    let session = guest_context("guest_mod003_svc_empty");
    let provider = test_provider();
    let bad = ChatRequestData {
        message: "   ",
        system_prompt: None,
        set_name: Some("default"),
        set_id: None,
        model_name: None,
        encrypted: false,
        send_thoughts: false,
    };

    let prepared = owned.service.chat_prepare_leased(&session, &bad, &provider, None);
    assert!(prepared.context.is_none());
    assert!(prepared.lease.is_none());
    assert!(
        matches!(
            prepared.error,
            Some(PrepareError::Validation(
                PrepareValidationError::MessageRequired
            ))
        )
    );

    let retry = owned
        .service
        .chat_prepare(&session, &chat_request("hi"), &provider, None);
    assert!(retry.error.is_none());
    owned.service.release_session_lock(&session.session_id);
}
