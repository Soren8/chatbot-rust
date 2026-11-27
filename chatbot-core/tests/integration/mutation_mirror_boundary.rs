//! MOD006 core ownership: durable-then-mirror application operations.
//!
//! Given an owned `ChatService`, when memory / prompt / delete / reset apply,
//! then key validation precedes history, stale CAS conflicts carry the current
//! version, bad set IDs and missing sets stay distinct, guests are rejected
//! at the key gate, and a mirror seal failure still leaves the durable write
//! behind.

use std::{path::PathBuf, sync::Arc};

use chatbot_core::{
    enc_key::EncryptionKey,
    history::HistoryService,
    session::{
        ChatService, ChatSessionStore, MutationMirrorError, SessionContext, SessionOperationError,
    },
    user_store::UserStore,
};

fn test_key() -> EncryptionKey {
    // Well-formed Fernet key (32 zero bytes) so session seals succeed.
    EncryptionKey::from_header_value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .expect("test key")
}

fn short_key() -> EncryptionKey {
    EncryptionKey::from_header_value("short").expect("short key")
}

fn authed_context(username: &str) -> SessionContext {
    SessionContext {
        session_id: username.to_string(),
        username: Some(username.to_string()),
    }
}

fn guest_context(session_id: &str) -> SessionContext {
    SessionContext {
        session_id: session_id.to_string(),
        username: None,
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
    let sessions = Arc::new(ChatSessionStore::new(
        3600,
        "You are a helpful assistant.".to_string(),
    ));
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
fn memory_update_commits_durable_then_mirrors() {
    let owned = make_service("core-mut-mem");
    let username = "core_mut_mem";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    let applied = owned
        .service
        .apply_memory_update(&session, Some(&key), "default", None, None, "lake house")
        .expect("memory update");
    let history = owned.service.history().expect("history");
    let loaded = history
        .load(username, applied.set_id, &key)
        .expect("durable memory");
    assert_eq!(loaded.memory, "lake house");
    assert!(applied.version.get() > 0);
}

#[test]
fn system_prompt_update_commits_durable() {
    let owned = make_service("core-mut-prompt");
    let username = "core_mut_prompt";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    let applied = owned
        .service
        .apply_system_prompt_update(&session, Some(&key), "default", None, None, "You guide lakes")
        .expect("prompt update");
    let loaded = owned
        .service
        .history()
        .expect("history")
        .load(username, applied.set_id, &key)
        .expect("durable prompt");
    assert_eq!(loaded.system_prompt, "You guide lakes");
}

#[test]
fn delete_pair_commits_durable() {
    let owned = make_service("core-mut-del");
    let username = "core_mut_del";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    let history = owned.service.history().expect("history");
    let default = history
        .ensure_default_set(username, &key)
        .expect("ensure default");
    let version = history
        .append_pair(username, default.set_id, default.version, "u1", "a1", &key)
        .expect("seed pair");
    let set_id_str = default.set_id.to_string();

    let applied = owned
        .service
        .apply_delete_pair(
            &session,
            Some(&key),
            "default",
            Some(set_id_str.as_str()),
            Some(version),
            0,
            "u1",
        )
        .expect("delete pair");
    assert_eq!(applied.set_id, default.set_id);
    let loaded = owned
        .service
        .history()
        .expect("history")
        .load(username, applied.set_id, &key)
        .expect("load after delete");
    assert!(loaded.history.is_empty());
}

#[test]
fn reset_history_clears_durable() {
    let owned = make_service("core-mut-reset");
    let username = "core_mut_reset";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    let history = owned.service.history().expect("history");
    let default = history
        .ensure_default_set(username, &key)
        .expect("ensure default");
    history
        .append_pair(username, default.set_id, default.version, "u1", "a1", &key)
        .expect("seed pair");

    let applied = owned
        .service
        .apply_reset_history(&session, Some(&key), "default", None, None)
        .expect("reset");
    let loaded = owned
        .service
        .history()
        .expect("history")
        .load(username, applied.set_id, &key)
        .expect("load after reset");
    assert!(loaded.history.is_empty());
}

#[test]
fn stale_version_conflicts_with_current() {
    let owned = make_service("core-mut-cas");
    let username = "core_mut_cas";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    let first = owned
        .service
        .apply_memory_update(&session, Some(&key), "default", None, None, "v1")
        .expect("first");
    let first_id = first.set_id.to_string();
    let second = owned
        .service
        .apply_memory_update(
            &session,
            Some(&key),
            "default",
            Some(first_id.as_str()),
            Some(first.version),
            "v2",
        )
        .expect("second");
    assert_ne!(first.version, second.version);

    match owned.service.apply_memory_update(
        &session,
        Some(&key),
        "default",
        Some(first_id.as_str()),
        Some(first.version),
        "stale",
    ) {
        Err(MutationMirrorError::Conflict {
            set_id,
            current_version,
        }) => {
            assert_eq!(set_id, first.set_id);
            assert_eq!(current_version, second.version);
        }
        other => panic!("expected conflict, got {other:?}"),
    }
}

#[test]
fn key_validation_precedes_set_id_parsing() {
    let owned = make_service("core-mut-keyprec");
    let username = "core_mut_keyprec";
    let session = authed_context(username);
    enroll(&owned, username, &test_key());

    match owned.service.apply_memory_update(
        &session,
        None,
        "default",
        Some("not-a-uuid"),
        None,
        "x",
    ) {
        Err(MutationMirrorError::Key(_)) => {}
        other => panic!("key must precede set_id, got {other:?}"),
    }
}

#[test]
fn invalid_set_id_and_missing_set_stay_distinct() {
    let owned = make_service("core-mut-addr");
    let username = "core_mut_addr";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    match owned
        .service
        .apply_memory_update(&session, Some(&key), "default", Some("not-a-uuid"), None, "x")
    {
        Err(MutationMirrorError::InvalidSetId) => {}
        other => panic!("expected InvalidSetId, got {other:?}"),
    }

    match owned.service.apply_memory_update(
        &session,
        Some(&key),
        "no-such-set-name-xyz",
        None,
        None,
        "x",
    ) {
        Err(MutationMirrorError::SetNotFound) => {}
        other => panic!("expected SetNotFound, got {other:?}"),
    }
}

#[test]
fn guest_cannot_use_authed_mutation() {
    let owned = make_service("core-mut-guest");
    let session = guest_context("guest_core_mut_guest");

    match owned
        .service
        .apply_memory_update(&session, None, "default", None, None, "x")
    {
        Err(MutationMirrorError::Key(_)) => {}
        other => panic!("guest must hit the key gate, got {other:?}"),
    }
}

#[test]
fn mirror_failure_after_durable_success_still_persists() {
    let owned = make_service("core-mut-mirror");
    let username = "core_mut_mirror";
    let session = authed_context(username);
    let key = short_key();
    enroll(&owned, username, &key);

    // Durable history accepts any key bytes (HKDF); establish the set first.
    let history = owned.service.history().expect("history");
    let default = history
        .ensure_default_set(username, &key)
        .expect("ensure default");

    // Initialize the session cipher through the real mirror path. Sealing
    // with a Fernet-invalid key fails, but the active set is recorded (no
    // rollback), so the next mutation takes the matching-set path where seal
    // failures surface instead of leaving the mirror alone.
    let init = owned.service.replace_session_set(
        &session.session_id,
        Some(username),
        Some(default.set_id),
        "",
        "",
        &[],
        true,
        Some(&key),
    );
    assert!(
        matches!(
            init,
            Err(SessionOperationError::HistoryUnavailable)
        ),
        "short key must fail the session seal, got {init:?}"
    );

    // The durable write lands first; the mirror seal fails after it.
    match owned
        .service
        .apply_memory_update(&session, Some(&key), "default", None, None, "durable anyway")
    {
        Err(MutationMirrorError::Mirror(_)) => {}
        other => panic!("short Fernet-invalid key must fail the mirror, got {other:?}"),
    }

    let history = owned.service.history().expect("history");
    let snap = history
        .find_by_display_name(username, "default", &key)
        .expect("find default")
        .expect("default exists");
    let loaded = history
        .load(username, snap.set_id, &key)
        .expect("durable persists despite mirror failure");
    assert_eq!(loaded.memory, "durable anyway");
}

#[test]
fn load_set_reads_then_mirrors() {
    let owned = make_service("core-mut-load");
    let username = "core_mut_load";
    let session = authed_context(username);
    let key = test_key();
    enroll(&owned, username, &key);

    owned
        .service
        .apply_memory_update(&session, Some(&key), "default", None, None, "load me")
        .expect("seed memory");

    let page = owned
        .service
        .apply_load_set(&session, Some(&key), None, Some("default"), None, None, false)
        .expect("load set");
    assert_eq!(page.memory, "load me");

    match owned.service.apply_load_set(
        &session,
        Some(&key),
        Some("not-a-uuid"),
        None,
        None,
        None,
        false,
    ) {
        Err(MutationMirrorError::InvalidSetId) => {}
        other => panic!("expected InvalidSetId, got {other:?}"),
    }

    match owned
        .service
        .apply_load_set(&session, Some(&key), None, Some("missing-name-xyz"), None, None, false)
    {
        Err(MutationMirrorError::SetNotFound) => {}
        other => panic!("expected SetNotFound, got {other:?}"),
    }
}
