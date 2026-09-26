//! MOD001 session-operation boundary: typed failures without HTTP transport.
//!
//! Given an owned chat service, when key validation, guest bootstrap,
//! mismatched bootstrap, store access, or mirror sealing fails, then the
//! core returns a narrow `SessionOperationError` with its original static
//! message and `PrepareError::Session` carries it (no status/headers/body).

use std::path::PathBuf;
use std::sync::Arc;

use chatbot_core::config::ProviderConfig;
use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::HistoryService;
use chatbot_core::session::{
    ChatRequestData, ChatService, ChatSessionStore, PrepareError, SessionContext,
    SessionOperationError,
};
use chatbot_core::user_store::UserStore;

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

fn premium_provider() -> ProviderConfig {
    ProviderConfig {
        tier: Some("premium".to_string()),
        ..test_provider()
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

fn short_key() -> EncryptionKey {
    EncryptionKey::from_header_value("short").expect("short key")
}

fn good_fernet_key() -> EncryptionKey {
    EncryptionKey::from_header_value("-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s=")
        .expect("fernet key")
}

fn guest_context(session_id: &str) -> SessionContext {
    SessionContext {
        session_id: session_id.to_string(),
        username: None,
    }
}

fn chat_request<'a>(message: &'a str, set_name: Option<&'a str>) -> ChatRequestData<'a> {
    ChatRequestData {
        message,
        system_prompt: None,
        set_name,
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
fn require_missing_key_returns_typed_missing() {
    let owned = make_service("mod001-missing");
    let username = "mod001_missing";
    enroll(&owned, username, &test_key());

    let err = owned
        .service
        .require_encryption_key(Some(username), None)
        .expect_err("missing key must fail");
    assert_eq!(err, SessionOperationError::MissingEncryptionKey);
    assert_eq!(err.message(), "Encryption key required. Please unlock.");
}

#[test]
fn require_wrong_key_returns_typed_invalid() {
    let owned = make_service("mod001-invalid");
    let username = "mod001_invalid";
    enroll(&owned, username, &test_key());

    let key = wrong_key();
    let err = owned
        .service
        .require_encryption_key(Some(username), Some(&key))
        .expect_err("wrong key must fail");
    assert_eq!(err, SessionOperationError::InvalidEncryptionKey);
    assert_eq!(err.message(), "Invalid encryption key.");
}

#[test]
fn require_unusable_store_returns_typed_unavailable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file_root = temp.path().join("not-a-dir");
    std::fs::write(&file_root, b"blocking file").expect("blocking file");
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
        sessions,
        Arc::new(history),
        file_root.clone(),
        "mod001-store-secret".to_string(),
    );

    let key = test_key();
    let err = service
        .require_encryption_key(Some("anyone"), Some(&key))
        .expect_err("unusable store must fail");
    assert_eq!(err, SessionOperationError::UserStoreUnavailable);
    assert_eq!(err.message(), "internal error while accessing user store");
}

#[test]
fn guest_custom_set_prepare_returns_typed_denied() {
    let owned = make_service("mod001-guest-custom");
    let session = guest_context("guest_mod001_custom_denied");
    let provider = test_provider();

    let result = owned.service.chat_prepare(
        &session,
        &chat_request("hello", Some("my-custom-set")),
        &provider,
        None,
    );
    let err = result.error.expect("guest custom set must fail");
    assert!(
        matches!(
            err,
            PrepareError::Session(SessionOperationError::GuestCustomSetDenied)
        ),
        "expected GuestCustomSetDenied, got {err:?}"
    );
    assert_eq!(
        SessionOperationError::GuestCustomSetDenied.message(),
        "Login required for custom sets"
    );
    owned.service.release_session_lock(&session.session_id);
}

#[test]
fn mismatched_bootstrap_prepare_returns_typed_misuse() {
    let owned = make_service("mod001-misuse");
    let session = SessionContext {
        session_id: "guest_mod001_mismatch".to_string(),
        username: Some("mod001_mismatch_user".to_string()),
    };
    let provider = test_provider();

    let result = owned.service.chat_prepare(
        &session,
        &chat_request("hello", Some("default")),
        &provider,
        None,
    );
    let err = result.error.expect("mismatched bootstrap must fail");
    assert!(
        matches!(
            err,
            PrepareError::Session(SessionOperationError::AuthenticatedBootstrapMisuse)
        ),
        "expected AuthenticatedBootstrapMisuse, got {err:?}"
    );
    assert_eq!(
        SessionOperationError::AuthenticatedBootstrapMisuse.message(),
        "authenticated session must load via history store"
    );
    owned.service.release_session_lock(&session.session_id);
}

#[test]
fn premium_tier_with_unusable_store_returns_typed_unavailable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file_root = temp.path().join("not-a-dir");
    std::fs::write(&file_root, b"blocking file").expect("blocking file");
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
        file_root,
        "mod001-tier-secret".to_string(),
    );
    let provider = premium_provider();

    // Seed an initialised guest-prefix entry, then present it with a username
    // so bootstrap (`initialise_session_data`) and the cipher key gate are
    // both skipped: `requires_cipher` is false and `initialised` is true, so
    // `build_chat_context` falls through to `ensure_model_allowed`, which
    // must hit the unusable account root.
    let session_id = "guest_mod001_tier_store";
    sessions.update_history(session_id, &[("u".to_string(), "a".to_string())]);
    let session = SessionContext {
        session_id: session_id.to_string(),
        username: Some("mod001_tier_user".to_string()),
    };
    let result = service.chat_prepare(
        &session,
        &chat_request("hello", Some("default")),
        &provider,
        None,
    );
    let err = result.error.expect("store failure must fail prepare");
    assert!(
        matches!(
            err,
            PrepareError::Session(SessionOperationError::UserStoreUnavailable)
        ),
        "expected UserStoreUnavailable from the tier gate, got {err:?}"
    );
}

#[test]
fn mirror_replace_with_unsealable_key_returns_history_unavailable() {
    let owned = make_service("mod001-seal");
    let username = "mod001_seal_user";
    let short = short_key();
    enroll(&owned, username, &short);

    let err = owned
        .service
        .replace_session_set(
            username,
            Some(username),
            None,
            "memory",
            "prompt",
            &[],
            true,
            Some(&short),
        )
        .expect_err("short Fernet key must fail seal");
    assert_eq!(err, SessionOperationError::HistoryUnavailable);
    assert_eq!(err.message(), "internal error while accessing chat history");
}

#[test]
fn unsealing_with_invalid_key_returns_history_unavailable() {
    let owned = make_service("mod001-corrupt");
    let username = "mod001_corrupt_user";
    let good = good_fernet_key();
    let short = short_key();
    enroll(&owned, username, &good);

    owned
        .service
        .replace_session_set(
            username,
            Some(username),
            None,
            "memory",
            "prompt",
            &[],
            true,
            Some(&good),
        )
        .expect("good seal must succeed");

    // Blob stays intact from the good key; only the presented key is invalid.
    // Rebind the verifier to the short key so the require gate passes but the
    // Fernet open of the intact blob fails.
    let verifier = owned
        .account_root
        .join("key_verifiers")
        .join(format!("{username}_kv.json"));
    std::fs::remove_file(&verifier).expect("remove verifier");
    enroll(&owned, username, &short);

    let err = owned
        .service
        .session_history_for_request(username, Some(username), Some(&short))
        .expect_err("intact blob with invalid key must fail unseal");
    assert_eq!(err, SessionOperationError::HistoryUnavailable);
}

#[test]
fn session_operation_messages_match_original_strings() {
    assert_eq!(
        SessionOperationError::MissingEncryptionKey.message(),
        "Encryption key required. Please unlock."
    );
    assert_eq!(
        SessionOperationError::InvalidEncryptionKey.message(),
        "Invalid encryption key."
    );
    assert_eq!(
        SessionOperationError::UserStoreUnavailable.message(),
        "internal error while accessing user store"
    );
    assert_eq!(
        SessionOperationError::HistoryUnavailable.message(),
        "internal error while accessing chat history"
    );
    assert_eq!(
        SessionOperationError::GuestCustomSetDenied.message(),
        "Login required for custom sets"
    );
    assert_eq!(
        SessionOperationError::AuthenticatedBootstrapMisuse.message(),
        "authenticated session must load via history store"
    );
}

#[test]
fn prepare_error_carries_session_variant() {
    let err: PrepareError = SessionOperationError::GuestCustomSetDenied.into();
    assert!(
        matches!(
            err,
            PrepareError::Session(SessionOperationError::GuestCustomSetDenied)
        ),
        "From must carry Session, got {err:?}"
    );
}
