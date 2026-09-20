//! Explicit account-store inputs: two-root isolation.
//!
//! `UserStore::open` / `RememberStore::open` take an explicit root instead of
//! the `HOST_DATA_DIR` global, and the key-verifier `_with_secret` variants
//! take an explicit HMAC secret instead of the global config. Two stores on
//! different roots share nothing for the same username, while an explicit
//! `open` stays on-disk compatible with the `new()` globals.
//!
//! The layout test alone touches `HOST_DATA_DIR`; the lazy-verifier test
//! alone changes `SECRET_KEY` and resets config. Other tests use explicit
//! roots/secrets, keeping those process-global changes independent.

use std::env;

use chatbot_core::remember_store::{RememberStore, ResumeOutcome};
use chatbot_core::user_store::{CreateOutcome, UserStore};
use chatbot_core::config;

/// Guards HOST_DATA_DIR for the test and restores it afterwards.
struct EnvGuard {
    previous: Option<String>,
}

impl EnvGuard {
    fn set_temp(dir: &std::path::Path) -> Self {
        let previous = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", dir);
        Self { previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var("HOST_DATA_DIR", value),
            None => env::remove_var("HOST_DATA_DIR"),
        }
    }
}

fn open_user_store(dir: &tempfile::TempDir) -> UserStore {
    UserStore::open(dir.path()).expect("open user store")
}

fn open_remember_store(dir: &tempfile::TempDir) -> RememberStore {
    RememberStore::open(dir.path()).expect("open remember store")
}

#[test]
fn two_roots_hold_independent_account_records_for_same_username() {
    let root_a = tempfile::tempdir().expect("tempdir");
    let root_b = tempfile::tempdir().expect("tempdir");
    let mut store_a = open_user_store(&root_a);
    let mut store_b = open_user_store(&root_b);

    let hash_a = bcrypt::hash("mod003-correct-horse-a", 4).expect("hash password");
    let hash_b = bcrypt::hash("mod003-correct-horse-b", 4).expect("hash password");

    assert!(matches!(
        store_a.create_user("mod003_alice", &hash_a).expect("create user"),
        CreateOutcome::Created
    ));
    assert!(matches!(
        store_b.create_user("mod003_alice", &hash_b).expect("create user"),
        CreateOutcome::Created
    ));

    // Each root authenticates only its own password for the same username.
    assert!(
        store_a
            .validate_user("mod003_alice", "mod003-correct-horse-a")
            .expect("validate own password")
    );
    assert!(
        !store_a
            .validate_user("mod003_alice", "mod003-correct-horse-b")
            .expect("validate peer password"),
        "root A must reject root B's password for the same username"
    );
    assert!(
        store_b
            .validate_user("mod003_alice", "mod003-correct-horse-b")
            .expect("validate own password")
    );
    assert!(
        !store_b
            .validate_user("mod003_alice", "mod003-correct-horse-a")
            .expect("validate peer password"),
        "root B must reject root A's password for the same username"
    );

    // Preferences are scoped to the owning root.
    store_a
        .update_user_preferences(
            "mod003_alice",
            Some("set-a".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("update preferences A");
    store_b
        .update_user_preferences(
            "mod003_alice",
            Some("set-b".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("update preferences B");
    let (last_a, ..) = store_a
        .user_preferences("mod003_alice")
        .expect("read preferences A");
    let (last_b, ..) = store_b
        .user_preferences("mod003_alice")
        .expect("read preferences B");
    assert_eq!(last_a.as_deref(), Some("set-a"));
    assert_eq!(last_b.as_deref(), Some("set-b"));

    // Per-root salts: the same password derives different keys per root.
    let key_a = store_a
        .derive_encryption_key("mod003_alice", "mod003-shared-password")
        .expect("derive key A");
    let key_b = store_b
        .derive_encryption_key("mod003_alice", "mod003-shared-password")
        .expect("derive key B");
    assert_ne!(
        key_a, key_b,
        "independent roots must not share salts for the same username"
    );

    // Reopening the same root sees the same record (same-root sharing).
    let reopened_a = open_user_store(&root_a);
    assert!(
        reopened_a
            .validate_user("mod003_alice", "mod003-correct-horse-a")
            .expect("validate after reopen")
    );
}

#[test]
fn key_verifiers_are_root_and_secret_scoped() {
    const SECRET_A: &[u8] = b"mod003-hmac-secret-a";
    const SECRET_B: &[u8] = b"mod003-hmac-secret-b";
    const DATA_KEY: &[u8] = b"mod003-data-key";
    const WRONG_KEY: &[u8] = b"mod003-wrong-data-key";

    let root_a = tempfile::tempdir().expect("tempdir");
    let root_b = tempfile::tempdir().expect("tempdir");
    let store_a = open_user_store(&root_a);
    let store_b = open_user_store(&root_b);

    store_a
        .ensure_key_verifier_with_secret("mod003_bob", DATA_KEY, SECRET_A)
        .expect("enroll verifier in root A");

    // Same root + same secret verifies; a foreign secret is rejected.
    assert!(
        store_a
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_A)
            .expect("verify own secret")
    );
    assert!(
        !store_a
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_B)
            .expect("verify foreign secret"),
        "cross-secret verification must fail"
    );

    // Enrolling with a foreign secret errors and must not clobber the record.
    assert!(
        store_a
            .ensure_key_verifier_with_secret("mod003_bob", DATA_KEY, SECRET_B)
            .is_err(),
        "ensure with a mismatched secret must fail"
    );
    assert!(
        store_a
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_A)
            .expect("verify after failed ensure"),
        "failed ensure must leave the enrolled verifier intact"
    );

    // A wrong key never verifies, and cannot enroll over the existing record.
    assert!(
        !store_a
            .verify_encryption_key_with_secret("mod003_bob", WRONG_KEY, SECRET_A)
            .expect("verify wrong key")
    );
    assert!(
        store_a
            .ensure_key_verifier_with_secret("mod003_bob", WRONG_KEY, SECRET_A)
            .is_err(),
        "ensure with a mismatched key must fail"
    );

    // The peer root is isolated: nothing enrolled there under either secret.
    assert!(
        !store_b
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_A)
            .expect("verify in peer root"),
        "verifiers must not leak across roots"
    );
    assert!(
        !store_b
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_B)
            .expect("verify unenrolled secret in peer root")
    );

    // The peer root enrolls independently under its own secret.
    store_b
        .ensure_key_verifier_with_secret("mod003_bob", DATA_KEY, SECRET_B)
        .expect("enroll verifier in root B");
    assert!(
        store_b
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_B)
            .expect("verify peer enrollment")
    );
    assert!(
        store_a
            .verify_encryption_key_with_secret("mod003_bob", DATA_KEY, SECRET_A)
            .expect("verify root A unaffected"),
        "peer enrollment must not disturb root A's verifier"
    );
    assert!(
        store_a.has_key_verifier("mod003_bob").expect("has verifier A"),
        "enrolled root must report its verifier"
    );
}

#[test]
fn remember_tokens_are_root_isolated() {
    let root_a = tempfile::tempdir().expect("tempdir");
    let root_b = tempfile::tempdir().expect("tempdir");
    let store_a = open_remember_store(&root_a);
    let store_b = open_remember_store(&root_b);

    let token = store_a.issue("mod003_carol").expect("issue token");
    let replacement = match store_a.resume(Some(&token)).expect("resume own token") {
        ResumeOutcome::Authenticated {
            username,
            replacement_token,
        } => {
            assert_eq!(username, "mod003_carol");
            assert_ne!(replacement_token, token, "resume must rotate the secret");
            replacement_token
        }
        ResumeOutcome::Invalid => panic!("own token rejected"),
    };

    // Neither the presented nor the rotated token exists in the peer root.
    assert!(
        matches!(
            store_b.resume(Some(&token)).expect("resume foreign token"),
            ResumeOutcome::Invalid
        ),
        "peer root must reject the foreign token"
    );
    assert!(
        matches!(
            store_b.resume(Some(&replacement)).expect("resume rotated token"),
            ResumeOutcome::Invalid
        ),
        "peer root must reject the rotated token"
    );
    assert_eq!(store_b.peek_username(Some(&token)), None);

    // The peer root issues and resumes independently for the same username.
    let peer_token = store_b.issue("mod003_carol").expect("issue peer token");
    assert!(
        matches!(
            store_b.resume(Some(&peer_token)).expect("resume peer token"),
            ResumeOutcome::Authenticated { .. }
        )
    );

    // The owning root still accepts its rotated token (family intact).
    assert!(
        matches!(
            store_a.resume(Some(&replacement)).expect("resume rotated token"),
            ResumeOutcome::Authenticated { .. }
        ),
        "foreign resumes must not disturb the owning family"
    );
}

/// Removes SECRET_KEY and drops any initialized global config, restoring
/// both afterwards. No other test in this binary reads either, so the
/// mutation is thread-safe here.
struct SecretGuard {
    previous: Option<String>,
}

impl SecretGuard {
    fn remove() -> Self {
        let previous = env::var("SECRET_KEY").ok();
        env::remove_var("SECRET_KEY");
        config::reset();
        Self { previous }
    }
}

impl Drop for SecretGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var("SECRET_KEY", value),
            None => env::remove_var("SECRET_KEY"),
        }
        config::reset();
    }
}

#[test]
fn compat_verifier_paths_do_not_initialize_config() {
    // With SECRET_KEY unset, any global config initialization panics
    // fail-closed, so reaching the assertions below proves the compat
    // verifier paths stay lazy on early-return inputs.
    let dir = tempfile::tempdir().expect("tempdir");
    let _secret = SecretGuard::remove();
    let store = open_user_store(&dir);

    assert!(
        store.verify_encryption_key("", b"mod003-key").is_err(),
        "invalid names must report an error without initializing config"
    );
    assert!(
        store
            .verify_encryption_key("not a user!", b"mod003-key")
            .is_err(),
        "invalid names must report an error without initializing config"
    );
    assert!(
        store.ensure_key_verifier("", b"mod003-key").is_err(),
        "invalid names must report an error without initializing config"
    );
    assert_eq!(
        store
            .verify_encryption_key("mod003_nobody", b"mod003-key")
            .expect("missing verifier reports false"),
        false,
        "missing verifiers must report false without initializing config"
    );
}

#[test]
fn explicit_open_shares_layout_with_global_new() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _env = EnvGuard::set_temp(dir.path());

    let hash = bcrypt::hash("mod003-dave-password", 4).expect("hash password");
    let token = {
        let mut global_users = UserStore::new().expect("global user store");
        assert!(matches!(
            global_users
                .create_user("mod003_dave", &hash)
                .expect("create user"),
            CreateOutcome::Created
        ));
        RememberStore::new()
            .expect("global remember store")
            .issue("mod003_dave")
            .expect("issue token")
    };

    // Explicit opens on the same root observe the globally created records.
    let explicit_users = UserStore::open(dir.path()).expect("explicit user store");
    assert!(
        explicit_users
            .validate_user("mod003_dave", "mod003-dave-password")
            .expect("validate cross-constructed record"),
        "open() must read records created via new()"
    );
    let explicit_remember = RememberStore::open(dir.path()).expect("explicit remember store");
    assert!(
        matches!(
            explicit_remember.resume(Some(&token)).expect("resume cross-constructed token"),
            ResumeOutcome::Authenticated { .. }
        ),
        "open() must resume tokens issued via new()"
    );
}
