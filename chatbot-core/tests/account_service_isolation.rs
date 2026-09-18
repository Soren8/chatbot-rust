//! Owned account service isolation.
//!
//! Two `AccountService`s built from separate roots/secrets share nothing for
//! the same username: passwords, preferences, salts/keys, verifiers, and
//! remember tokens stay scoped. `users()` returns a store already configured
//! with the explicit HMAC secret, so ordinary `ensure`/`verify` use it with
//! the same validation/record-read precedence as the compatibility path and
//! never read ambient config. The explicit verifier path preserves the
//! early-return lazy timing: invalid names and missing verifiers never
//! initialize global config.
//!
//! These tests never touch the process-global stores. Only the two lazy-parity
//! tests mutate `SECRET_KEY`/global config, serialized through a shared
//! static mutex held for the whole removal window. All other tests use
//! explicit roots/secrets only and never read ambient config.

use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};

use chatbot_core::account_service::AccountService;
use chatbot_core::config;
use chatbot_core::remember_store::ResumeOutcome;
use chatbot_core::user_store::CreateOutcome;

fn make_service(secret: &str) -> (tempfile::TempDir, AccountService) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("accounts");
    std::fs::create_dir_all(&root).expect("account root");
    let service = AccountService::with_root_and_secret(root, secret.to_owned());
    (temp, service)
}

#[test]
fn two_services_hold_independent_passwords_and_preferences() {
    let (_tmp_a, accounts_a) = make_service("mod003-account-secret-a");
    let (_tmp_b, accounts_b) = make_service("mod003-account-secret-b");

    let hash_a = bcrypt::hash("mod003-pass-a-123!", 4).expect("hash password");
    let hash_b = bcrypt::hash("mod003-pass-b-456!", 4).expect("hash password");

    let mut store_a = accounts_a.users().expect("open users A");
    let mut store_b = accounts_b.users().expect("open users B");
    assert!(matches!(
        store_a
            .create_user("mod003_svc_alice", &hash_a)
            .expect("create A"),
        CreateOutcome::Created
    ));
    assert!(matches!(
        store_b
            .create_user("mod003_svc_alice", &hash_b)
            .expect("create B"),
        CreateOutcome::Created
    ));

    assert!(
        accounts_a
            .users()
            .expect("reopen A")
            .validate_user("mod003_svc_alice", "mod003-pass-a-123!")
            .expect("validate A own")
    );
    assert!(
        !accounts_a
            .users()
            .expect("reopen A")
            .validate_user("mod003_svc_alice", "mod003-pass-b-456!")
            .expect("validate A peer"),
        "service A must reject service B's password"
    );
    assert!(
        accounts_b
            .users()
            .expect("reopen B")
            .validate_user("mod003_svc_alice", "mod003-pass-b-456!")
            .expect("validate B own")
    );
    assert!(
        !accounts_b
            .users()
            .expect("reopen B")
            .validate_user("mod003_svc_alice", "mod003-pass-a-123!")
            .expect("validate B peer"),
        "service B must reject service A's password"
    );

    let mut store_a = accounts_a.users().expect("open A mut");
    store_a
        .update_user_preferences(
            "mod003_svc_alice",
            Some("set-a".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("prefs A");
    let mut store_b = accounts_b.users().expect("open B mut");
    store_b
        .update_user_preferences(
            "mod003_svc_alice",
            Some("set-b".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("prefs B");
    let (last_a, ..) = accounts_a
        .users()
        .expect("read A")
        .user_preferences("mod003_svc_alice")
        .expect("prefs A");
    let (last_b, ..) = accounts_b
        .users()
        .expect("read B")
        .user_preferences("mod003_svc_alice")
        .expect("prefs B");
    assert_eq!(last_a.as_deref(), Some("set-a"));
    assert_eq!(last_b.as_deref(), Some("set-b"));

    let key_a = accounts_a
        .users()
        .expect("open A")
        .derive_encryption_key("mod003_svc_alice", "mod003-shared-password")
        .expect("derive A");
    let key_b = accounts_b
        .users()
        .expect("open B")
        .derive_encryption_key("mod003_svc_alice", "mod003-shared-password")
        .expect("derive B");
    assert_ne!(key_a, key_b, "independent roots must not share salts");
}

#[test]
fn ordinary_verifier_uses_explicit_secret_without_global_config() {
    let (_tmp_a, accounts_a) = make_service("mod003-explicit-secret-a");
    let (_tmp_b, accounts_b) = make_service("mod003-explicit-secret-b");
    const DATA_KEY: &[u8] = b"mod003-account-data-key";
    const WRONG_KEY: &[u8] = b"mod003-account-wrong-key";

    accounts_a
        .users()
        .expect("open A")
        .ensure_key_verifier("mod003_svc_bob", DATA_KEY)
        .expect("enroll A via ordinary API");

    assert!(
        accounts_a
            .users()
            .expect("open A")
            .verify_encryption_key("mod003_svc_bob", DATA_KEY)
            .expect("verify A own"),
        "ordinary verify must use the explicit secret"
    );
    assert!(
        !accounts_a
            .users()
            .expect("open A")
            .verify_encryption_key("mod003_svc_bob", WRONG_KEY)
            .expect("verify A wrong"),
        "wrong key must not verify"
    );
    assert!(
        accounts_a
            .users()
            .expect("open A")
            .ensure_key_verifier("mod003_svc_bob", WRONG_KEY)
            .is_err(),
        "ensure with a mismatched key must fail without clobbering"
    );
    assert!(
        accounts_a
            .users()
            .expect("open A")
            .verify_encryption_key("mod003_svc_bob", DATA_KEY)
            .expect("verify A intact"),
        "failed ensure must leave the verifier intact"
    );

    assert!(
        !accounts_b
            .users()
            .expect("open B")
            .verify_encryption_key("mod003_svc_bob", DATA_KEY)
            .expect("verify B peer"),
        "verifiers must not leak across services"
    );
    accounts_b
        .users()
        .expect("open B")
        .ensure_key_verifier("mod003_svc_bob", DATA_KEY)
        .expect("enroll B independently");
    assert!(
        accounts_b
            .users()
            .expect("open B")
            .verify_encryption_key("mod003_svc_bob", DATA_KEY)
            .expect("verify B own")
    );
    assert!(
        accounts_a
            .users()
            .expect("open A")
            .verify_encryption_key("mod003_svc_bob", DATA_KEY)
            .expect("verify A unaffected"),
        "peer enrollment must not disturb the owner"
    );

    // Same key under the peer secret never verifies through the one-off
    // override, proving the ordinary path bound the explicit secret.
    assert!(
        !accounts_a
            .users()
            .expect("open A")
            .verify_encryption_key_with_secret(
                "mod003_svc_bob",
                DATA_KEY,
                b"mod003-explicit-secret-b"
            )
            .expect("foreign secret check"),
        "same key under a foreign secret must fail"
    );
}

#[test]
fn remember_tokens_are_service_scoped_with_rotation() {
    let (_tmp_a, accounts_a) = make_service("mod003-remember-secret-a");
    let (_tmp_b, accounts_b) = make_service("mod003-remember-secret-b");

    let token = accounts_a
        .remember()
        .expect("remember A")
        .issue("mod003_svc_carol")
        .expect("issue");
    let replacement = match accounts_a
        .remember()
        .expect("remember A")
        .resume(Some(&token))
        .expect("resume own")
    {
        ResumeOutcome::Authenticated {
            username,
            replacement_token,
        } => {
            assert_eq!(username, "mod003_svc_carol");
            assert_ne!(replacement_token, token, "resume must rotate");
            replacement_token
        }
        ResumeOutcome::Invalid => panic!("own token rejected"),
    };

    assert!(
        matches!(
            accounts_b
                .remember()
                .expect("remember B")
                .resume(Some(&token))
                .expect("resume foreign"),
            ResumeOutcome::Invalid
        ),
        "peer service must reject the foreign token"
    );
    assert!(
        matches!(
            accounts_b
                .remember()
                .expect("remember B")
                .resume(Some(&replacement))
                .expect("resume rotated foreign"),
            ResumeOutcome::Invalid
        ),
        "peer service must reject the rotated token"
    );

    let peer_token = accounts_b
        .remember()
        .expect("remember B")
        .issue("mod003_svc_carol")
        .expect("issue peer");
    assert!(matches!(
        accounts_b
            .remember()
            .expect("remember B")
            .resume(Some(&peer_token))
            .expect("resume peer"),
        ResumeOutcome::Authenticated { .. }
    ));
    assert!(
        matches!(
            accounts_a
                .remember()
                .expect("remember A")
                .resume(Some(&replacement))
                .expect("resume rotated own"),
            ResumeOutcome::Authenticated { .. }
        ),
        "foreign resumes must not disturb the owning family"
    );
}

fn secret_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Removes SECRET_KEY and drops any initialized global config, restoring both
/// afterwards. Holds the shared static mutex for the whole window so the two
/// lazy-parity tests serialise against each other; all other tests in this
/// binary use explicit roots/secrets and never read ambient config.
struct SecretGuard {
    _held: MutexGuard<'static, ()>,
    previous: Option<String>,
}

impl SecretGuard {
    fn remove() -> Self {
        let held = secret_mutex()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = env::var("SECRET_KEY").ok();
        env::remove_var("SECRET_KEY");
        config::reset();
        Self {
            _held: held,
            previous,
        }
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
fn explicit_verifier_early_returns_do_not_initialize_config() {
    // With SECRET_KEY unset, any global config initialization panics
    // fail-closed, so reaching the assertions below proves the explicit
    // verifier path stays lazy on early-return inputs.
    let (_temp, accounts) = make_service("mod003-lazy-secret");
    let _secret = SecretGuard::remove();

    assert!(
        accounts
            .users()
            .expect("open explicit store")
            .verify_encryption_key("", b"mod003-key")
            .is_err(),
        "invalid names must report an error without initializing config"
    );
    assert!(
        accounts
            .users()
            .expect("open explicit store")
            .verify_encryption_key("not a user!", b"mod003-key")
            .is_err(),
        "invalid names must report an error without initializing config"
    );
    assert!(
        accounts
            .users()
            .expect("open explicit store")
            .ensure_key_verifier("", b"mod003-key")
            .is_err(),
        "invalid names must report an error without initializing config"
    );
    assert_eq!(
        accounts
            .users()
            .expect("open explicit store")
            .verify_encryption_key("mod003_nobody", b"mod003-key")
            .expect("missing verifier reports false"),
        false,
        "missing verifiers must report false without initializing config"
    );
}

#[test]
fn explicit_enroll_and_verify_do_not_initialize_config() {
    // The ordinary explicit APIs must succeed with no global config present,
    // proving they bind the explicit secret instead of resolving it lazily.
    let (_temp, accounts) = make_service("mod003-lazy-enroll-secret");
    let _secret = SecretGuard::remove();

    accounts
        .users()
        .expect("open explicit store")
        .ensure_key_verifier("mod003_lazy_user", b"mod003-lazy-key")
        .expect("explicit enroll without config");
    assert!(
        accounts
            .users()
            .expect("open explicit store")
            .verify_encryption_key("mod003_lazy_user", b"mod003-lazy-key")
            .expect("explicit verify without config"),
        "explicit enrollment must verify without initializing config"
    );
    assert!(
        !accounts
            .users()
            .expect("open explicit store")
            .verify_encryption_key("mod003_lazy_user", b"mod003-lazy-wrong")
            .expect("explicit wrong-key check"),
        "wrong key must not verify"
    );
}
