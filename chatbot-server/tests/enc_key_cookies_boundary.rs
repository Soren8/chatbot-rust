use std::{
    env,
    sync::{Mutex, OnceLock},
};

use axum::http::{header, HeaderMap};
use chatbot_core::{enc_key::EncryptionKey, remember_store::RememberStore};
use chatbot_server::chat_utils as cookies;

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

fn seed_user(username: &str, password: &str) {
    use bcrypt::{hash, DEFAULT_COST};
    use chatbot_core::user_store::{CreateOutcome, UserStore};

    let mut store = UserStore::new().expect("initialise user store");
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    match store.create_user(username, &hashed) {
        Ok(CreateOutcome::Created) | Ok(CreateOutcome::AlreadyExists) => {}
        Err(err) => panic!("failed to create test user: {err}"),
    }
}

fn derive_key_b64(username: &str, password: &str) -> String {
    use chatbot_core::user_store::UserStore;

    let store = UserStore::new().expect("user store");
    String::from_utf8(
        store
            .derive_encryption_key(username, password)
            .expect("derive key"),
    )
    .expect("key utf8")
}

fn register_verifier(username: &str, password: &str) {
    use chatbot_core::user_store::UserStore;

    let store = UserStore::new().expect("user store");
    let key = store
        .derive_encryption_key(username, password)
        .expect("derive key");
    store
        .ensure_key_verifier(username, &key)
        .expect("register verifier");
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

fn session_cookie_pair(username: &str) -> String {
    let finalize =
        chatbot_core::session::finalize_login(None, username).expect("finalize login session");
    cookie_pair(&finalize.set_cookie)
}

fn headers_with(cookie_header: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        cookie_header.parse().expect("cookie header value"),
    );
    headers
}

fn key_string(key: &EncryptionKey) -> &str {
    std::str::from_utf8(key.as_bytes()).expect("key utf8")
}

#[test]
fn header_enc_key_takes_precedence_over_any_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let session_pair = session_cookie_pair("ck_header_alice");
    let cookie_header = format!(
        "{session_pair}; enc_key=cookie-generic-xyz; enc_key-ck_header_alice=cookie-account-xyz"
    );
    let mut headers = headers_with(&cookie_header);
    headers.insert("X-Enc-Key", "header-key-abc123".parse().unwrap());

    let extracted = cookies::extract_enc_key(&headers).expect("extract enc key");

    assert_eq!(key_string(&extracted), "header-key-abc123");
}

#[test]
fn authenticated_session_prefers_account_cookie_over_generic() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let session_pair = session_cookie_pair("ck_pref_alice");
    let cookie_header = format!(
        "{session_pair}; enc_key=generic-key-111; enc_key-ck_pref_alice=account-key-222"
    );

    let extracted =
        cookies::extract_enc_key(&headers_with(&cookie_header)).expect("extract enc key");

    assert_eq!(key_string(&extracted), "account-key-222");
}

#[test]
fn generic_cookie_is_used_when_account_cookie_absent() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let session_pair = session_cookie_pair("ck_generic_alice");
    let cookie_header = format!("{session_pair}; enc_key=generic-only-456");

    let extracted =
        cookies::extract_enc_key(&headers_with(&cookie_header)).expect("extract enc key");

    assert_eq!(key_string(&extracted), "generic-only-456");
}

#[test]
fn account_cookie_is_ignored_without_authenticated_session() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let with_both = headers_with("enc_key=generic-abc; enc_key-ck_nosess=account-xyz");
    let extracted = cookies::extract_enc_key(&with_both).expect("fallback to generic");
    assert_eq!(key_string(&extracted), "generic-abc");

    let account_only = headers_with("enc_key-ck_nosess=account-xyz");
    assert!(
        cookies::extract_enc_key(&account_only).is_none(),
        "account cookie alone must not resolve without a session"
    );
}

#[test]
fn empty_cookie_values_are_skipped() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    assert!(cookies::extract_enc_key_cookie(None).is_none());
    assert!(cookies::extract_enc_key_cookie(Some("enc_key=; other=1")).is_none());
    assert!(
        cookies::extract_account_enc_key_cookie(Some("enc_key-alice=; other=1"), "alice")
            .is_none()
    );

    let generic = cookies::extract_enc_key_cookie(Some("enc_key=; enc_key=valid-key-123"))
        .expect("empty first value is skipped");
    assert_eq!(key_string(&generic), "valid-key-123");

    let account = cookies::extract_account_enc_key_cookie(
        Some("enc_key-alice=; enc_key-alice=valid-acct-456"),
        "alice",
    )
    .expect("empty account value is skipped");
    assert_eq!(key_string(&account), "valid-acct-456");
}

#[test]
fn url_encoded_cookie_values_are_decoded() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let raw = "enc key+with/special=chars&more";
    let encoded = urlencoding::encode(raw);

    let generic =
        cookies::extract_enc_key_cookie(Some(&format!("enc_key={encoded}")))
            .expect("encoded generic cookie");
    assert_eq!(key_string(&generic), raw);

    let account = cookies::extract_account_enc_key_cookie(
        Some(&format!("enc_key-alice={encoded}")),
        "alice",
    )
    .expect("encoded account cookie");
    assert_eq!(key_string(&account), raw);
}

#[test]
fn cookie_names_require_exact_match() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    assert!(
        cookies::extract_enc_key_cookie(Some(
            "enc_key-alice=accountval; enc_keyx=nope"
        ))
        .is_none(),
        "generic extractor must ignore account and prefixed names"
    );
    assert!(
        cookies::extract_enc_key_cookie(Some("xenc_key=genericval")).is_none(),
        "generic extractor must ignore suffixed names"
    );

    assert!(
        cookies::extract_account_enc_key_cookie(Some("enc_key=genericval"), "alice").is_none()
    );
    assert!(
        cookies::extract_account_enc_key_cookie(Some("enc_key-bob=otherval"), "alice").is_none()
    );
    assert!(
        cookies::extract_account_enc_key_cookie(Some("enc_key-alice2=otherval"), "alice")
            .is_none(),
        "account extractor must ignore longer usernames sharing a prefix"
    );

    let account =
        cookies::extract_account_enc_key_cookie(Some("enc_key-alice=acctval"), "alice")
            .expect("exact account name");
    assert_eq!(key_string(&account), "acctval");
}

#[test]
fn account_cookie_name_derives_from_generic_name() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    assert_eq!(cookies::ENC_KEY_COOKIE_NAME, "enc_key");
    assert_eq!(
        cookies::account_enc_key_cookie_name("alice"),
        "enc_key-alice"
    );
}

#[test]
fn set_cookies_carry_strict_flags_and_configured_lifetime() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let key = "test-key-material-123";
    let encoded = urlencoding::encode(key);

    let generic = cookies::build_enc_key_set_cookie(key, 3600);
    assert_eq!(
        generic,
        format!("enc_key={encoded}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600")
    );

    let account = cookies::build_enc_key_account_set_cookie("alice", key, 2592000);
    assert_eq!(
        account,
        format!(
            "enc_key-alice={encoded}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000"
        )
    );

    let special = "a b+c/d=e";
    let special_encoded = urlencoding::encode(special);
    let special_cookie = cookies::build_enc_key_set_cookie(special, 60);
    assert_eq!(
        special_cookie,
        format!(
            "enc_key={special_encoded}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=60"
        )
    );
}

#[test]
fn clear_cookies_expire_immediately_with_strict_flags() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    assert_eq!(
        cookies::build_enc_key_clear_cookie(),
        "enc_key=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
    );
    assert_eq!(
        cookies::build_enc_key_account_clear_cookie("alice"),
        "enc_key-alice=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
    );
}

#[test]
fn enc_key_cookie_value_returns_key_material() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();

    let key = EncryptionKey::from_header_value("test-key-material").expect("valid key");

    assert_eq!(
        cookies::enc_key_cookie_value(&key),
        Some("test-key-material")
    );
}

#[test]
fn promote_restores_missing_generic_from_verified_account_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_restore_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);
    let key = derive_key_b64(username, password);

    let cookie_header = format!(
        "enc_key-{username}={}",
        urlencoding::encode(&key)
    );
    let promoted = cookies::promote_enc_key_cookies(Some(&cookie_header), username);

    assert_eq!(
        promoted,
        vec![format!(
            "enc_key={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
            urlencoding::encode(&key)
        )],
        "verified account cookie restores the missing generic cookie with session lifetime"
    );
}

#[test]
fn promote_leaves_matching_cookies_without_sliding_max_age() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_nominal_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);
    let key = derive_key_b64(username, password);
    let encoded = urlencoding::encode(&key);

    let cookie_header = format!("enc_key={encoded}; enc_key-{username}={encoded}");
    let promoted = cookies::promote_enc_key_cookies(Some(&cookie_header), username);

    assert!(
        promoted.is_empty(),
        "matching cookies must not slide max-age, got {promoted:?}"
    );
}

#[test]
fn promote_rejects_unverified_keys() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_unverified_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);

    let generic_wrong = cookies::promote_enc_key_cookies(
        Some("enc_key=definitely-not-the-right-key"),
        username,
    );
    assert!(
        generic_wrong.is_empty(),
        "unverified generic key must not promote, got {generic_wrong:?}"
    );

    let account_wrong = cookies::promote_enc_key_cookies(
        Some("enc_key-ck_unverified_alice=definitely-not-the-right-key"),
        username,
    );
    assert!(
        account_wrong.is_empty(),
        "unverified account key must not promote, got {account_wrong:?}"
    );
}

#[test]
fn promote_blocks_generic_fallback_when_account_key_mismatches() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_blocked_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);
    let key = derive_key_b64(username, password);

    let cookie_header = format!(
        "enc_key={}; enc_key-{username}=mismatched-account-key",
        urlencoding::encode(&key)
    );
    let promoted = cookies::promote_enc_key_cookies(Some(&cookie_header), username);

    assert!(
        promoted.is_empty(),
        "mismatched account cookie blocks the valid generic fallback, got {promoted:?}"
    );
}

#[test]
fn promote_copies_generic_key_to_account_when_remembered() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_remembered_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);
    let key = derive_key_b64(username, password);

    let token = RememberStore::new()
        .expect("remember store")
        .issue_or_refresh(username, None)
        .expect("issue remember token");
    let cookie_header = format!(
        "enc_key={}; remember={token}",
        urlencoding::encode(&key)
    );
    let promoted = cookies::promote_enc_key_cookies(Some(&cookie_header), username);

    assert_eq!(
        promoted,
        vec![format!(
            "enc_key-{username}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000",
            urlencoding::encode(&key)
        )],
        "remembered generic key is copied to the account cookie with remember lifetime"
    );
}

#[test]
fn promote_leaves_generic_alone_when_not_remembered() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let username = "ck_plain_alice";
    let password = "Sup3rS3cret!";
    seed_user(username, password);
    register_verifier(username, password);
    let key = derive_key_b64(username, password);

    let cookie_header = format!("enc_key={}", urlencoding::encode(&key));
    let promoted = cookies::promote_enc_key_cookies(Some(&cookie_header), username);

    assert!(
        promoted.is_empty(),
        "unremembered generic alone needs no promotion, got {promoted:?}"
    );
}
