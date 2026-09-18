//! HTTP identity lifecycle through the public `chatbot_core::session` API:
//! bootstrap, CSRF validation, login/logout rotation and noncreating
//! rate-limit identity lookup.

use std::{
    env,
    sync::{Mutex, OnceLock},
};

use chatbot_core::session::{
    finalize_login, logout_user, prepare_home_context, rate_limit_identity, session_context,
    validate_csrf_token,
};

mod common;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_openai_provider()
}

/// Raw `session=<value>` pair carried in `Set-Cookie`.
fn cookie_value(set_cookie: &str) -> String {
    let pair = set_cookie.split(';').next().unwrap_or(set_cookie).trim();
    pair
        .strip_prefix("session=")
        .expect("identity cookie must be named session")
        .to_owned()
}

fn cookie_header(value: &str) -> String {
    format!("session={value}")
}

#[test]
fn bootstrap_mints_guest_identity_with_csrf_and_cookie() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    let bootstrap = prepare_home_context(None).expect("bootstrap session");

    assert!(
        bootstrap.session_id.starts_with("guest_"),
        "guest bootstrap must use the guest_ prefix, got {}",
        bootstrap.session_id
    );
    assert_eq!(
        bootstrap.session_id.len(),
        "guest_".len() + 22,
        "guest suffix is 16 random bytes as unpadded base64"
    );
    assert_eq!(bootstrap.username, None);
    assert_eq!(
        bootstrap.csrf_token.len(),
        43,
        "CSRF token is 32 random bytes as unpadded base64"
    );
    let value = cookie_value(&bootstrap.set_cookie);
    assert_eq!(value.len(), 43, "session cookie is 32 random bytes");
    assert!(
        bootstrap.set_cookie.starts_with("session="),
        "unexpected Set-Cookie shape: {}",
        bootstrap.set_cookie
    );
    for flag in ["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=3600", "Secure"] {
        assert!(
            bootstrap.set_cookie.contains(flag),
            "Set-Cookie must carry {flag}: {}",
            bootstrap.set_cookie
        );
    }
}

#[test]
fn bootstrap_and_context_reuse_presented_cookie_with_stable_identifier() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    let first = prepare_home_context(None).expect("bootstrap session");
    let header = cookie_header(&cookie_value(&first.set_cookie));

    let second = prepare_home_context(Some(&header)).expect("repeat bootstrap");
    assert_eq!(second.session_id, first.session_id);
    assert_eq!(second.csrf_token, first.csrf_token);
    assert_eq!(second.username, None);
    assert_eq!(cookie_value(&second.set_cookie), cookie_value(&first.set_cookie));

    let context = session_context(Some(&header)).expect("session context");
    assert_eq!(context.session_id, first.session_id);
    assert_eq!(context.username, None);
}

#[test]
fn csrf_token_validates_only_for_matching_session() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    let bootstrap = prepare_home_context(None).expect("bootstrap session");
    let header = cookie_header(&cookie_value(&bootstrap.set_cookie));

    assert_eq!(
        validate_csrf_token(Some(&header), Some(&bootstrap.csrf_token)).expect("validate csrf"),
        true
    );
    assert_eq!(
        validate_csrf_token(Some(&header), Some("wrong-token")).expect("validate csrf"),
        false
    );
    assert_eq!(
        validate_csrf_token(Some(&header), None).expect("validate csrf"),
        false
    );
    assert_eq!(
        validate_csrf_token(Some(&header), Some("")).expect("validate csrf"),
        false
    );
    assert_eq!(
        validate_csrf_token(
            Some("session=mod002-no-such-session"),
            Some(&bootstrap.csrf_token)
        )
        .expect("validate csrf"),
        false
    );
}

#[test]
fn login_rotates_cookie_and_binds_username() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    let guest = prepare_home_context(None).expect("bootstrap session");
    let guest_value = cookie_value(&guest.set_cookie);
    let guest_header = cookie_header(&guest_value);
    let guest_csrf = guest.csrf_token.clone();

    let login = finalize_login(Some(&guest_header), "mod002_alice").expect("login");
    assert_eq!(login.session_id, "mod002_alice");
    assert_eq!(login.csrf_token.len(), 43);
    let login_value = cookie_value(&login.set_cookie);
    assert_ne!(login_value, guest_value, "login must rotate the cookie");

    let login_header = cookie_header(&login_value);
    let context = session_context(Some(&login_header)).expect("login context");
    assert_eq!(context.session_id, "mod002_alice");
    assert_eq!(context.username.as_deref(), Some("mod002_alice"));
    assert_eq!(
        validate_csrf_token(Some(&login_header), Some(&login.csrf_token)).expect("validate csrf"),
        true
    );
    assert_eq!(
        rate_limit_identity(Some(&login_header)),
        Some("user:mod002_alice".to_string())
    );

    // The presented guest cookie is revoked, not reused.
    assert_eq!(
        validate_csrf_token(Some(&guest_header), Some(&guest_csrf)).expect("validate csrf"),
        false
    );
    assert_eq!(
        rate_limit_identity(Some(&guest_header)),
        Some(format!("guest:{guest_value}"))
    );
    let recycled = session_context(Some(&guest_header)).expect("old cookie context");
    assert_ne!(recycled.session_id, "mod002_alice");
    assert_eq!(recycled.username, None);
}

#[test]
fn logout_rotates_logged_in_cookie_to_fresh_guest() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    let guest = prepare_home_context(None).expect("bootstrap session");
    let guest_header = cookie_header(&cookie_value(&guest.set_cookie));
    let login = finalize_login(Some(&guest_header), "mod002_bob").expect("login");
    let login_value = cookie_value(&login.set_cookie);
    let login_header = cookie_header(&login_value);

    let logout = logout_user(Some(&login_header)).expect("logout");
    assert!(
        logout.session_id.starts_with("guest_"),
        "logout must return to a guest identity, got {}",
        logout.session_id
    );
    let logout_value = cookie_value(&logout.set_cookie);
    assert_ne!(logout_value, login_value, "logout must rotate the cookie");

    let logout_header = cookie_header(&logout_value);
    let context = session_context(Some(&logout_header)).expect("logout context");
    assert_eq!(context.session_id, logout.session_id);
    assert_eq!(context.username, None);
    assert_eq!(
        rate_limit_identity(Some(&logout_header)),
        Some(format!("guest:{}", logout.session_id))
    );

    // The logged-in cookie is revoked.
    assert_eq!(
        rate_limit_identity(Some(&login_header)),
        Some(format!("guest:{login_value}"))
    );
}

#[test]
fn rate_limit_identity_is_noncreating_and_maps_unknown_to_cookie_key() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup();

    assert_eq!(rate_limit_identity(None), None);

    let unknown = "session=mod002-unknown-cookie";
    assert_eq!(
        rate_limit_identity(Some(unknown)),
        Some("guest:mod002-unknown-cookie".to_string())
    );
    // A second lookup agrees without having created anything.
    assert_eq!(
        rate_limit_identity(Some(unknown)),
        Some("guest:mod002-unknown-cookie".to_string())
    );

    // Proof nothing was created: bootstrapping the unknown cookie mints new state.
    let bootstrap = prepare_home_context(Some(unknown)).expect("bootstrap unknown");
    assert_ne!(
        cookie_value(&bootstrap.set_cookie),
        "mod002-unknown-cookie"
    );
    assert!(bootstrap.session_id.starts_with("guest_"));

    // A known guest maps to its stable session identifier.
    let known_header = cookie_header(&cookie_value(&bootstrap.set_cookie));
    let context = session_context(Some(&known_header)).expect("known context");
    assert_eq!(
        rate_limit_identity(Some(&known_header)),
        Some(format!("guest:{}", context.session_id))
    );
}
