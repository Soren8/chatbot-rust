//! MOD003: owned HTTP identity store isolation.
//!
//! Two `HttpSessionStore` instances share nothing: bootstrap, session
//! lookup, login/logout rotation, CSRF validation and the non-creating
//! rate-limit identity are all scoped to the owning store. CSRF policy
//! travels as an explicit per-call flag, so these tests never touch the
//! process-global config.

use chatbot_core::session_identity::HttpSessionStore;

/// Raw `session=<value>` pair carried in `Set-Cookie`.
fn cookie_value(set_cookie: &str) -> String {
    let pair = set_cookie.split(';').next().unwrap_or(set_cookie).trim();
    pair.strip_prefix("session=")
        .expect("identity cookie must be named session")
        .to_owned()
}

fn cookie_header(value: &str) -> String {
    format!("session={value}")
}

#[test]
fn two_stores_isolate_bootstrap_lookup_login_logout_lifecycle() {
    let store_a = HttpSessionStore::new(3600);
    let store_b = HttpSessionStore::new(3600);

    let bootstrap_a = store_a
        .prepare_home_context(None, true)
        .expect("bootstrap store A");
    let bootstrap_b = store_b
        .prepare_home_context(None, true)
        .expect("bootstrap store B");

    assert!(
        bootstrap_a.session_id.starts_with("guest_"),
        "owned bootstrap must use the guest_ prefix, got {}",
        bootstrap_a.session_id
    );
    assert_eq!(
        bootstrap_a.session_id.len(),
        "guest_".len() + 22,
        "guest suffix is 16 random bytes as unpadded base64"
    );
    assert_eq!(bootstrap_a.username, None);
    assert_eq!(
        bootstrap_a.csrf_token.len(),
        43,
        "CSRF token is 32 random bytes as unpadded base64"
    );
    assert_eq!(
        cookie_value(&bootstrap_a.set_cookie).len(),
        43,
        "session cookie is 32 random bytes"
    );
    for flag in ["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=3600", "Secure"] {
        assert!(
            bootstrap_a.set_cookie.contains(flag),
            "Set-Cookie must carry {flag}: {}",
            bootstrap_a.set_cookie
        );
    }
    assert_ne!(
        bootstrap_a.session_id, bootstrap_b.session_id,
        "independent stores must not share guest identities"
    );
    assert_ne!(
        cookie_value(&bootstrap_a.set_cookie),
        cookie_value(&bootstrap_b.set_cookie),
        "independent stores must not share cookies"
    );

    let header_a = cookie_header(&cookie_value(&bootstrap_a.set_cookie));

    let repeat_a = store_a
        .prepare_home_context(Some(&header_a), true)
        .expect("repeat bootstrap on owning store");
    assert_eq!(repeat_a.session_id, bootstrap_a.session_id);
    assert_eq!(repeat_a.csrf_token, bootstrap_a.csrf_token);
    assert_eq!(
        cookie_value(&repeat_a.set_cookie),
        cookie_value(&bootstrap_a.set_cookie)
    );

    let context_a = store_a
        .session_context(Some(&header_a))
        .expect("owning store resolves its cookie");
    assert_eq!(context_a.session_id, bootstrap_a.session_id);
    assert_eq!(context_a.username, None);

    let foreign = store_b
        .session_context(Some(&header_a))
        .expect("peer store looks up the foreign cookie");
    assert_ne!(
        foreign.session_id, bootstrap_a.session_id,
        "peer store must mint a fresh guest for an unknown cookie"
    );
    assert_eq!(foreign.username, None);

    let login = store_a
        .finalize_login(Some(&header_a), "mod003_alice", true)
        .expect("login on owning store");
    assert_eq!(login.session_id, "mod003_alice");
    assert_eq!(login.csrf_token.len(), 43);
    let login_value = cookie_value(&login.set_cookie);
    assert_ne!(
        login_value,
        cookie_value(&bootstrap_a.set_cookie),
        "login must rotate the cookie"
    );

    let login_header = cookie_header(&login_value);
    let context = store_a
        .session_context(Some(&login_header))
        .expect("login context on owning store");
    assert_eq!(context.session_id, "mod003_alice");
    assert_eq!(context.username.as_deref(), Some("mod003_alice"));
    assert_eq!(
        store_a.rate_limit_identity(Some(&login_header)),
        Some("user:mod003_alice".to_string())
    );

    assert_eq!(
        store_b.rate_limit_identity(Some(&login_header)),
        Some(format!("guest:{login_value}")),
        "peer store must treat the login cookie as unknown"
    );
    let foreign_login = store_b
        .session_context(Some(&login_header))
        .expect("peer store looks up the login cookie");
    assert_ne!(
        foreign_login.session_id, "mod003_alice",
        "peer store must not adopt the login identity"
    );

    let logout = store_a
        .logout_user(Some(&login_header), true)
        .expect("logout on owning store");
    assert!(
        logout.session_id.starts_with("guest_"),
        "logout must return to a guest identity, got {}",
        logout.session_id
    );
    let logout_value = cookie_value(&logout.set_cookie);
    assert_ne!(logout_value, login_value, "logout must rotate the cookie");

    let logout_header = cookie_header(&logout_value);
    let context = store_a
        .session_context(Some(&logout_header))
        .expect("logout context on owning store");
    assert_eq!(context.session_id, logout.session_id);
    assert_eq!(context.username, None);
    assert_eq!(
        store_a.rate_limit_identity(Some(&logout_header)),
        Some(format!("guest:{}", logout.session_id))
    );

    assert_eq!(
        store_a.rate_limit_identity(Some(&login_header)),
        Some(format!("guest:{login_value}")),
        "the logged-in cookie is revoked after logout"
    );
    let recycled = store_a
        .session_context(Some(&login_header))
        .expect("revoked cookie mints a fresh guest");
    assert_ne!(recycled.session_id, "mod003_alice");
    assert_eq!(recycled.username, None);

    let peer_header = cookie_header(&cookie_value(&bootstrap_b.set_cookie));
    let peer = store_b
        .session_context(Some(&peer_header))
        .expect("peer store keeps its own bootstrap");
    assert_eq!(peer.session_id, bootstrap_b.session_id);
    assert_eq!(peer.username, None);
}

#[test]
fn csrf_tokens_are_store_scoped_and_policy_gated() {
    let store_a = HttpSessionStore::new(3600);
    let store_b = HttpSessionStore::new(3600);

    let bootstrap_a = store_a
        .prepare_home_context(None, true)
        .expect("bootstrap store A");
    let bootstrap_b = store_b
        .prepare_home_context(None, true)
        .expect("bootstrap store B");
    let header_a = cookie_header(&cookie_value(&bootstrap_a.set_cookie));
    let header_b = cookie_header(&cookie_value(&bootstrap_b.set_cookie));

    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), Some(&bootstrap_a.csrf_token), true)
            .expect("validate csrf"),
        true
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), Some("wrong-token"), true)
            .expect("validate csrf"),
        false
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), None, true)
            .expect("validate csrf"),
        false
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), Some(""), true)
            .expect("validate csrf"),
        false
    );

    assert_eq!(
        store_b
            .validate_csrf_token(Some(&header_a), Some(&bootstrap_a.csrf_token), true)
            .expect("validate csrf"),
        false,
        "tokens must not validate against the peer store"
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_b), Some(&bootstrap_b.csrf_token), true)
            .expect("validate csrf"),
        false,
        "tokens must not validate against a foreign session"
    );

    let login = store_a
        .finalize_login(Some(&header_a), "mod003_carol", true)
        .expect("login rotates CSRF");
    let login_header = cookie_header(&cookie_value(&login.set_cookie));
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&login_header), Some(&login.csrf_token), true)
            .expect("validate csrf"),
        true
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), Some(&bootstrap_a.csrf_token), true)
            .expect("validate csrf"),
        false,
        "the revoked guest cookie must no longer validate"
    );

    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), Some("wrong-token"), false)
            .expect("validate csrf"),
        true,
        "disabled policy passes without checking the token"
    );
    assert_eq!(
        store_a
            .validate_csrf_token(Some(&header_a), None, false)
            .expect("validate csrf"),
        true,
        "disabled policy passes without a token"
    );

    assert!(
        bootstrap_a.set_cookie.contains("Secure"),
        "csrf-enabled bootstrap must flag Secure: {}",
        bootstrap_a.set_cookie
    );
    let insecure = store_a
        .prepare_home_context(None, false)
        .expect("csrf-disabled bootstrap");
    assert!(
        !insecure.set_cookie.contains("Secure"),
        "csrf-disabled bootstrap must omit Secure: {}",
        insecure.set_cookie
    );
}

#[test]
fn rate_limit_identity_is_noncreating_and_store_scoped() {
    let store_a = HttpSessionStore::new(3600);
    let store_b = HttpSessionStore::new(3600);

    assert_eq!(store_a.rate_limit_identity(None), None);
    assert_eq!(store_b.rate_limit_identity(None), None);

    let unknown = "session=mod003-unknown-cookie";
    assert_eq!(
        store_a.rate_limit_identity(Some(unknown)),
        Some("guest:mod003-unknown-cookie".to_string())
    );
    assert_eq!(
        store_a.rate_limit_identity(Some(unknown)),
        Some("guest:mod003-unknown-cookie".to_string())
    );

    // Proof nothing was created: validation still misses and bootstrap mints
    // new state instead of adopting the unknown cookie.
    assert_eq!(
        store_a
            .validate_csrf_token(Some(unknown), Some("anything"), true)
            .expect("validate csrf"),
        false
    );
    let bootstrap = store_a
        .prepare_home_context(Some(unknown), true)
        .expect("bootstrap unknown cookie");
    assert_ne!(
        cookie_value(&bootstrap.set_cookie),
        "mod003-unknown-cookie"
    );
    assert!(bootstrap.session_id.starts_with("guest_"));

    let known_header = cookie_header(&cookie_value(&bootstrap.set_cookie));
    let context = store_a
        .session_context(Some(&known_header))
        .expect("known context");
    assert_eq!(
        store_a.rate_limit_identity(Some(&known_header)),
        Some(format!("guest:{}", context.session_id))
    );

    let login = store_a
        .finalize_login(Some(&known_header), "mod003_dave", true)
        .expect("login");
    let login_value = cookie_value(&login.set_cookie);
    let login_header = cookie_header(&login_value);
    assert_eq!(
        store_a.rate_limit_identity(Some(&login_header)),
        Some("user:mod003_dave".to_string())
    );

    assert_eq!(
        store_b.rate_limit_identity(Some(&login_header)),
        Some(format!("guest:{login_value}")),
        "peer store must treat the login cookie as unknown"
    );
    assert_eq!(
        store_b.rate_limit_identity(Some(&known_header)),
        Some(format!("guest:{}", cookie_value(&bootstrap.set_cookie))),
        "peer store must treat the guest cookie as unknown"
    );
}

#[test]
fn short_timeout_resolves_to_minimum_60s_cookie_age() {
    let floored = HttpSessionStore::new(30);
    let standard = HttpSessionStore::new(3600);

    let floored_bootstrap = floored
        .prepare_home_context(None, true)
        .expect("bootstrap floored store");
    assert!(
        floored_bootstrap.set_cookie.contains("Max-Age=60"),
        "30s resolves to the 60s floor: {}",
        floored_bootstrap.set_cookie
    );

    let standard_bootstrap = standard
        .prepare_home_context(None, true)
        .expect("bootstrap standard store");
    assert!(
        standard_bootstrap.set_cookie.contains("Max-Age=3600"),
        "explicit per-store timeout drives Max-Age: {}",
        standard_bootstrap.set_cookie
    );
}
