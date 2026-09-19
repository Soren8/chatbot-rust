use axum::http::{header, HeaderMap};
use chatbot_core::account_service::AccountService;
use chatbot_core::config_source::ConfigSource;
use chatbot_core::enc_key::EncryptionKey;

use crate::identity::RequestIdentity;

pub const ENC_KEY_COOKIE_NAME: &str = "enc_key";

pub fn account_enc_key_cookie_name(username: &str) -> String {
    format!("{ENC_KEY_COOKIE_NAME}-{username}")
}

pub fn extract_enc_key(headers: &HeaderMap) -> Option<EncryptionKey> {
    extract_enc_key_with_identity(&RequestIdentity::global(), headers)
}

/// Request-scoped variant: the account-cookie lookup runs against the
/// router's identity instead of the process-global store. Handlers must
/// use this; the header-only wrapper above stays for direct compatibility
/// callers (existing tests).
pub fn extract_enc_key_with_identity(
    identity: &RequestIdentity,
    headers: &HeaderMap,
) -> Option<EncryptionKey> {
    headers
        .get("X-Enc-Key")
        .and_then(|value| value.to_str().ok())
        .and_then(EncryptionKey::from_header_value)
        .or_else(|| {
            let cookie = headers
                .get(header::COOKIE)
                .and_then(|value| value.to_str().ok());
            let username = identity
                .session_context(cookie)
                .ok()
                .and_then(|ctx| ctx.username);
            let account_key = username
                .as_deref()
                .and_then(|u| extract_account_enc_key_cookie(cookie, u));
            account_key.or_else(|| extract_enc_key_cookie(cookie))
        })
}

pub fn extract_enc_key_cookie(cookie_header: Option<&str>) -> Option<EncryptionKey> {
    decode_named_enc_cookie(cookie_header, ENC_KEY_COOKIE_NAME)
}

pub fn extract_account_enc_key_cookie(
    cookie_header: Option<&str>,
    username: &str,
) -> Option<EncryptionKey> {
    decode_named_enc_cookie(cookie_header, &account_enc_key_cookie_name(username))
}

fn decode_named_enc_cookie(cookie_header: Option<&str>, name: &str) -> Option<EncryptionKey> {
    let header = cookie_header?;
    let prefix = format!("{name}=");
    for part in header.split(';') {
        let part = part.trim();
        let Some(value) = part.strip_prefix(&prefix) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let decoded = urlencoding::decode(value).ok()?;
        return EncryptionKey::from_header_value(decoded.as_ref());
    }
    None
}

fn enc_cookie_secure_flag_with(csrf: bool) -> &'static str {
    if csrf {
        " Secure;"
    } else {
        ""
    }
}

pub fn build_enc_key_set_cookie(key: &str, max_age_secs: u64) -> String {
    build_named_enc_key_set_cookie(ENC_KEY_COOKIE_NAME, key, max_age_secs)
}

/// Explicit-CSRF variant with no ambient read for owned routers.
pub fn build_enc_key_set_cookie_with_csrf(key: &str, max_age_secs: u64, csrf: bool) -> String {
    build_named_enc_key_set_cookie_with_csrf(ENC_KEY_COOKIE_NAME, key, max_age_secs, csrf)
}

pub fn build_enc_key_account_set_cookie(username: &str, key: &str, max_age_secs: u64) -> String {
    build_named_enc_key_set_cookie(&account_enc_key_cookie_name(username), key, max_age_secs)
}

/// Explicit-CSRF variant with no ambient read for owned routers.
pub fn build_enc_key_account_set_cookie_with_csrf(
    username: &str,
    key: &str,
    max_age_secs: u64,
    csrf: bool,
) -> String {
    build_named_enc_key_set_cookie_with_csrf(
        &account_enc_key_cookie_name(username),
        key,
        max_age_secs,
        csrf,
    )
}

fn build_named_enc_key_set_cookie(name: &str, key: &str, max_age_secs: u64) -> String {
    build_named_enc_key_set_cookie_with_csrf(
        name,
        key,
        max_age_secs,
        chatbot_core::config::app_config().csrf,
    )
}

fn build_named_enc_key_set_cookie_with_csrf(
    name: &str,
    key: &str,
    max_age_secs: u64,
    csrf: bool,
) -> String {
    let encoded = urlencoding::encode(key);
    format!(
        "{name}={encoded}; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age={max_age_secs}",
        secure = enc_cookie_secure_flag_with(csrf)
    )
}

pub fn build_enc_key_clear_cookie() -> String {
    build_enc_key_clear_cookie_with_csrf(chatbot_core::config::app_config().csrf)
}

/// Explicit-CSRF variant with no ambient read for owned routers.
pub fn build_enc_key_clear_cookie_with_csrf(csrf: bool) -> String {
    format!(
        "{ENC_KEY_COOKIE_NAME}=; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age=0",
        secure = enc_cookie_secure_flag_with(csrf)
    )
}

pub fn build_enc_key_account_clear_cookie(username: &str) -> String {
    build_enc_key_account_clear_cookie_with_csrf(
        username,
        chatbot_core::config::app_config().csrf,
    )
}

/// Explicit-CSRF variant with no ambient read for owned routers.
pub fn build_enc_key_account_clear_cookie_with_csrf(username: &str, csrf: bool) -> String {
    let name = account_enc_key_cookie_name(username);
    format!(
        "{name}=; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age=0",
        secure = enc_cookie_secure_flag_with(csrf)
    )
}

pub fn enc_key_cookie_value(key: &EncryptionKey) -> Option<&str> {
    std::str::from_utf8(key.as_bytes()).ok()
}

/// After switch-account (last-used `enc_key` cleared) or a deploy that only had
/// last-used, copy a verified key onto the missing cookie. Does not slide
/// max-age when both cookies are already present.
///
/// Compatibility wrapper: promotes through the process-global account stores,
/// preserving the existing global-router behavior. Injected routers must use
/// [`promote_enc_key_cookies_with_accounts`] with their own service instead.
pub fn promote_enc_key_cookies(cookie_header: Option<&str>, username: &str) -> Vec<String> {
    promote_enc_key_cookies_with_accounts(cookie_header, username, &AccountService::global())
}

/// Scoped variant: promotes through the router's injected [`AccountService`]
/// so verification and remember checks resolve in that router's user/remember
/// stores only. Cookie secure/max-age stay live from global config.
pub fn promote_enc_key_cookies_with_accounts(
    cookie_header: Option<&str>,
    username: &str,
    accounts: &AccountService,
) -> Vec<String> {
    promote_enc_key_cookies_with_accounts_and_config(
        cookie_header,
        username,
        accounts,
        &ConfigSource::global(),
    )
}

/// Fully scoped variant: verification and remember checks use `accounts`
/// while cookie secure/max-age resolve from `config` with no other ambient
/// reads. Global-config routers behave exactly like
/// [`promote_enc_key_cookies_with_accounts`]; owned routers stay immune.
pub fn promote_enc_key_cookies_with_accounts_and_config(
    cookie_header: Option<&str>,
    username: &str,
    accounts: &AccountService,
    config: &ConfigSource,
) -> Vec<String> {
    let Ok(store) = accounts.users() else {
        return Vec::new();
    };
    let last = extract_enc_key_cookie(cookie_header);
    let account = extract_account_enc_key_cookie(cookie_header, username);

    // Prefer account-specific cookie first.
    let (key, from_account) = if let Some(ref acct_key) = account {
        if store
            .verify_encryption_key(username, acct_key.as_bytes())
            .unwrap_or(false)
        {
            (acct_key, true)
        } else {
            return Vec::new();
        }
    } else if let Some(ref last_key) = last {
        if store
            .verify_encryption_key(username, last_key.as_bytes())
            .unwrap_or(false)
        {
            (last_key, false)
        } else {
            return Vec::new();
        }
    } else {
        return Vec::new();
    };

    let Some(key_str) = enc_key_cookie_value(key) else {
        return Vec::new();
    };

    let remembered = chatbot_core::remember_store::extract_account_token(cookie_header, username).is_some()
        || accounts
            .remember()
            .ok()
            .and_then(|rs| rs.peek_username(chatbot_core::remember_store::extract_token(cookie_header).as_deref()))
            .as_deref() == Some(username);

    // Original read/error ordering: timeout resolves once when not remembered
    // (even with zero emits); each emitted cookie resolves CSRF separately at
    // its own site, and zero emits read no CSRF.
    let max_age = if remembered {
        chatbot_core::remember_store::REMEMBER_MAX_AGE_SECS
    } else {
        config.session_timeout().max(60)
    };

    let mut cookies = Vec::new();
    let last_matches = last.as_ref().map(|k| k.as_bytes()) == Some(key.as_bytes());
    if !last_matches {
        cookies.push(build_enc_key_set_cookie_with_csrf(
            key_str,
            max_age,
            config.csrf(),
        ));
    }
    if !from_account && remembered {
        cookies.push(build_enc_key_account_set_cookie_with_csrf(
            username,
            key_str,
            max_age,
            config.csrf(),
        ));
    }
    cookies
}
