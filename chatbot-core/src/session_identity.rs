use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use rand::Rng;
use thiserror::Error;

use crate::{config, fernet_crypto::constant_time_eq};

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HomeBootstrap {
    pub session_id: String,
    pub username: Option<String>,
    pub csrf_token: String,
    pub set_cookie: String,
}

#[derive(Debug, Clone)]
pub struct LoginFinalize {
    pub session_id: String,
    pub set_cookie: String,
    /// CSRF token of the new session; clients that restore sessions over
    /// fetch (remember token) need it to keep calling same-page endpoints.
    pub csrf_token: String,
}

#[derive(Debug, Clone)]
pub struct LogoutFinalize {
    pub session_id: String,
    pub set_cookie: String,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid session")]
    InvalidSession,
}

const SESSION_COOKIE_NAME: &str = "session";
pub(crate) const SESSION_GUEST_PREFIX: &str = "guest_";
const CSRF_TOKEN_BYTES: usize = 32;
const COOKIE_TOKEN_BYTES: usize = 32;
const GUEST_TOKEN_BYTES: usize = 16;

#[derive(Clone)]
struct HttpSessionRecord {
    guest_id: String,
    username: Option<String>,
    csrf_token: String,
    last_used: Instant,
}

/// Owned HTTP identity state: cookie-indexed session records plus the
/// resolved HTTP timeout. Two instances share nothing; production keeps one
/// process-global instance behind the free functions below.
pub struct HttpSessionStore {
    sessions: Mutex<HashMap<String, HttpSessionRecord>>,
    timeout: Duration,
}

impl HttpSessionStore {
    /// Explicit owned construction from the resolved `session_timeout` value.
    /// Applies the HTTP minimum-60s floor (chat's raw timeout stays separate).
    pub fn new(session_timeout_secs: u64) -> Self {
        HttpSessionStore {
            sessions: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(std::cmp::max(60, session_timeout_secs)),
        }
    }

    /// Process-global store behind the free functions. Public so scoped
    /// identities can init it first (preserving store-first first-use order)
    /// then resolve CSRF from their own config.
    pub fn global() -> &'static HttpSessionStore {
        static STORE: Lazy<HttpSessionStore> = Lazy::new(|| {
            let config = config::app_config();
            HttpSessionStore::new(config.session_timeout)
        });
        &STORE
    }

    fn is_live(&self, record: &HttpSessionRecord, now: Instant) -> bool {
        now.duration_since(record.last_used) <= self.timeout
    }

    /// Live record for `cookie_value`, touched. Expired records read as
    /// absent; the background purge removes them.
    fn live_record<'a>(
        &self,
        sessions: &'a mut HashMap<String, HttpSessionRecord>,
        cookie_value: &str,
        now: Instant,
    ) -> Option<&'a mut HttpSessionRecord> {
        let record = sessions.get_mut(cookie_value)?;
        if !self.is_live(record, now) {
            return None;
        }
        record.last_used = now;
        Some(record)
    }

    fn clean_expired(&self, sessions: &mut HashMap<String, HttpSessionRecord>, now: Instant) {
        sessions.retain(|_, record| self.is_live(record, now));
    }

    /// Owned purge hook. Public so composed servers can purge the same
    /// instance that backs their router; the global delegate stays composed
    /// in `session::purge_expired_sessions`.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        self.clean_expired(&mut sessions, now);
        before.saturating_sub(sessions.len())
    }

    /// Test instrumentation: number of stored records, expired or not.
    pub fn record_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    fn new_record(&self, now: Instant) -> (String, HttpSessionRecord) {
        let cookie_value = random_token(COOKIE_TOKEN_BYTES);
        let guest_id = random_token(GUEST_TOKEN_BYTES);
        let csrf_token = random_token(CSRF_TOKEN_BYTES);

        (
            cookie_value,
            HttpSessionRecord {
                guest_id,
                username: None,
                csrf_token,
                last_used: now,
            },
        )
    }

    fn ensure_record(
        &self,
        sessions: &mut HashMap<String, HttpSessionRecord>,
        cookie_header: Option<&str>,
        now: Instant,
    ) -> (String, bool) {
        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            if self.live_record(sessions, &cookie_value, now).is_some() {
                return (cookie_value, false);
            }
            sessions.remove(&cookie_value);
        }

        let (cookie_value, mut record) = self.new_record(now);
        record.last_used = now;
        sessions.insert(cookie_value.clone(), record);
        (cookie_value, true)
    }

    fn build_set_cookie(&self, value: &str, csrf_enabled: bool) -> String {
        let max_age = self.timeout.as_secs().clamp(60, 31_536_000);
        let secure = if csrf_enabled {
            " Secure;"
        } else {
            ""
        };
        format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={max_age}"
        )
    }

    /// Bootstrap (or reuse) the session for `cookie_header`.
    pub fn prepare_home_context(
        &self,
        cookie_header: Option<&str>,
        csrf_enabled: bool,
    ) -> Result<HomeBootstrap, SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();

        let (cookie_value, _) = self.ensure_record(&mut sessions, cookie_header, now);
        let snapshot = sessions
            .get(&cookie_value)
            .expect("session record should exist")
            .clone();
        drop(sessions);

        let session_id = session_identifier(&snapshot);
        let username = snapshot.username.clone();
        let csrf_token = snapshot.csrf_token.clone();
        let set_cookie = self.build_set_cookie(&cookie_value, csrf_enabled);

        Ok(HomeBootstrap {
            session_id,
            username,
            csrf_token,
            set_cookie,
        })
    }

    pub fn validate_csrf_token(
        &self,
        cookie_header: Option<&str>,
        token: Option<&str>,
        csrf_enabled: bool,
    ) -> Result<bool, SessionError> {
        if !csrf_enabled {
            return Ok(true);
        }

        let Some(token) = token else {
            return Ok(false);
        };

        if token.is_empty() {
            return Ok(false);
        }

        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();

        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            if let Some(record) = self.live_record(&mut sessions, &cookie_value, now) {
                return Ok(constant_time_eq(
                    record.csrf_token.as_bytes(),
                    token.as_bytes(),
                ));
            }
        }

        Ok(false)
    }

    /// Read-only lookup. Without a live record the caller gets an ephemeral
    /// guest context that is not stored: no Set-Cookie follows this call, so
    /// a stored record would be unreachable.
    pub fn session_context(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<SessionContext, SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();

        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            if let Some(record) = self.live_record(&mut sessions, &cookie_value, now) {
                return Ok(SessionContext {
                    session_id: session_identifier(record),
                    username: record.username.clone(),
                });
            }
        }
        drop(sessions);

        Ok(SessionContext {
            session_id: format!("{SESSION_GUEST_PREFIX}{}", random_token(GUEST_TOKEN_BYTES)),
            username: None,
        })
    }

    /// Stable rate-limit identity without creating a session.
    /// Prefers `user:{username}`, then `guest:{session_id}` for known cookies,
    /// then `guest:{cookie}` for presented-but-unknown cookies. Callers should
    /// fall back to an IP key when this returns `None`.
    pub fn rate_limit_identity(&self, cookie_header: Option<&str>) -> Option<String> {
        let cookie_value = extract_session_cookie(cookie_header)?;
        let sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        if let Some(record) = sessions
            .get(&cookie_value)
            .filter(|record| self.is_live(record, now))
        {
            if let Some(username) = record.username.as_deref() {
                return Some(format!("user:{username}"));
            }
            return Some(format!("guest:{}", session_identifier(record)));
        }
        Some(format!("guest:{cookie_value}"))
    }

    pub fn finalize_login(
        &self,
        cookie_header: Option<&str>,
        username: &str,
        csrf_enabled: bool,
    ) -> Result<LoginFinalize, SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();

        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            sessions.remove(&cookie_value);
        }

        let (cookie_value, mut record) = self.new_record(now);
        record.username = Some(username.to_string());
        record.last_used = now;
        let session_id = session_identifier(&record);
        let csrf_token = record.csrf_token.clone();
        let set_cookie = self.build_set_cookie(&cookie_value, csrf_enabled);
        sessions.insert(cookie_value, record);
        drop(sessions);

        Ok(LoginFinalize {
            session_id,
            set_cookie,
            csrf_token,
        })
    }

    pub fn logout_user(
        &self,
        cookie_header: Option<&str>,
        csrf_enabled: bool,
    ) -> Result<LogoutFinalize, SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();

        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            sessions.remove(&cookie_value);
        }

        let (cookie_value, record) = self.new_record(now);
        let session_id = session_identifier(&record);
        let set_cookie = self.build_set_cookie(&cookie_value, csrf_enabled);
        sessions.insert(cookie_value, record);
        drop(sessions);

        Ok(LogoutFinalize {
            session_id,
            set_cookie,
        })
    }
}

fn random_token(size: usize) -> String {
    let mut bytes = vec![0u8; size];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn extract_session_cookie(header: Option<&str>) -> Option<String> {
    let header = header?;
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(SESSION_COOKIE_NAME) {
            if let Some(rest) = value.strip_prefix('=') {
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

fn session_identifier(record: &HttpSessionRecord) -> String {
    match record.username.as_deref() {
        Some(username) => username.to_string(),
        None => format!("{SESSION_GUEST_PREFIX}{}", record.guest_id),
    }
}

/// Production entry point: delegates to the single process-global store.
/// Store initializes first, then the CSRF flag reads live; the store timeout
/// was resolved once at first use.
pub fn prepare_home_context(cookie_header: Option<&str>) -> Result<HomeBootstrap, SessionError> {
    let store = HttpSessionStore::global();
    let csrf_enabled = config::app_config().csrf;
    store.prepare_home_context(cookie_header, csrf_enabled)
}

/// Production entry point: delegates to the single process-global store.
/// The CSRF flag is read live per call. Disabled/missing/empty tokens return
/// before the global store initializes, preserving the original first-use
/// freeze sequence.
pub fn validate_csrf_token(cookie_header: Option<&str>, token: Option<&str>) -> Result<bool, SessionError> {
    validate_csrf_token_with_csrf(cookie_header, token, config::app_config().csrf)
}

/// Explicit-CSRF variant for scoped identities: same global store and same
/// disabled/missing/empty early returns before init, no ambient read.
pub fn validate_csrf_token_with_csrf(
    cookie_header: Option<&str>,
    token: Option<&str>,
    csrf_enabled: bool,
) -> Result<bool, SessionError> {
    if !csrf_enabled {
        return Ok(true);
    }
    let Some(token) = token else {
        return Ok(false);
    };
    if token.is_empty() {
        return Ok(false);
    }
    HttpSessionStore::global().validate_csrf_token(cookie_header, Some(token), csrf_enabled)
}

/// Production entry point: delegates to the single process-global store.
pub fn session_context(cookie_header: Option<&str>) -> Result<SessionContext, SessionError> {
    HttpSessionStore::global().session_context(cookie_header)
}

/// Stable rate-limit identity without creating a session.
/// Prefers `user:{username}`, then `guest:{session_id}` for known cookies,
/// then `guest:{cookie}` for presented-but-unknown cookies. Callers should
/// fall back to an IP key when this returns `None`.
///
/// Production entry point: delegates to the single process-global store.
/// Missing/malformed headers return before the global store initializes,
/// preserving the original first-use freeze sequence.
pub fn rate_limit_identity(cookie_header: Option<&str>) -> Option<String> {
    extract_session_cookie(cookie_header)?;
    HttpSessionStore::global().rate_limit_identity(cookie_header)
}

/// Production entry point: delegates to the single process-global store.
/// Store initializes first, then the CSRF flag reads live; the store timeout
/// was resolved once at first use.
pub fn finalize_login(
    cookie_header: Option<&str>,
    username: &str,
) -> Result<LoginFinalize, SessionError> {
    let store = HttpSessionStore::global();
    let csrf_enabled = config::app_config().csrf;
    store.finalize_login(cookie_header, username, csrf_enabled)
}

/// Production entry point: delegates to the single process-global store.
/// Store initializes first, then the CSRF flag reads live; the store timeout
/// was resolved once at first use.
pub fn logout_user(cookie_header: Option<&str>) -> Result<LogoutFinalize, SessionError> {
    let store = HttpSessionStore::global();
    let csrf_enabled = config::app_config().csrf;
    store.logout_user(cookie_header, csrf_enabled)
}

/// Crate-visible purge hook for the composed [`crate::session::purge_expired_sessions`].
pub(crate) fn purge_expired_http_sessions() -> usize {
    HttpSessionStore::global().purge_expired()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_record(store: &HttpSessionStore, cookie: &str, username: Option<&str>, age: Duration) -> String {
        let (_, mut record) = store.new_record(Instant::now());
        record.username = username.map(str::to_string);
        record.last_used = Instant::now() - age;
        let csrf = record.csrf_token.clone();
        store.sessions.lock().unwrap().insert(cookie.to_string(), record);
        csrf
    }

    #[test]
    fn expired_record_is_rejected_on_lookup_without_global_sweep() {
        let store = HttpSessionStore::new(60);
        let expired = Duration::from_secs(120);
        let csrf = insert_record(&store, "expired", Some("alice"), expired);
        insert_record(&store, "other-expired", Some("bob"), expired);
        let header = Some("session=expired");

        assert!(!store.validate_csrf_token(header, Some(&csrf), true).unwrap());
        assert!(store.session_context(header).unwrap().username.is_none());
        assert_eq!(store.rate_limit_identity(header).as_deref(), Some("guest:expired"));
        assert!(store.sessions.lock().unwrap().contains_key("other-expired"));

        assert_eq!(store.purge_expired(), 2);
        assert_eq!(store.record_count(), 0);
    }

    #[test]
    fn live_record_still_resolves_and_validates() {
        let store = HttpSessionStore::new(60);
        let csrf = insert_record(&store, "live", Some("alice"), Duration::from_secs(1));
        let header = Some("session=live");

        assert!(store.validate_csrf_token(header, Some(&csrf), true).unwrap());
        assert_eq!(store.session_context(header).unwrap().username.as_deref(), Some("alice"));
        assert_eq!(store.rate_limit_identity(header).as_deref(), Some("user:alice"));
    }

    #[test]
    fn home_bootstrap_replaces_expired_record() {
        let store = HttpSessionStore::new(60);
        insert_record(&store, "expired", Some("alice"), Duration::from_secs(120));

        let bootstrap = store.prepare_home_context(Some("session=expired"), true).unwrap();
        assert!(bootstrap.username.is_none());
        assert!(!bootstrap.set_cookie.starts_with("session=expired;"));
    }

    #[test]
    fn session_context_without_valid_cookie_persists_nothing() {
        let store = HttpSessionStore::new(60);
        let first = store.session_context(None).unwrap();
        let unknown = store.session_context(Some("session=unknown")).unwrap();

        assert!(first.username.is_none() && first.session_id.starts_with(SESSION_GUEST_PREFIX));
        assert!(unknown.username.is_none() && unknown.session_id.starts_with(SESSION_GUEST_PREFIX));
        assert_eq!(store.record_count(), 0);
    }
}
