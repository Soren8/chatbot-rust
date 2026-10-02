//! Durable "remember this computer" device tokens (opt-in, 30 days).
//!
//! A remember token restores the HTTP **session** only — it never grants access
//! to encrypted chat data. Data endpoints keep requiring `X-Enc-Key` validated
//! against the per-user HMAC key verifier (two-secrets model, see
//! docs/design-privacy.md). Logout does not revoke the family; ✕ / uncheck /
//! expiry do.
//!
//! Token format: `base64url(family_id(16B) || secret(32B))`. The server stores
//! only `sha256(secret)` per family in `data/remember_tokens/{family_hex}.json`,
//! so nothing reusable survives a disk leak. Every successful use rotates the
//! secret; a mismatched secret fails closed without deleting the family:
//! unauthenticated deletion with only a known family ID would permit DoS.
//! Theft of a current secret is indistinguishable from valid bearer use.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::fernet_crypto::constant_time_eq;

pub const REMEMBER_COOKIE_NAME: &str = "remember";
pub const REMEMBER_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

const FAMILY_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;
const TOKEN_BYTES: usize = FAMILY_BYTES + SECRET_BYTES;
const MAX_FAMILIES_PER_USER: usize = 10;
const TOKENS_DIR: &str = "remember_tokens";

#[derive(Debug, Error)]
pub enum RememberError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct RememberRecord {
    username: String,
    /// hex(sha256(secret)) — the raw secret never touches disk.
    secret_hash: String,
    /// hex(sha256(previous secret)) — one-generation grace so concurrent tabs
    /// presenting the pre-rotation token are rejected without revoking the
    /// family. Older tokens are also rejected without revocation.
    #[serde(default)]
    prev_secret_hash: Option<String>,
    created: u64,
    expires: u64,
}

pub struct RememberStore {
    dir: PathBuf,
}

pub enum ResumeOutcome {
    Authenticated {
        username: String,
        /// Replacement token (secret rotated); must reach the client as a cookie.
        replacement_token: String,
    },
    Invalid,
}

fn store_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

impl RememberStore {
    pub fn new() -> Result<Self, RememberError> {
        let base = env::var("HOST_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        Self::open(&base)
    }

    /// Open (creating) the remember-token store rooted at `root`.
    ///
    /// Explicit input ownership for composed application services: each
    /// service passes its own root instead of sharing `HOST_DATA_DIR`.
    /// Creates the same `remember_tokens` directory as [`RememberStore::new`]
    /// and performs no environment reads. Locking and rotation semantics are
    /// unchanged.
    pub fn open(root: &Path) -> Result<Self, RememberError> {
        let dir = root.join(TOKENS_DIR);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(Self { dir })
    }

    /// Issue a fresh token family for `username`, keeping at most
    /// [`MAX_FAMILIES_PER_USER`] families per user (oldest evicted).
    pub fn issue(&self, username: &str) -> Result<String, RememberError> {
        let _guard = store_lock();
        self.issue_locked(username)
    }

    /// Reuse the presented family when it already belongs to `username`;
    /// otherwise mint a new family. A foreign family is left intact so another
    /// cached account on this browser keeps its per-account cookie.
    pub fn issue_or_refresh(
        &self,
        username: &str,
        presented: Option<&str>,
    ) -> Result<String, RememberError> {
        let _guard = store_lock();
        if let Some((family, secret)) = parse_token(presented) {
            let family_hex = to_hex(&family);
            if let Some(record) = self.read_record(&family_hex) {
                if unix_now() < record.expires
                    && record.username == username
                    && secret_matches(&record, &secret)
                {
                    return self.rotate_family_locked(&family, &record);
                }
            }
        }
        self.issue_locked(username)
    }

    /// Username bound to this family, if the file exists and is unexpired.
    /// Does not rotate; checks the bearer secret before reporting ownership.
    pub fn peek_username(&self, token: Option<&str>) -> Option<String> {
        let _guard = store_lock();
        let (family, secret) = parse_token(token)?;
        let record = self.read_record(&to_hex(&family))?;
        if unix_now() >= record.expires || !secret_matches(&record, &secret) {
            return None;
        }
        Some(record.username)
    }

    /// Ownership check for forget's generic-cookie fallback only. Unlike
    /// `peek_username` (used to select login and key cookies), this accepts
    /// the same previous generation that `revoke_if_username` can revoke.
    pub fn peek_username_for_forget(&self, token: Option<&str>) -> Option<String> {
        let _guard = store_lock();
        let (family, secret) = parse_token(token)?;
        let record = self.read_record(&to_hex(&family))?;
        let presented = Sha256::digest(&secret);
        let previous_matches = record.prev_secret_hash.as_deref()
            .and_then(hex_to_bytes)
            .is_some_and(|previous| constant_time_eq(presented.as_slice(), &previous));
        if unix_now() >= record.expires || !(secret_matches(&record, &secret) || previous_matches) {
            return None;
        }
        Some(record.username)
    }

    /// Revoke the presented family only when it belongs to `username` and the
    /// bearer secret is current or one generation previous.
    pub fn revoke_if_username(&self, token: Option<&str>, username: &str) -> bool {
        let _guard = store_lock();
        let Some((family, secret)) = parse_token(token) else {
            return false;
        };
        let family_hex = to_hex(&family);
        let Some(record) = self.read_record(&family_hex) else {
            return false;
        };
        let presented = Sha256::digest(&secret);
        let previous_matches = record.prev_secret_hash.as_deref()
            .and_then(hex_to_bytes)
            .is_some_and(|previous| constant_time_eq(presented.as_slice(), &previous));
        if unix_now() >= record.expires || record.username != username
            || !(secret_matches(&record, &secret) || previous_matches) {
            return false;
        }
        fs::remove_file(self.family_path(&family_hex)).is_ok()
    }

    /// Validate a presented token. On success the secret is rotated (same
    /// family) and the replacement token returned. Mismatched, expired or
    /// unknown tokens are rejected without secret-mismatch revocation.
    pub fn resume(&self, token: Option<&str>) -> Result<ResumeOutcome, RememberError> {
        let _guard = store_lock();
        let Some((family, secret)) = parse_token(token) else {
            return Ok(ResumeOutcome::Invalid);
        };
        let family_hex = to_hex(&family);
        let path = self.family_path(&family_hex);
        let Some(record) = self.read_record(&family_hex) else {
            return Ok(ResumeOutcome::Invalid);
        };
        if unix_now() >= record.expires {
            let _ = fs::remove_file(&path);
            return Ok(ResumeOutcome::Invalid);
        }

        let stored = match hex_to_bytes(&record.secret_hash) {
            Some(bytes) => bytes,
            None => {
                let _ = fs::remove_file(&path);
                return Ok(ResumeOutcome::Invalid);
            }
        };
        let presented = Sha256::digest(&secret);
        let matches_current = constant_time_eq(presented.as_slice(), &stored);
        if !matches_current {
            return Ok(ResumeOutcome::Invalid);
        }

        let replacement_token = self.rotate_family_locked(&family, &record)?;
        Ok(ResumeOutcome::Authenticated {
            username: record.username,
            replacement_token,
        })
    }

    /// Revoke the token family presented in `token` when the secret is current.
    pub fn revoke(&self, token: Option<&str>) {
        let _guard = store_lock();
        if let Some((family, secret)) = parse_token(token) {
            let family_hex = to_hex(&family);
            if self.read_record(&family_hex).is_some_and(|record| {
                unix_now() < record.expires && secret_matches(&record, &secret)
            }) {
                let _ = fs::remove_file(self.family_path(&family_hex));
            }
        }
    }

    pub fn purge_expired(&self) -> usize {
        let _guard = store_lock();
        self.purge_expired_locked()
    }

    fn issue_locked(&self, username: &str) -> Result<String, RememberError> {
        self.purge_expired_locked();
        self.evict_beyond_cap(username)?;

        let family = random_bytes(FAMILY_BYTES);
        let secret = random_bytes(SECRET_BYTES);
        let record = RememberRecord {
            username: username.to_string(),
            secret_hash: to_hex(&Sha256::digest(&secret)),
            prev_secret_hash: None,
            created: unix_now(),
            expires: unix_now() + REMEMBER_MAX_AGE_SECS,
        };
        self.write_record(&to_hex(&family), &record)?;
        Ok(pack_client_token(&family, &secret))
    }

    fn rotate_family_locked(
        &self,
        family: &[u8],
        record: &RememberRecord,
    ) -> Result<String, RememberError> {
        let replacement_secret = random_bytes(SECRET_BYTES);
        let replacement = RememberRecord {
            username: record.username.clone(),
            prev_secret_hash: Some(record.secret_hash.clone()),
            secret_hash: to_hex(&Sha256::digest(&replacement_secret)),
            created: unix_now(),
            expires: unix_now() + REMEMBER_MAX_AGE_SECS,
        };
        self.write_record(&to_hex(family), &replacement)?;
        Ok(pack_client_token(family, &replacement_secret))
    }

    fn purge_expired_locked(&self) -> usize {
        let now = unix_now();
        let mut removed = 0;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<RememberRecord>(&contents) else {
                continue;
            };
            if now >= record.expires && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    fn evict_beyond_cap(&self, username: &str) -> Result<(), RememberError> {
        let mut families: Vec<(u64, String)> = Vec::new();
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<RememberRecord>(&contents) else {
                continue;
            };
            if record.username == username {
                families.push((record.created, name.to_string()));
            }
        }
        if families.len() < MAX_FAMILIES_PER_USER {
            return Ok(());
        }
        families.sort_by_key(|(created, _)| *created);
        let excess = families.len() + 1 - MAX_FAMILIES_PER_USER;
        for (_, family_hex) in families.into_iter().take(excess) {
            let _ = fs::remove_file(self.family_path(&family_hex));
        }
        Ok(())
    }

    fn family_path(&self, family_hex: &str) -> PathBuf {
        self.dir.join(format!("{family_hex}.json"))
    }

    fn read_record(&self, family_hex: &str) -> Option<RememberRecord> {
        let path = self.family_path(family_hex);
        let contents = fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<RememberRecord>(&contents) {
            Ok(record) => Some(record),
            Err(_) => {
                let _ = fs::remove_file(&path);
                None
            }
        }
    }

    fn write_record(&self, family_hex: &str, record: &RememberRecord) -> Result<(), RememberError> {
        let json = serde_json::to_string_pretty(record)?;
        let path = self.family_path(family_hex);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn pack_client_token(family: &[u8], secret: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(TOKEN_BYTES);
    bytes.extend_from_slice(family);
    bytes.extend_from_slice(secret);
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn parse_token(token: Option<&str>) -> Option<(Vec<u8>, Vec<u8>)> {
    let raw = token?.trim();
    if raw.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    if bytes.len() != TOKEN_BYTES {
        return None;
    }
    Some((bytes[..FAMILY_BYTES].to_vec(), bytes[FAMILY_BYTES..].to_vec()))
}

fn secret_matches(record: &RememberRecord, secret: &[u8]) -> bool {
    let Some(stored) = hex_to_bytes(&record.secret_hash) else {
        return false;
    };
    constant_time_eq(Sha256::digest(secret).as_slice(), &stored)
}

/// Last-used remember cookie name (`remember=`). Per-account cookies are
/// `remember-{username}=` (see [`account_cookie_name`]).
pub fn extract_token(cookie_header: Option<&str>) -> Option<String> {
    extract_named_cookie(cookie_header, REMEMBER_COOKIE_NAME)
}

pub fn account_cookie_name(username: &str) -> String {
    format!("{REMEMBER_COOKIE_NAME}-{username}")
}

/// Remember token for `username`: `remember-{username}` first, else last-used.
pub fn extract_account_token(cookie_header: Option<&str>, username: &str) -> Option<String> {
    extract_named_cookie(cookie_header, &account_cookie_name(username))
}

pub fn extract_token_for_user(cookie_header: Option<&str>, username: &str) -> Option<String> {
    extract_account_token(cookie_header, username).or_else(|| extract_token(cookie_header))
}

fn extract_named_cookie(cookie_header: Option<&str>, name: &str) -> Option<String> {
    let header = cookie_header?;
    let prefix = format!("{name}=");
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// `Set-Cookie` value issuing a new remember token (30 days, sliding on use).
pub fn build_set_cookie(token: &str) -> String {
    build_set_cookie_with_csrf(token, crate::config::app_config().csrf)
}

/// Explicit-CSRF variant for owned routers: same shape as
/// [`build_set_cookie`] with no ambient config read. Global routers keep
/// using [`build_set_cookie`] so the live lookup timing is untouched.
pub fn build_set_cookie_with_csrf(token: &str, csrf: bool) -> String {
    let secure = secure_flag_with(csrf);
    format!(
        "{REMEMBER_COOKIE_NAME}={token}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={REMEMBER_MAX_AGE_SECS}"
    )
}

/// `Set-Cookie` value clearing the last-used remember cookie.
pub fn build_clear_cookie() -> String {
    build_clear_cookie_with_csrf(crate::config::app_config().csrf)
}

/// Explicit-CSRF variant with no ambient read; see [`build_set_cookie_with_csrf`].
pub fn build_clear_cookie_with_csrf(csrf: bool) -> String {
    let secure = secure_flag_with(csrf);
    format!("{REMEMBER_COOKIE_NAME}=; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age=0")
}

pub fn build_account_set_cookie(username: &str, token: &str) -> String {
    build_account_set_cookie_with_csrf(username, token, crate::config::app_config().csrf)
}

/// Explicit-CSRF variant with no ambient read; see [`build_set_cookie_with_csrf`].
pub fn build_account_set_cookie_with_csrf(username: &str, token: &str, csrf: bool) -> String {
    let name = account_cookie_name(username);
    let secure = secure_flag_with(csrf);
    format!(
        "{name}={token}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={REMEMBER_MAX_AGE_SECS}"
    )
}

pub fn build_account_clear_cookie(username: &str) -> String {
    build_account_clear_cookie_with_csrf(username, crate::config::app_config().csrf)
}

/// Explicit-CSRF variant with no ambient read; see [`build_set_cookie_with_csrf`].
pub fn build_account_clear_cookie_with_csrf(username: &str, csrf: bool) -> String {
    let name = account_cookie_name(username);
    let secure = secure_flag_with(csrf);
    format!("{name}=; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age=0")
}

fn secure_flag_with(csrf: bool) -> &'static str {
    if csrf {
        " Secure;"
    } else {
        ""
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        bytes.push(u8::from_str_radix(&format!("{hi}{lo}"), 16).ok()?);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_temp_store(f: impl FnOnce(&RememberStore, &Path)) {
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");
        let previous = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", tmp.path());
        let store = RememberStore::new().expect("store");
        f(&store, tmp.path());
        match previous {
            Some(value) => env::set_var("HOST_DATA_DIR", value),
            None => env::remove_var("HOST_DATA_DIR"),
        }
    }

    use std::path::Path;

    #[test]
    fn issue_and_resume_round_trip() {
        with_temp_store(|store, _| {
            let token = store.issue("alice").expect("issue");
            assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), TOKEN_BYTES);
            match store.resume(Some(&token)).expect("resume") {
                ResumeOutcome::Authenticated { username, replacement_token } => {
                    assert_eq!(username, "alice");
                    assert_ne!(replacement_token, token, "secret must rotate");
                }
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            }
        });
    }

    #[test]
    fn resume_survives_store_recreation() {
        with_temp_store(|store, _| {
            let token = store.issue("alice").expect("issue");
            // A fresh store (as after a server restart) reads the same files.
            let restarted = RememberStore::new().expect("store");
            assert!(matches!(
                restarted.resume(Some(&token)).expect("resume"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    #[test]
    fn previous_generation_rejected_without_revocation() {
        with_temp_store(|store, _| {
            let first = store.issue("alice").expect("issue");
            let second = match store.resume(Some(&first)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            // Presenting the previous generation (concurrent tab after
            // rotation) is rejected but must NOT kill the family.
            assert!(matches!(
                store.resume(Some(&first)).expect("resume"),
                ResumeOutcome::Invalid
            ));
            assert!(matches!(
                store.resume(Some(&second)).expect("resume"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    #[test]
    fn two_generations_old_replay_rejected_without_revocation() {
        with_temp_store(|store, _| {
            let first = store.issue("alice").expect("issue");
            let second = match store.resume(Some(&first)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            let third = match store.resume(Some(&second)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            // Two generations stale: rejected without invalidating the current token.
            assert!(matches!(
                store.resume(Some(&first)).expect("resume"),
                ResumeOutcome::Invalid
            ));
            assert!(matches!(
                store.resume(Some(&third)).expect("resume"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    fn expire_token(store: &RememberStore, token: &str) {
        let (family, _) = parse_token(Some(token)).expect("token");
        let path = store.family_path(&to_hex(&family));
        let contents = fs::read_to_string(&path).expect("read record");
        let mut record: RememberRecord = serde_json::from_str(&contents).expect("parse record");
        record.expires = unix_now().saturating_sub(1);
        fs::write(path, serde_json::to_string(&record).unwrap()).unwrap();
    }

    #[test]
    fn peek_username_rejects_expired_token() {
        with_temp_store(|store, _| {
            let token = store.issue("alice").expect("issue");
            expire_token(store, &token);
            assert_eq!(store.peek_username(Some(&token)), None);
        });
    }

    #[test]
    fn peek_username_for_forget_accepts_current_and_previous_generation() {
        with_temp_store(|store, _| {
            let first = store.issue("alice").expect("issue");
            assert_eq!(store.peek_username_for_forget(Some(&first)), Some("alice".into()));
            let second = match store.resume(Some(&first)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            assert_eq!(store.peek_username_for_forget(Some(&second)), Some("alice".into()));
            assert_eq!(store.peek_username_for_forget(Some(&first)), Some("alice".into()));
            let third = match store.resume(Some(&second)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            assert_eq!(store.peek_username_for_forget(Some(&first)), None);
            assert_eq!(store.peek_username_for_forget(Some("forged-token")), None);
            expire_token(store, &third);
            assert_eq!(store.peek_username_for_forget(Some(&third)), None);
        });
    }

    #[test]
    fn purge_expired_removes_only_expired_records_and_skips_malformed_files() {
        with_temp_store(|store, dir| {
            let expired = store.issue("expired").expect("issue");
            let live = store.issue("live").expect("issue");
            expire_token(store, &expired);
            let malformed = dir.join(TOKENS_DIR).join("malformed.json");
            fs::write(&malformed, b"not json").unwrap();

            assert_eq!(store.purge_expired(), 1);
            assert_eq!(store.peek_username(Some(&live)), Some("live".into()));
            assert!(!store.family_path(&to_hex(&parse_token(Some(&expired)).unwrap().0)).exists());
            assert!(malformed.exists());
        });
    }

    #[test]
    fn expired_token_rejected_and_removed() {
        with_temp_store(|store, dir| {
            let token = store.issue("alice").expect("issue");
            // Force expiry by rewriting the record's expires field.
            let tokens_dir = dir.join(TOKENS_DIR);
            for entry in fs::read_dir(&tokens_dir).expect("read dir").flatten() {
                let path = entry.path();
                let contents = fs::read_to_string(&path).expect("read record");
                let mut record: RememberRecord =
                    serde_json::from_str(&contents).expect("parse record");
                record.expires = unix_now().saturating_sub(1);
                fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
            }
            assert!(matches!(
                store.resume(Some(&token)).expect("resume"),
                ResumeOutcome::Invalid
            ));
            assert_eq!(store.purge_expired(), 0, "resume already removed it");
            assert_eq!(fs::read_dir(&tokens_dir).unwrap().count(), 0);
        });
    }

    #[test]
    fn revoke_removes_family() {
        with_temp_store(|store, _| {
            let token = store.issue("alice").expect("issue");
            store.revoke(Some(&token));
            assert!(matches!(
                store.resume(Some(&token)).expect("resume"),
                ResumeOutcome::Invalid
            ));
        });
    }

    #[test]
    fn issue_or_refresh_reuses_family_for_same_user() {
        with_temp_store(|store, dir| {
            let first = store.issue("alice").expect("issue");
            let second = store
                .issue_or_refresh("alice", Some(&first))
                .expect("refresh");
            assert_ne!(second, first);
            let tokens_dir = dir.join(TOKENS_DIR);
            let count = fs::read_dir(&tokens_dir)
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .ok()
                        .and_then(|e| e.path().extension().map(|ext| ext == "json"))
                        .unwrap_or(false)
                })
                .count();
            assert_eq!(count, 1, "refresh must not mint a second family");
            assert!(matches!(
                store.resume(Some(&second)).expect("resume"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    #[test]
    fn issue_or_refresh_preserves_foreign_family() {
        with_temp_store(|store, _| {
            let alice = store.issue("alice").expect("issue");
            let bob = store
                .issue_or_refresh("bob", Some(&alice))
                .expect("switch user");
            assert!(matches!(
                store.resume(Some(&alice)).expect("resume alice"),
                ResumeOutcome::Authenticated { .. }
            ));
            assert!(matches!(
                store.resume(Some(&bob)).expect("resume bob"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    #[test]
    fn revoke_if_username_ignores_other_accounts() {
        with_temp_store(|store, _| {
            let alice = store.issue("alice").expect("issue");
            assert!(!store.revoke_if_username(Some(&alice), "bob"));
            assert!(matches!(
                store.resume(Some(&alice)).expect("resume"),
                ResumeOutcome::Authenticated { .. }
            ));
        });
    }

    #[test]
    fn concurrent_resume_of_current_secret_does_not_revoke_family() {
        with_temp_store(|store, _| {
            let token = store.issue("alice").expect("issue");
            let (left, right) = std::thread::scope(|scope| {
                let left = scope.spawn(|| store.resume(Some(&token)));
                let right = scope.spawn(|| store.resume(Some(&token)));
                (
                    left.join().expect("left").expect("left resume"),
                    right.join().expect("right").expect("right resume"),
                )
            });
            let replacements: Vec<String> = [left, right]
                .into_iter()
                .filter_map(|outcome| match outcome {
                    ResumeOutcome::Authenticated {
                        replacement_token, ..
                    } => Some(replacement_token),
                    ResumeOutcome::Invalid => None,
                })
                .collect();
            assert!(
                !replacements.is_empty(),
                "at least one concurrent resume must succeed"
            );
            let latest = replacements.last().expect("replacement");
            assert!(
                matches!(
                    store.resume(Some(latest)).expect("resume latest"),
                    ResumeOutcome::Authenticated { .. }
                ),
                "family must still accept the rotated token"
            );
        });
    }

    #[test]
    fn per_user_family_cap() {
        with_temp_store(|store, dir| {
            for _ in 0..MAX_FAMILIES_PER_USER {
                store.issue("alice").expect("issue");
            }
            store.issue("alice").expect("issue beyond cap");
            let tokens_dir = dir.join(TOKENS_DIR);
            let count = fs::read_dir(&tokens_dir)
                .unwrap()
                .filter_map(Result::ok)
                .count();
            assert!(
                count <= MAX_FAMILIES_PER_USER,
                "cap should evict oldest families, found {count}"
            );
        });
    }

    #[test]
    fn malformed_tokens_rejected() {
        with_temp_store(|store, _| {
            for bad in [None, Some(""), Some("garbage"), Some("!!!!")] {
                assert!(matches!(
                    store.resume(bad).expect("resume"),
                    ResumeOutcome::Invalid
                ));
            }
        });
    }

    #[test]
    fn cookie_parsing_and_flags() {
        let cookie = build_set_cookie("tok");
        assert!(cookie.starts_with("remember=tok;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains(&format!("Max-Age={REMEMBER_MAX_AGE_SECS}")));
        assert_eq!(
            extract_token(Some("session=abc; remember=tok; other=1")),
            Some("tok".to_string())
        );
        assert_eq!(extract_token(Some("session=abc")), None);
        assert_eq!(extract_token(None), None);
        assert_eq!(
            extract_token(Some("remember-alice=accttok; remember=tok")),
            Some("tok".to_string()),
            "last-used parser must ignore per-account cookies"
        );
        assert_eq!(
            extract_account_token(Some("remember-alice=accttok; remember=tok"), "alice"),
            Some("accttok".to_string())
        );
        assert_eq!(
            extract_token_for_user(Some("remember-bob=b; remember=tok"), "alice"),
            Some("tok".to_string())
        );
        let account = build_account_set_cookie("alice", "tok");
        assert!(account.starts_with("remember-alice=tok;"));
        assert!(account.contains("HttpOnly"));
        let clear_account = build_account_clear_cookie("alice");
        assert!(clear_account.starts_with("remember-alice=;"));
        assert!(clear_account.contains("Max-Age=0"));
        let clear = build_clear_cookie();
        assert!(clear.starts_with("remember=;"));
        assert!(clear.contains("Max-Age=0"));
    }
}
