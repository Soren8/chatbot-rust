//! Durable "remember this computer" device tokens (opt-in, 30 days).
//!
//! A remember token restores the HTTP **session** only — it never grants access
//! to encrypted chat data. Data endpoints keep requiring `X-Enc-Key` validated
//! against the per-user HMAC key verifier (two-secrets model, see
//! docs/design-privacy.md).
//!
//! Token format: `base64url(family_id(16B) || secret(32B))`. The server stores
//! only `sha256(secret)` per family in `data/remember_tokens/{family_hex}.json`,
//! so nothing reusable survives a disk leak. Every successful use rotates the
//! secret; presenting a rotated-out secret is treated as theft and revokes the
//! whole family (including the currently valid token).

use std::{
    env, fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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

impl RememberStore {
    pub fn new() -> Result<Self, RememberError> {
        let base = env::var("HOST_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let dir = base.join(TOKENS_DIR);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(Self { dir })
    }

    /// Issue a fresh token family for `username`, keeping at most
    /// [`MAX_FAMILIES_PER_USER`] families per user (oldest evicted).
    pub fn issue(&self, username: &str) -> Result<String, RememberError> {
        self.purge_expired();
        self.evict_beyond_cap(username)?;

        let family = random_bytes(FAMILY_BYTES);
        let secret = random_bytes(SECRET_BYTES);
        let record = RememberRecord {
            username: username.to_string(),
            secret_hash: to_hex(&Sha256::digest(&secret)),
            created: unix_now(),
            expires: unix_now() + REMEMBER_MAX_AGE_SECS,
        };
        self.write_record(&to_hex(&family), &record)?;
        Ok(pack_client_token(&family, &secret))
    }

    /// Validate a presented token. On success the secret is rotated (same
    /// family) and the replacement token returned. A stale secret revokes the
    /// entire family. Expired or unknown tokens are rejected.
    pub fn resume(&self, token: Option<&str>) -> Result<ResumeOutcome, RememberError> {
        let Some((family, secret)) = parse_token(token) else {
            return Ok(ResumeOutcome::Invalid);
        };
        let family_hex = to_hex(&family);
        let path = self.family_path(&family_hex);
        let Ok(contents) = fs::read_to_string(&path) else {
            return Ok(ResumeOutcome::Invalid);
        };
        let Ok(record) = serde_json::from_str::<RememberRecord>(&contents) else {
            let _ = fs::remove_file(&path);
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
        if !constant_time_eq(presented.as_slice(), &stored) {
            // Replay of a rotated-out secret: assume theft, revoke the family.
            let _ = fs::remove_file(&path);
            return Ok(ResumeOutcome::Invalid);
        }

        let replacement_secret = random_bytes(SECRET_BYTES);
        let replacement = RememberRecord {
            username: record.username.clone(),
            secret_hash: to_hex(&Sha256::digest(&replacement_secret)),
            created: unix_now(),
            expires: unix_now() + REMEMBER_MAX_AGE_SECS,
        };
        self.write_record(&family_hex, &replacement)?;
        Ok(ResumeOutcome::Authenticated {
            username: record.username,
            replacement_token: pack_client_token(&family, &replacement_secret),
        })
    }

    /// Revoke the token family presented in `token` (logout).
    pub fn revoke(&self, token: Option<&str>) {
        if let Some((family, _)) = parse_token(token) {
            let _ = fs::remove_file(self.family_path(&to_hex(&family)));
        }
    }

    pub fn purge_expired(&self) -> usize {
        let now = unix_now();
        let mut removed = 0;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        for entry in entries.flatten() {
            let path = entry.path();
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

    fn write_record(&self, family_hex: &str, record: &RememberRecord) -> Result<(), RememberError> {
        let json = serde_json::to_string_pretty(record)?;
        fs::write(self.family_path(family_hex), json)?;
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

/// Extract the remember token from a raw `Cookie` header.
pub fn extract_token(cookie_header: Option<&str>) -> Option<String> {
    let header = cookie_header?;
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(REMEMBER_COOKIE_NAME) {
            if let Some(rest) = value.strip_prefix('=') {
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value issuing a new remember token (30 days, sliding on use).
pub fn build_set_cookie(token: &str) -> String {
    let secure = secure_flag();
    format!(
        "{REMEMBER_COOKIE_NAME}={token}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={REMEMBER_MAX_AGE_SECS}"
    )
}

/// `Set-Cookie` value clearing the remember cookie (logout).
pub fn build_clear_cookie() -> String {
    let secure = secure_flag();
    format!("{REMEMBER_COOKIE_NAME}=; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age=0")
}

fn secure_flag() -> &'static str {
    if crate::config::app_config().csrf {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
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
    fn replay_revokes_whole_family() {
        with_temp_store(|store, _| {
            let first = store.issue("alice").expect("issue");
            let second = match store.resume(Some(&first)).expect("resume") {
                ResumeOutcome::Authenticated { replacement_token, .. } => replacement_token,
                ResumeOutcome::Invalid => panic!("valid token rejected"),
            };
            // Old secret replayed after rotation: family must be revoked.
            assert!(matches!(
                store.resume(Some(&first)).expect("resume"),
                ResumeOutcome::Invalid
            ));
            // The current, previously valid token dies with the family.
            assert!(matches!(
                store.resume(Some(&second)).expect("resume"),
                ResumeOutcome::Invalid
            ));
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
        let clear = build_clear_cookie();
        assert!(clear.starts_with("remember=;"));
        assert!(clear.contains("Max-Age=0"));
    }
}
