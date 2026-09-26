//! Per-account encrypted OpenCode connection settings. Routing and egress policy live outside this store.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, AeadCore, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::account_service::AccountService;
use crate::enc_key::EncryptionKey;
use crate::names::normalise_username;

const META: TableDefinition<'_, &str, u64> = TableDefinition::new("connection_schema");
const RECORDS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("connections");
const SCHEMA: u64 = 1;
const MAX_CACHE: usize = 256;
pub const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("invalid connection input")]
    InvalidInput,
    #[error("encryption key missing or invalid")]
    InvalidKey,
    #[error("connection not found")]
    NotFound,
    #[error("connection version conflict")]
    Conflict { current_revision: u64 },
    #[error("connection limit reached")]
    LimitReached,
    #[error("connection data invalid or authentication failed")]
    Corrupt,
    #[error("unsupported connection schema")]
    UnsupportedSchema,
    #[error("connection storage unavailable")]
    Storage,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub username: String,
    pub has_password: bool,
}

// Do not derive Debug for plaintext or credential-bearing inputs.
#[derive(Clone)]
pub struct ConnectionInput {
    pub name: String,
    pub base_url: String,
    pub username: String,
    pub password: String,
}

impl Drop for ConnectionInput {
    fn drop(&mut self) {
        self.name.zeroize();
        self.base_url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Default)]
pub struct ConnectionPatch {
    pub name: Option<String>,
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct ConnectionCredentials {
    pub base_url: String,
    pub username: String,
    pub password: String,
}

impl Drop for ConnectionCredentials {
    fn drop(&mut self) {
        self.base_url.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct SecretRecord {
    name: String,
    base_url: String,
    username: String,
    password: String,
}

impl Drop for SecretRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LastCheck {
    pub checked_at: u64,
    pub status: String,
    pub version: Option<String>,
}

struct Owned {
    db: Database,
    accounts: AccountService,
    checks: Mutex<HashMap<(String, Uuid, u64), LastCheck>>,
}

#[derive(Clone)]
pub struct ConnectionService(Arc<Owned>);

fn storage<E>(_: E) -> ConnectionError { ConnectionError::Storage }

fn owner(username: &str) -> Result<String, ConnectionError> {
    normalise_username(username).map_err(|_| ConnectionError::InvalidInput)
}

fn aad(owner: &str, id: Uuid, revision: u64) -> Vec<u8> {
    let mut out = b"chatbot-connection-aad-v1\0".to_vec();
    out.extend_from_slice(&(owner.len() as u32).to_le_bytes());
    out.extend_from_slice(owner.as_bytes());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&SCHEMA.to_le_bytes());
    out.extend_from_slice(&revision.to_le_bytes());
    out
}

fn cipher(key: &EncryptionKey) -> Aes256Gcm {
    let hk = Hkdf::<Sha256>::new(None, key.as_bytes());
    let mut derived = [0u8; 32];
    hk.expand(b"chatbot-connection-payload-v1", &mut derived).expect("valid key size");
    let cipher = Aes256Gcm::new_from_slice(&derived).expect("valid AES key size");
    derived.zeroize();
    cipher
}

fn seal(owner: &str, id: Uuid, revision: u64, secret: &SecretRecord, key: &EncryptionKey) -> Result<Vec<u8>, ConnectionError> {
    let mut plain = serde_json::to_vec(secret).map_err(storage)?;
    let nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize> = Nonce::generate();
    let result = cipher(key).encrypt(&nonce, Payload { msg: &plain, aad: &aad(owner, id, revision) });
    plain.zeroize();
    let encrypted = result.map_err(|_| ConnectionError::Corrupt)?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn unseal(owner: &str, id: Uuid, revision: u64, blob: &[u8], key: &EncryptionKey) -> Result<SecretRecord, ConnectionError> {
    if blob.len() < 28 { return Err(ConnectionError::Corrupt); }
    let nonce: [u8; 12] = blob[..12].try_into().map_err(|_| ConnectionError::Corrupt)?;
    let mut plain = cipher(key).decrypt(&nonce.into(), Payload { msg: &blob[12..], aad: &aad(owner, id, revision) }).map_err(|_| ConnectionError::Corrupt)?;
    let secret = serde_json::from_slice(&plain).map_err(|_| ConnectionError::Corrupt);
    plain.zeroize();
    secret
}

// Plain value is owner length + owner + revision + ciphertext; no endpoint metadata.
fn encode(owner: &str, revision: u64, blob: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(2 + owner.len() + 8 + blob.len());
    value.extend_from_slice(&(owner.len() as u16).to_le_bytes());
    value.extend_from_slice(owner.as_bytes());
    value.extend_from_slice(&revision.to_le_bytes());
    value.extend_from_slice(blob);
    value
}

fn decode(value: &[u8]) -> Result<(&str, u64, &[u8]), ConnectionError> {
    if value.len() < 2 { return Err(ConnectionError::Corrupt); }
    let len = u16::from_le_bytes([value[0], value[1]]) as usize;
    if value.len() < 2 + len + 8 + 28 { return Err(ConnectionError::Corrupt); }
    let owner = std::str::from_utf8(&value[2..2 + len]).map_err(|_| ConnectionError::Corrupt)?;
    let revision = u64::from_le_bytes(value[2 + len..2 + len + 8].try_into().map_err(|_| ConnectionError::Corrupt)?);
    Ok((owner, revision, &value[2 + len + 8..]))
}

fn valid_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max_chars && !value.chars().any(char::is_control)
}

fn validate(record: &SecretRecord) -> Result<(), ConnectionError> {
    if !valid_text(&record.name, 128) || !valid_text(&record.base_url, 2048)
        || !valid_text(&record.username, 256) || record.username.contains(':')
        || record.password.is_empty() || record.password.len() > 4096
        || record.password.chars().any(char::is_control) {
        return Err(ConnectionError::InvalidInput);
    }
    Ok(())
}

fn projection(id: Uuid, revision: u64, secret: &SecretRecord) -> ConnectionRecord {
    ConnectionRecord { id, revision, name: secret.name.clone(), kind: "opencode".into(), base_url: secret.base_url.clone(), username: secret.username.clone(), has_password: !secret.password.is_empty() }
}

impl ConnectionService {
    /// `root` is HOST_DATA_DIR; the database is opened only once for all clones.
    pub fn open(root: impl AsRef<Path>, accounts: AccountService) -> Result<Self, ConnectionError> {
        let dir = root.as_ref().join("connections");
        std::fs::create_dir_all(&dir).map_err(storage)?;
        let db = Database::create(dir.join("redb")).map_err(storage)?;
        let tx = db.begin_write().map_err(storage)?;
        {
            let mut meta = tx.open_table(META).map_err(storage)?;
            let current = meta.get("schema").map_err(storage)?.map(|v| v.value()).unwrap_or(0);
            if current > SCHEMA { return Err(ConnectionError::UnsupportedSchema); }
            if current == 0 { meta.insert("schema", SCHEMA).map_err(storage)?; }
            tx.open_table(RECORDS).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(Self(Arc::new(Owned { db, accounts, checks: Mutex::new(HashMap::new()) })))
    }

    fn verify(&self, user: &str, key: &EncryptionKey) -> Result<String, ConnectionError> {
        let owner = owner(user)?;
        let users = self.0.accounts.users().map_err(storage)?;
        if !users.has_key_verifier(&owner).map_err(storage)? || !users.verify_encryption_key(&owner, key.as_bytes()).map_err(storage)? {
            return Err(ConnectionError::InvalidKey);
        }
        Ok(owner)
    }

    pub fn create(&self, user: &str, key: &EncryptionKey, input: ConnectionInput) -> Result<ConnectionRecord, ConnectionError> {
        let owner = self.verify(user, key)?;
        let mut input = input;
        let secret = SecretRecord { name: std::mem::take(&mut input.name), base_url: std::mem::take(&mut input.base_url), username: std::mem::take(&mut input.username), password: std::mem::take(&mut input.password) };
        validate(&secret)?;
        let id = Uuid::new_v4();
        let revision = 1;
        let blob = seal(&owner, id, revision, &secret, key)?;
        let tx = self.0.db.begin_write().map_err(storage)?;
        {
            let mut table = tx.open_table(RECORDS).map_err(storage)?;
            let mut count = 0;
            for item in table.iter().map_err(storage)? {
                let (_, value) = item.map_err(storage)?;
                if decode(value.value())?.0 == owner { count += 1; }
            }
            if count >= 16 { return Err(ConnectionError::LimitReached); }
            table.insert(id.as_bytes().as_slice(), encode(&owner, revision, &blob).as_slice()).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(projection(id, revision, &secret))
    }

    pub fn list(&self, user: &str, key: &EncryptionKey) -> Result<Vec<ConnectionRecord>, ConnectionError> {
        let owner = self.verify(user, key)?;
        let tx = self.0.db.begin_read().map_err(storage)?;
        let table = tx.open_table(RECORDS).map_err(storage)?;
        let mut results = Vec::new();
        for item in table.iter().map_err(storage)? {
            let (id_bytes, value) = item.map_err(storage)?;
            let (record_owner, revision, blob) = decode(value.value())?;
            if record_owner != owner { continue; }
            let id = Uuid::from_slice(id_bytes.value()).map_err(|_| ConnectionError::Corrupt)?;
            results.push(projection(id, revision, &unseal(&owner, id, revision, blob, key)?));
        }
        Ok(results)
    }

    pub fn credentials(&self, user: &str, key: &EncryptionKey, id: Uuid) -> Result<(u64, ConnectionCredentials), ConnectionError> {
        let owner = self.verify(user, key)?;
        let tx = self.0.db.begin_read().map_err(storage)?;
        let table = tx.open_table(RECORDS).map_err(storage)?;
        let value = table.get(id.as_bytes().as_slice()).map_err(storage)?.ok_or(ConnectionError::NotFound)?;
        let (record_owner, revision, blob) = decode(value.value())?;
        if record_owner != owner { return Err(ConnectionError::NotFound); }
        let secret = unseal(&owner, id, revision, blob, key)?;
        Ok((revision, ConnectionCredentials { base_url: secret.base_url.clone(), username: secret.username.clone(), password: secret.password.clone() }))
    }

    pub fn update(&self, user: &str, key: &EncryptionKey, id: Uuid, expected_revision: u64, patch: ConnectionPatch) -> Result<ConnectionRecord, ConnectionError> {
        let owner = self.verify(user, key)?;
        let tx = self.0.db.begin_write().map_err(storage)?;
        let (result, invalidate) = {
            let mut table = tx.open_table(RECORDS).map_err(storage)?;
            let old = table.get(id.as_bytes().as_slice()).map_err(storage)?.ok_or(ConnectionError::NotFound)?;
            let (record_owner, revision, blob) = decode(old.value())?;
            if record_owner != owner { return Err(ConnectionError::NotFound); }
            if revision != expected_revision { return Err(ConnectionError::Conflict { current_revision: revision }); }
            let mut secret = unseal(&owner, id, revision, blob, key)?;
            drop(old);
            if let Some(name) = patch.name { secret.name = name; }
            let mut invalidate = false;
            if let Some(url) = patch.base_url { invalidate |= url != secret.base_url; secret.base_url = url; }
            if let Some(username) = patch.username { invalidate |= username != secret.username; secret.username = username; }
            if let Some(password) = patch.password { invalidate |= password != secret.password; secret.password = password; }
            validate(&secret)?;
            let next = revision.checked_add(1).ok_or(ConnectionError::Corrupt)?;
            let blob = seal(&owner, id, next, &secret, key)?;
            table.insert(id.as_bytes().as_slice(), encode(&owner, next, &blob).as_slice()).map_err(storage)?;
            (projection(id, next, &secret), invalidate)
        };
        tx.commit().map_err(storage)?;
        if invalidate { self.clear_check(&owner, id); }
        Ok(result)
    }

    pub fn delete(&self, user: &str, key: &EncryptionKey, id: Uuid, expected_revision: u64) -> Result<(), ConnectionError> {
        let owner = self.verify(user, key)?;
        let tx = self.0.db.begin_write().map_err(storage)?;
        {
            let mut table = tx.open_table(RECORDS).map_err(storage)?;
            let old = table.get(id.as_bytes().as_slice()).map_err(storage)?.ok_or(ConnectionError::NotFound)?;
            let (record_owner, revision, blob) = decode(old.value())?;
            if record_owner != owner { return Err(ConnectionError::NotFound); }
            if revision != expected_revision { return Err(ConnectionError::Conflict { current_revision: revision }); }
            unseal(&owner, id, revision, blob, key)?;
            drop(old);
            table.remove(id.as_bytes().as_slice()).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        self.clear_check(&owner, id);
        Ok(())
    }

    fn clear_check(&self, owner: &str, id: Uuid) {
        self.0.checks.lock().unwrap_or_else(|e| e.into_inner()).retain(|(u, i, _), _| u != owner || *i != id);
    }

    /// A caller must perform policy validation before checking; this observation grants no authorization.
    pub fn record_check(&self, user: &str, key: &EncryptionKey, id: Uuid, expected_revision: u64, status: String, version: Option<String>) -> Result<LastCheck, ConnectionError> {
        let owner = self.verify(user, key)?;
        let (revision, _) = self.credentials(&owner, key, id)?;
        if revision != expected_revision { return Err(ConnectionError::Conflict { current_revision: revision }); }
        if status.len() > 64 || version.as_ref().is_some_and(|v| v.len() > 128) {
            return Err(ConnectionError::InvalidInput);
        }
        let observation = LastCheck { checked_at: SystemTime::now().duration_since(UNIX_EPOCH).map_err(storage)?.as_secs(), status, version };
        let mut cache = self.0.checks.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_CACHE { cache.clear(); }
        cache.insert((owner, id, revision), observation.clone());
        Ok(observation)
    }

    pub fn last_check(&self, user: &str, key: &EncryptionKey, id: Uuid) -> Result<Option<LastCheck>, ConnectionError> {
        let owner = self.verify(user, key)?;
        let (revision, _) = self.credentials(&owner, key, id)?;
        Ok(self.0.checks.lock().unwrap_or_else(|e| e.into_inner()).get(&(owner, id, revision)).cloned())
    }
}
