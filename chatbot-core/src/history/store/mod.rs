//! Sealed durable store. Not public outside `history`.

mod keys;
mod tables;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable};
use thiserror::Error;
use tracing::debug;

use super::crypto::{self, CryptoError};
use super::types::{
    BlobFormat, SetId, SetPayloadV1, SetSnapshot, SetSummary, SetVersion,
};
use crate::enc_key::EncryptionKey;
use keys::{set_id_key, user_set_key, user_sets_prefix};
use tables::{
    SetMetaValue, META, SCHEMA_KEY, SCHEMA_VERSION, SETS_BLOB, SETS_META, USER_SETS,
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("set not found")]
    NotFound,
    #[error("version conflict: current={current}")]
    Conflict { current: SetVersion },
    #[error("forbidden")]
    Forbidden,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("invalid input")]
    InvalidInput,
    #[error("database error: {0}")]
    Database(String),
    #[error("crypto error")]
    Crypto,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CryptoError> for StoreError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Decrypt | CryptoError::Framing | CryptoError::Fernet(_) => {
                StoreError::DecryptFailed
            }
            _ => StoreError::Crypto,
        }
    }
}

impl From<redb::Error> for StoreError {
    fn from(err: redb::Error) -> Self {
        StoreError::Database(err.to_string())
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(err: redb::DatabaseError) -> Self {
        StoreError::Database(err.to_string())
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(err: redb::TransactionError) -> Self {
        StoreError::Database(err.to_string())
    }
}

impl From<redb::TableError> for StoreError {
    fn from(err: redb::TableError) -> Self {
        StoreError::Database(err.to_string())
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(err: redb::StorageError) -> Self {
        StoreError::Database(err.to_string())
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(err: redb::CommitError) -> Self {
        StoreError::Database(err.to_string())
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct RedbHistoryStore {
    db: Arc<Database>,
    path: PathBuf,
}

impl RedbHistoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(&path).map_err(StoreError::from)?;
        let store = Self {
            db: Arc::new(db),
            path,
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            if meta.get(SCHEMA_KEY)?.is_none() {
                meta.insert(SCHEMA_KEY, [SCHEMA_VERSION].as_slice())?;
            }
            let _ = txn.open_table(SETS_META)?;
            let _ = txn.open_table(SETS_BLOB)?;
            let _ = txn.open_table(USER_SETS)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn load_snapshot(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        let txn = self.db.begin_read()?;
        let meta_table = txn.open_table(SETS_META)?;
        let blob_table = txn.open_table(SETS_BLOB)?;
        let id_key = set_id_key(set_id);

        let meta_bytes = meta_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let meta = SetMetaValue::decode(meta_bytes.value()).ok_or(StoreError::Database(
            "corrupt set meta".into(),
        ))?;
        if meta.user_id != user_id {
            return Err(StoreError::Forbidden);
        }
        let blob = blob_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let payload = crypto::open_blob(
            user_id,
            set_id,
            meta.version,
            meta.blob_format,
            blob.value(),
            key,
        )?;
        Ok(payload.into_snapshot(set_id, meta.version, meta.is_default))
    }

    pub fn list_set_ids(&self, user_id: &str) -> Result<Vec<(SetId, u64)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(USER_SETS)?;
        let prefix = user_sets_prefix(user_id);
        let mut out = Vec::new();
        // Range from prefix to prefix with high suffix — redb range is inclusive start.
        // We scan all and filter by prefix.
        let iter = table.iter()?;
        for entry in iter {
            let (k, v) = entry?;
            let key = k.value();
            if key.starts_with(&prefix) && key.len() == prefix.len() + 16 {
                if let Some((_, set_id)) = keys::parse_user_set_key(key) {
                    out.push((set_id, v.value()));
                }
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(out)
    }

    /// Insert a brand-new set at version 1.
    pub fn create_set(
        &self,
        user_id: &str,
        set_id: SetId,
        display_name: &str,
        system_prompt: &str,
        is_default: bool,
        key: &EncryptionKey,
    ) -> Result<SetSummary, StoreError> {
        let version = SetVersion(1);
        let payload = SetPayloadV1 {
            display_name: display_name.to_owned(),
            memory: String::new(),
            system_prompt: system_prompt.to_owned(),
            history: Vec::new(),
        };
        let now = now_millis();
        let blob = crypto::seal_blob(
            user_id,
            set_id,
            version,
            BlobFormat::AeadV1,
            &payload,
            key,
        )?;
        let meta = SetMetaValue {
            user_id: user_id.to_owned(),
            version,
            created_at: now,
            updated_at: now,
            is_default,
            blob_format: BlobFormat::AeadV1,
        };

        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let id_key = set_id_key(set_id);
            let already_exists = meta_table.get(id_key.as_slice())?.is_some();
            if already_exists {
                return Err(StoreError::InvalidInput);
            }
            let meta_bytes = meta.encode();
            meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.insert(id_key.as_slice(), blob.as_slice())?;
            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.insert(user_set_key(user_id, set_id).as_slice(), now)?;
        }
        txn.commit()?;

        Ok(SetSummary {
            set_id,
            version,
            display_name: display_name.to_owned(),
            updated_at: now,
            is_default,
        })
    }

    /// CAS commit of a full snapshot. `expected` must match stored version.
    /// Writes `snapshot` content at `expected.next()` (snapshot.version field is ignored for CAS check).
    pub fn commit_snapshot(
        &self,
        user_id: &str,
        expected: SetVersion,
        snapshot: &SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<SetVersion, StoreError> {
        let set_id = snapshot.set_id;
        let new_version = expected.next();
        if new_version.get() == expected.get() {
            // overflow
            return Err(StoreError::InvalidInput);
        }

        let payload = SetPayloadV1::from_snapshot(snapshot);
        let blob = crypto::seal_blob(
            user_id,
            set_id,
            new_version,
            BlobFormat::AeadV1,
            &payload,
            key,
        )?;
        let now = now_millis();
        let id_key = set_id_key(set_id);

        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let mut meta = {
                let existing = meta_table
                    .get(id_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                SetMetaValue::decode(existing.value()).ok_or(StoreError::Database(
                    "corrupt set meta".into(),
                ))?
            };
            if meta.user_id != user_id {
                return Err(StoreError::Forbidden);
            }
            if meta.version != expected {
                return Err(StoreError::Conflict {
                    current: meta.version,
                });
            }
            meta.version = new_version;
            meta.updated_at = now;
            meta.is_default = snapshot.is_default;
            meta.blob_format = BlobFormat::AeadV1;
            let meta_bytes = meta.encode();
            meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;

            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.insert(id_key.as_slice(), blob.as_slice())?;

            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.insert(user_set_key(user_id, set_id).as_slice(), now)?;
        }
        txn.commit()?;
        debug!(%set_id, version = new_version.get(), "history set committed");
        Ok(new_version)
    }

    pub fn delete_set(
        &self,
        user_id: &str,
        set_id: SetId,
        expected: SetVersion,
    ) -> Result<(), StoreError> {
        let id_key = set_id_key(set_id);
        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let meta = {
                let existing = meta_table
                    .get(id_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                SetMetaValue::decode(existing.value()).ok_or(StoreError::Database(
                    "corrupt set meta".into(),
                ))?
            };
            if meta.user_id != user_id {
                return Err(StoreError::Forbidden);
            }
            if meta.is_default {
                return Err(StoreError::InvalidInput);
            }
            if meta.version != expected {
                return Err(StoreError::Conflict {
                    current: meta.version,
                });
            }
            meta_table.remove(id_key.as_slice())?;
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.remove(id_key.as_slice())?;
            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.remove(user_set_key(user_id, set_id).as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Load meta only (for list without full decrypt of names — caller decrypts).
    #[allow(dead_code)] // used by migration / future list optimizations
    pub fn load_meta(&self, set_id: SetId) -> Result<SetMetaValue, StoreError> {
        let txn = self.db.begin_read()?;
        let meta_table = txn.open_table(SETS_META)?;
        let id_key = set_id_key(set_id);
        let existing = meta_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        SetMetaValue::decode(existing.value())
            .ok_or_else(|| StoreError::Database("corrupt set meta".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::ops::{append_pair, delete_pair};

    fn key() -> EncryptionKey {
        EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
            .unwrap()
    }

    #[test]
    fn create_load_append_cas() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let set_id = SetId::new();
        let summary = store
            .create_set("alice", set_id, "default", "sys", true, &key)
            .unwrap();
        assert_eq!(summary.version, SetVersion(1));

        let snap = store.load_snapshot("alice", set_id, &key).unwrap();
        assert_eq!(snap.display_name, "default");
        assert!(snap.history.is_empty());

        let next = append_pair(&snap, "hello", "world").unwrap();
        let v2 = store
            .commit_snapshot("alice", SetVersion(1), &next, &key)
            .unwrap();
        assert_eq!(v2, SetVersion(2));

        // Stale CAS fails
        let err = store
            .commit_snapshot("alice", SetVersion(1), &next, &key)
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict { current: SetVersion(2) }));

        let loaded = store.load_snapshot("alice", set_id, &key).unwrap();
        assert_eq!(loaded.history.len(), 1);
        assert_eq!(loaded.version, SetVersion(2));

        // Wrong user
        assert!(matches!(
            store.load_snapshot("bob", set_id, &key),
            Err(StoreError::Forbidden)
        ));
    }

    #[test]
    fn delete_pair_via_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let set_id = SetId::new();
        store
            .create_set("alice", set_id, "chat", "sys", false, &key)
            .unwrap();
        let snap = store.load_snapshot("alice", set_id, &key).unwrap();
        let s1 = append_pair(&snap, "u1", "a1").unwrap();
        store
            .commit_snapshot("alice", SetVersion(1), &s1, &key)
            .unwrap();
        let s1 = store.load_snapshot("alice", set_id, &key).unwrap();
        let s2 = append_pair(&s1, "u2", "a2").unwrap();
        store
            .commit_snapshot("alice", SetVersion(2), &s2, &key)
            .unwrap();

        let loaded = store.load_snapshot("alice", set_id, &key).unwrap();
        let deleted = delete_pair(&loaded, 0, "u1").unwrap();
        store
            .commit_snapshot("alice", SetVersion(3), &deleted, &key)
            .unwrap();
        let final_snap = store.load_snapshot("alice", set_id, &key).unwrap();
        assert_eq!(final_snap.history.len(), 1);
        assert_eq!(final_snap.history[0].0, "u2");
    }

    #[test]
    fn list_set_ids_and_no_name_in_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.redb");
        let store = RedbHistoryStore::open(&path).unwrap();
        let key = key();
        let secret_name = "Top Secret Plans";
        let set_id = SetId::new();
        store
            .create_set("alice", set_id, secret_name, "sys", false, &key)
            .unwrap();
        let listed = store.list_set_ids("alice").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, set_id);

        // File bytes must not contain plaintext set name
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(secret_name.len())
                .any(|w| w == secret_name.as_bytes()),
            "display name must not appear in redb file"
        );
    }
}
