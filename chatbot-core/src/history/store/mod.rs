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
use keys::{
    migrated_user_meta_key, set_id_key, user_set_key, user_sets_prefix, user_sets_prefix_end,
};
use tables::{
    SetMetaValue, META, SCHEMA_KEY, SCHEMA_VERSION, SETS_BLOB, SETS_META, USER_SETS,
};

/// One set to insert during legacy migration (pre-sealed in one txn).
pub struct ImportSet {
    pub set_id: SetId,
    pub display_name: String,
    pub memory: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
    pub is_default: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

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

        // Prefer a bounded range so we do not scan other users' keys.
        if let Some(end) = user_sets_prefix_end(user_id) {
            let iter = table.range(prefix.as_slice()..end.as_slice())?;
            for entry in iter {
                let (k, v) = entry?;
                let key = k.value();
                if key.len() == prefix.len() + 16 {
                    if let Some((_, set_id)) = keys::parse_user_set_key(key) {
                        out.push((set_id, v.value()));
                    }
                }
            }
        } else {
            // Pathological prefix (all 0xff): fall back to full scan + filter.
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
    #[allow(dead_code)]
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

    pub fn is_user_migrated(&self, user_id: &str) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let key = migrated_user_meta_key(user_id);
        Ok(meta.get(key.as_str())?.is_some())
    }

    /// Insert many sets and mark the user migrated in a single write transaction.
    ///
    /// Returns the number of sets inserted (0 if the user was already marked migrated).
    pub fn import_sets_and_mark_migrated(
        &self,
        user_id: &str,
        sets: &[ImportSet],
        key: &EncryptionKey,
    ) -> Result<usize, StoreError> {
        if self.is_user_migrated(user_id)? {
            return Ok(0);
        }

        let version = SetVersion(1);
        let mut prepared: Vec<(SetId, Vec<u8>, Vec<u8>, u64)> = Vec::with_capacity(sets.len());
        for set in sets {
            let payload = SetPayloadV1 {
                display_name: set.display_name.clone(),
                memory: set.memory.clone(),
                system_prompt: set.system_prompt.clone(),
                history: set.history.clone(),
            };
            let blob = crypto::seal_blob(
                user_id,
                set.set_id,
                version,
                BlobFormat::AeadV1,
                &payload,
                key,
            )?;
            let meta = SetMetaValue {
                user_id: user_id.to_owned(),
                version,
                created_at: set.created_at,
                updated_at: set.updated_at,
                is_default: set.is_default,
                blob_format: BlobFormat::AeadV1,
            };
            prepared.push((set.set_id, meta.encode(), blob, set.updated_at));
        }

        let mig_key = migrated_user_meta_key(user_id);
        let txn = self.db.begin_write()?;
        let inserted = {
            let already = {
                let meta_tbl = txn.open_table(META)?;
                let flag = meta_tbl.get(mig_key.as_str())?.is_some();
                flag
            };
            if already {
                0usize
            } else {
                let mut count = 0usize;
                {
                    let mut meta_table = txn.open_table(SETS_META)?;
                    let mut blob_table = txn.open_table(SETS_BLOB)?;
                    let mut user_table = txn.open_table(USER_SETS)?;
                    for (set_id, meta_bytes, blob, updated_at) in &prepared {
                        let id_key = set_id_key(*set_id);
                        let exists = meta_table.get(id_key.as_slice())?.is_some();
                        if exists {
                            continue;
                        }
                        meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;
                        blob_table.insert(id_key.as_slice(), blob.as_slice())?;
                        user_table.insert(user_set_key(user_id, *set_id).as_slice(), *updated_at)?;
                        count += 1;
                    }
                }
                let mut meta_tbl = txn.open_table(META)?;
                meta_tbl.insert(mig_key.as_str(), [1u8].as_slice())?;
                count
            }
        };
        txn.commit()?;
        Ok(inserted)
    }

    /// Mark user migrated with no sets (no legacy file).
    pub fn mark_user_migrated_empty(&self, user_id: &str) -> Result<(), StoreError> {
        let mig_key = migrated_user_meta_key(user_id);
        let txn = self.db.begin_write()?;
        {
            let mut meta_tbl = txn.open_table(META)?;
            let missing = meta_tbl.get(mig_key.as_str())?.is_none();
            if missing {
                meta_tbl.insert(mig_key.as_str(), [1u8].as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
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

    #[test]
    fn list_set_ids_is_scoped_to_user() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let a1 = SetId::new();
        let a2 = SetId::new();
        let b1 = SetId::new();
        store
            .create_set("alice", a1, "one", "sys", false, &key)
            .unwrap();
        store
            .create_set("alice", a2, "two", "sys", false, &key)
            .unwrap();
        store
            .create_set("bob", b1, "bob-set", "sys", false, &key)
            .unwrap();

        let alice = store.list_set_ids("alice").unwrap();
        assert_eq!(alice.len(), 2);
        assert!(alice.iter().all(|(id, _)| *id == a1 || *id == a2));

        let bob = store.list_set_ids("bob").unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].0, b1);
    }

    #[test]
    fn concurrent_cas_only_one_writer_wins() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(RedbHistoryStore::open(dir.path().join("history.redb")).unwrap());
        let key = Arc::new(key());
        let set_id = SetId::new();
        store
            .create_set("race", set_id, "default", "sys", true, &key)
            .unwrap();
        let snap = store.load_snapshot("race", set_id, &key).unwrap();
        assert_eq!(snap.version, SetVersion(1));

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = vec![];
        for i in 0..2 {
            let store = Arc::clone(&store);
            let key = Arc::clone(&key);
            let barrier = Arc::clone(&barrier);
            let base = snap.clone();
            handles.push(thread::spawn(move || {
                let next = append_pair(&base, &format!("u{i}"), &format!("a{i}")).unwrap();
                barrier.wait();
                store.commit_snapshot("race", SetVersion(1), &next, &key)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Conflict { .. })))
            .count();
        assert_eq!(wins, 1, "exactly one CAS commit should succeed");
        assert_eq!(conflicts, 1, "the other writer must see Conflict");

        let final_snap = store.load_snapshot("race", set_id, &key).unwrap();
        assert_eq!(final_snap.version, SetVersion(2));
        assert_eq!(final_snap.history.len(), 1);
    }

    #[test]
    fn forbidden_cross_user_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let set_id = SetId::new();
        store
            .create_set("owner", set_id, "s", "sys", false, &key)
            .unwrap();
        assert!(matches!(
            store.load_snapshot("intruder", set_id, &key),
            Err(StoreError::Forbidden)
        ));
    }

    #[test]
    fn cannot_delete_default_set() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let set_id = SetId::new();
        store
            .create_set("alice", set_id, "default", "sys", true, &key)
            .unwrap();
        assert!(matches!(
            store.delete_set("alice", set_id, SetVersion(1)),
            Err(StoreError::InvalidInput)
        ));
    }
}
