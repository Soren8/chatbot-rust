//! Sealed durable store. Not public outside `history`.

mod chunks;
mod keys;
mod tables;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, DatabaseError, ReadableDatabase, ReadableTable};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::crypto::{self, CryptoError};
use super::types::{
    BlobFormat, LogicalSnapshot, SetId, SetPayloadV1, SetSnapshot, SetSummary, SetVersion,
};
use crate::config::PrivacyLevel;
use crate::enc_key::EncryptionKey;
use keys::{
    migrated_user_meta_key, set_id_key, user_set_key, user_sets_prefix, user_sets_prefix_end,
};
use tables::{
    META, SCHEMA_KEY, SCHEMA_VERSION, SETS_BLOB, SETS_META, SETS_NAME, SETS_POLICY, SetMetaValue,
    USER_SETS,
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

/// Open (or create) a redb 4 database, upgrading legacy v2 files in place when needed.
///
/// redb 4 only supports file format v3. Databases created with redb 2.x default to v2 and
/// return [`DatabaseError::UpgradeRequired`]. redb 2.6 can still open those files and rewrite
/// them to v3 via [`redb2::Database::upgrade`]; redb 4 then opens the upgraded file.
fn open_database(path: &Path) -> Result<Database, StoreError> {
    match Database::create(path) {
        Ok(db) => Ok(db),
        Err(DatabaseError::UpgradeRequired(from_version)) => {
            info!(
                path = %path.display(),
                from_version,
                "history redb requires file-format upgrade; migrating to v3"
            );
            upgrade_legacy_redb_file(path, from_version)?;
            match Database::create(path) {
                Ok(db) => Ok(db),
                Err(err) => Err(StoreError::Database(format!(
                    "failed to open history redb after v{from_version}→v3 upgrade: {err}"
                ))),
            }
        }
        Err(err) => Err(StoreError::from(err)),
    }
}

fn upgrade_legacy_redb_file(path: &Path, from_version: u8) -> Result<(), StoreError> {
    // Hold exclusive access via redb2 until upgrade completes and the handle is dropped.
    let mut db = redb2::Database::open(path).map_err(|err| {
        StoreError::Database(format!(
            "failed to open legacy redb (format v{from_version}) for upgrade at {}: {err}",
            path.display()
        ))
    })?;
    let upgraded = db.upgrade().map_err(|err| {
        StoreError::Database(format!(
            "failed to upgrade redb file format v{from_version}→v3 at {}: {err}",
            path.display()
        ))
    })?;
    // Release the file lock before redb 4 reopens.
    drop(db);
    if upgraded {
        info!(
            path = %path.display(),
            from_version,
            "history redb upgraded to file format v3"
        );
    } else {
        warn!(
            path = %path.display(),
            from_version,
            "redb reported UpgradeRequired but upgrade() made no changes"
        );
    }
    Ok(())
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
        let db = open_database(&path)?;
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
            let current = meta
                .get(SCHEMA_KEY)?
                .and_then(|v| v.value().first().copied())
                .unwrap_or(0);
            if current > SCHEMA_VERSION {
                return Err(StoreError::Database(format!(
                    "unsupported history schema {current}"
                )));
            }
            if current < SCHEMA_VERSION {
                meta.insert(SCHEMA_KEY, [SCHEMA_VERSION].as_slice())?;
            }
            let _ = txn.open_table(SETS_META)?;
            let _ = txn.open_table(SETS_BLOB)?;
            let _ = txn.open_table(SETS_NAME)?;
            let _ = txn.open_table(SETS_POLICY)?;
            let _ = txn.open_table(USER_SETS)?;
            let _ = txn.open_table(tables::SETS_HEADER)?;
            let _ = txn.open_table(tables::SETS_MANIFEST)?;
            let _ = txn.open_table(tables::PAIR_BLOBS)?;
            let _ = txn.open_table(tables::IMAGE_BLOBS)?;
            let _ = txn.open_table(tables::THUMB_BLOBS)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Load non-sensitive meta only (no blob decrypt). Used for cache validation.
    pub fn load_meta(&self, user_id: &str, set_id: SetId) -> Result<SetMetaValue, StoreError> {
        let txn = self.db.begin_read()?;
        let meta_table = txn.open_table(SETS_META)?;
        let id_key = set_id_key(set_id);
        let meta_bytes = meta_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let meta = SetMetaValue::decode(meta_bytes.value())
            .ok_or(StoreError::Database("corrupt set meta".into()))?;
        if meta.user_id != user_id {
            return Err(StoreError::Forbidden);
        }
        Ok(meta)
    }

    pub fn load_policy(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<PrivacyLevel, StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SETS_POLICY)?;
        match table.get(set_id_key(set_id).as_slice())? {
            Some(blob) => Ok(crypto::open_policy_v1(user_id, set_id, blob.value(), key)?),
            None => Ok(PrivacyLevel::Private),
        }
    }

    pub fn load_meta_policy(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<(SetMetaValue, PrivacyLevel), StoreError> {
        let txn = self.db.begin_read()?;
        let id = set_id_key(set_id);
        let mt = txn.open_table(SETS_META)?;
        let meta =
            SetMetaValue::decode(mt.get(id.as_slice())?.ok_or(StoreError::NotFound)?.value())
                .ok_or(StoreError::Database("corrupt set meta".into()))?;
        if meta.user_id != user_id {
            return Err(StoreError::Forbidden);
        }
        let pt = txn.open_table(SETS_POLICY)?;
        let policy = match pt.get(id.as_slice())? {
            Some(blob) => crypto::open_policy_v1(user_id, set_id, blob.value(), key)?,
            None => PrivacyLevel::default_chat(),
        };
        Ok((meta, policy))
    }

    pub fn change_policy(
        &self,
        user_id: &str,
        set_id: SetId,
        expected: SetVersion,
        level: PrivacyLevel,
        key: &EncryptionKey,
    ) -> Result<SetVersion, StoreError> {
        let (meta, current_policy) = self.load_meta_policy(user_id, set_id, key)?;
        if meta.version != expected {
            return Err(StoreError::Conflict {
                current: meta.version,
            });
        }
        if current_policy == level {
            return Ok(expected);
        }
        let next = expected.next();
        if next == expected {
            return Err(StoreError::InvalidInput);
        }
        let policy = crypto::seal_policy_v1(user_id, set_id, level, key)?;
        let blob = if meta.blob_format.is_chunked() {
            None
        } else {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            Some(crypto::seal_blob(
                user_id,
                set_id,
                next,
                meta.blob_format,
                &SetPayloadV1::from_snapshot(&snap),
                key,
            )?)
        };
        let manifest = if meta.blob_format.is_chunked() {
            let old = self.load_manifest(user_id, set_id, expected, key)?;
            Some(crypto::seal_manifest_v1(user_id, set_id, next, &old, key)?)
        } else {
            None
        };
        let id = set_id_key(set_id);
        let txn = self.db.begin_write()?;
        {
            let mut mt = txn.open_table(SETS_META)?;
            let mut current =
                SetMetaValue::decode(mt.get(id.as_slice())?.ok_or(StoreError::NotFound)?.value())
                    .ok_or(StoreError::Database("corrupt set meta".into()))?;
            if current.user_id != user_id {
                return Err(StoreError::Forbidden);
            }
            if current.version != expected {
                return Err(StoreError::Conflict {
                    current: current.version,
                });
            }
            current.version = next;
            current.updated_at = now_millis();
            mt.insert(id.as_slice(), current.encode().as_slice())?;
            let mut pt = txn.open_table(SETS_POLICY)?;
            pt.insert(id.as_slice(), policy.as_slice())?;
            if let Some(blob) = blob {
                let mut bt = txn.open_table(SETS_BLOB)?;
                bt.insert(id.as_slice(), blob.as_slice())?;
            }
            if let Some(manifest) = manifest {
                let mut table = txn.open_table(tables::SETS_MANIFEST)?;
                table.insert(id.as_slice(), manifest.as_slice())?;
            }
            let mut users = txn.open_table(USER_SETS)?;
            users.insert(user_set_key(user_id, set_id).as_slice(), current.updated_at)?;
        }
        txn.commit()?;
        Ok(next)
    }

    pub fn load_snapshot(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if meta.blob_format.is_chunked() {
            let logical = self.load_logical(user_id, set_id, key)?;
            return self.materialize_snapshot(user_id, &logical, key);
        }
        let txn = self.db.begin_read()?;
        let blob_table = txn.open_table(SETS_BLOB)?;
        let id_key = set_id_key(set_id);
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
        let mut snapshot = payload.into_snapshot(set_id, meta.version, meta.is_default);
        snapshot.privacy_level = self.load_policy(user_id, set_id, key)?;
        Ok(snapshot)
    }

    /// Decrypt only the sealed display name. Does not open `SETS_BLOB`.
    pub fn load_display_name(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<String, StoreError> {
        let txn = self.db.begin_read()?;
        let meta_table = txn.open_table(SETS_META)?;
        let name_table = txn.open_table(SETS_NAME)?;
        let id_key = set_id_key(set_id);

        let meta_bytes = meta_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let meta = SetMetaValue::decode(meta_bytes.value())
            .ok_or(StoreError::Database("corrupt set meta".into()))?;
        if meta.user_id != user_id {
            return Err(StoreError::Forbidden);
        }
        let blob = name_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        Ok(crypto::open_name_v1(user_id, set_id, blob.value(), key)?)
    }

    /// Write / replace the sealed display name without touching the history blob.
    pub fn put_display_name(
        &self,
        user_id: &str,
        set_id: SetId,
        display_name: &str,
        key: &EncryptionKey,
    ) -> Result<(), StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let sealed = crypto::seal_name_v1(user_id, set_id, display_name, key)?;
        let txn = self.db.begin_write()?;
        {
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.insert(set_id_key(set_id).as_slice(), sealed.as_slice())?;
        }
        txn.commit()?;
        Ok(())
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
        self.create_set_with_policy(
            user_id,
            set_id,
            display_name,
            system_prompt,
            is_default,
            PrivacyLevel::default_chat(),
            key,
        )
    }

    pub fn create_set_with_policy(
        &self,
        user_id: &str,
        set_id: SetId,
        display_name: &str,
        system_prompt: &str,
        is_default: bool,
        privacy_level: PrivacyLevel,
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
        let blob = crypto::seal_blob(user_id, set_id, version, BlobFormat::AeadV1, &payload, key)?;
        let name_blob = crypto::seal_name_v1(user_id, set_id, display_name, key)?;
        let meta = SetMetaValue {
            user_id: user_id.to_owned(),
            version,
            created_at: now,
            updated_at: now,
            is_default,
            blob_format: BlobFormat::AeadV1,
            header_generation: 0,
            pair_count: None,
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
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.insert(id_key.as_slice(), name_blob.as_slice())?;
            let policy = crypto::seal_policy_v1(user_id, set_id, privacy_level, key)?;
            let mut policy_table = txn.open_table(SETS_POLICY)?;
            policy_table.insert(id_key.as_slice(), policy.as_slice())?;
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
            privacy_level,
        })
    }

    /// CAS commit of a full snapshot. `expected` must match stored version.
    /// Writes `snapshot` content at `expected.next()` (snapshot.version field is ignored for CAS check).
    /// Returns the sealed logical shape for the cache: chunked commits come
    /// back ref-normalized, whole-blob commits echo the sealed working copy.
    pub fn commit_snapshot(
        &self,
        user_id: &str,
        expected: SetVersion,
        mut snapshot: SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<(SetVersion, LogicalSnapshot), StoreError> {
        let set_id = snapshot.set_id;
        match self.load_meta(user_id, set_id) {
            Ok(meta) if meta.blob_format.is_chunked() => {
                return self.commit_chunked(user_id, expected, snapshot, key);
            }
            Ok(_) => (),
            Err(err) => return Err(err),
        }
        let new_version = expected.next();
        if new_version.get() == expected.get() {
            // overflow
            return Err(StoreError::InvalidInput);
        }

        let payload = SetPayloadV1::from_snapshot(&snapshot);
        let durable_policy = self.load_policy(user_id, set_id, key)?;
        let blob = crypto::seal_blob(
            user_id,
            set_id,
            new_version,
            BlobFormat::AeadV1,
            &payload,
            key,
        )?;
        let name_blob = crypto::seal_name_v1(user_id, set_id, &snapshot.display_name, key)?;
        let policy_blob =
            crypto::seal_policy_v1(user_id, set_id, PrivacyLevel::default_chat(), key)?;
        let now = now_millis();
        let id_key = set_id_key(set_id);

        let txn = self.db.begin_write()?;
        let durable_is_default;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let mut meta = {
                let existing = meta_table
                    .get(id_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                SetMetaValue::decode(existing.value())
                    .ok_or(StoreError::Database("corrupt set meta".into()))?
            };
            durable_is_default = meta.is_default;
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
            // is_default is lifecycle metadata only; content commits cannot flip it.
            meta.blob_format = BlobFormat::AeadV1;
            let meta_bytes = meta.encode();
            meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;

            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.insert(id_key.as_slice(), blob.as_slice())?;
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.insert(id_key.as_slice(), name_blob.as_slice())?;
            let mut policy_table = txn.open_table(SETS_POLICY)?;
            if policy_table.get(id_key.as_slice())?.is_none() {
                policy_table.insert(id_key.as_slice(), policy_blob.as_slice())?;
            }

            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.insert(user_set_key(user_id, set_id).as_slice(), now)?;
        }
        txn.commit()?;
        debug!(%set_id, version = new_version.get(), "history set committed");
        snapshot.version = new_version;
        snapshot.is_default = durable_is_default;
        snapshot.privacy_level = durable_policy;
        // Whole-blob payloads seal no pair ids; the working copy's ids are not
        // durable until a chunk migrate assigns stable ones (and migrate
        // invalidates this entry first). Keep the cached shape load-accurate.
        snapshot.pair_ids.clear();
        Ok((new_version, LogicalSnapshot::from_normalized(snapshot)))
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
                SetMetaValue::decode(existing.value())
                    .ok_or(StoreError::Database("corrupt set meta".into()))?
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
            let mut name_table = txn.open_table(SETS_NAME)?;
            let _ = name_table.remove(id_key.as_slice())?;
            let mut policy_table = txn.open_table(SETS_POLICY)?;
            let _ = policy_table.remove(id_key.as_slice())?;
            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.remove(user_set_key(user_id, set_id).as_slice())?;
        }
        txn.commit()?;
        let _ = self.delete_chunks_for_set(set_id);
        Ok(())
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
        let mut prepared: Vec<(SetId, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u64)> =
            Vec::with_capacity(sets.len());
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
            let name_blob = crypto::seal_name_v1(user_id, set.set_id, &set.display_name, key)?;
            let policy_blob =
                crypto::seal_policy_v1(user_id, set.set_id, PrivacyLevel::Private, key)?;
            let meta = SetMetaValue {
                user_id: user_id.to_owned(),
                version,
                created_at: set.created_at,
                updated_at: set.updated_at,
                is_default: set.is_default,
                blob_format: BlobFormat::AeadV1,
                header_generation: 0,
                pair_count: None,
            };
            prepared.push((
                set.set_id,
                meta.encode(),
                blob,
                name_blob,
                policy_blob,
                set.updated_at,
            ));
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
                    let mut name_table = txn.open_table(SETS_NAME)?;
                    let mut policy_table = txn.open_table(SETS_POLICY)?;
                    let mut user_table = txn.open_table(USER_SETS)?;
                    for (set_id, meta_bytes, blob, name_blob, policy_blob, updated_at) in &prepared
                    {
                        let id_key = set_id_key(*set_id);
                        let exists = meta_table.get(id_key.as_slice())?.is_some();
                        if exists {
                            continue;
                        }
                        meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;
                        blob_table.insert(id_key.as_slice(), blob.as_slice())?;
                        name_table.insert(id_key.as_slice(), name_blob.as_slice())?;
                        policy_table.insert(id_key.as_slice(), policy_blob.as_slice())?;
                        user_table
                            .insert(user_set_key(user_id, *set_id).as_slice(), *updated_at)?;
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

    #[cfg(test)]
    pub fn test_remove_history_blob(&self, user_id: &str, set_id: SetId) -> Result<(), StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_write()?;
        {
            let id_key = set_id_key(set_id);
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.remove(id_key.as_slice())?;
            let mut header = txn.open_table(tables::SETS_HEADER)?;
            header.remove(id_key.as_slice())?;
            let mut manifest = txn.open_table(tables::SETS_MANIFEST)?;
            manifest.remove(id_key.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn test_chunk_ciphertexts(
        &self,
        set_id: SetId,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), StoreError> {
        let txn = self.db.begin_read()?;
        let pair_table = txn.open_table(tables::PAIR_BLOBS)?;
        let image_table = txn.open_table(tables::IMAGE_BLOBS)?;
        let pair_keys = chunks::collect_prefix_keys(&pair_table, set_id)?;
        let image_keys = chunks::collect_prefix_keys(&image_table, set_id)?;
        let mut pairs = Vec::new();
        for k in pair_keys {
            if let Some(v) = pair_table.get(k.as_slice())? {
                pairs.push(v.value().to_vec());
            }
        }
        let mut images = Vec::new();
        for k in image_keys {
            if let Some(v) = image_table.get(k.as_slice())? {
                images.push(v.value().to_vec());
            }
        }
        pairs.sort();
        images.sort();
        Ok((pairs, images))
    }

    #[cfg(test)]
    pub fn test_remove_name_blob(&self, user_id: &str, set_id: SetId) -> Result<(), StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_write()?;
        {
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.remove(set_id_key(set_id).as_slice())?;
        }
        txn.commit()?;
        Ok(())
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
        let (v2, _) = store
            .commit_snapshot("alice", SetVersion(1), next.clone(), &key)
            .unwrap();
        assert_eq!(v2, SetVersion(2));

        // Stale CAS fails
        let err = store
            .commit_snapshot("alice", SetVersion(1), next, &key)
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::Conflict {
                current: SetVersion(2)
            }
        ));

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
    fn missing_policy_defaults_private_but_corrupt_policy_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("policy.redb")).unwrap();
        let key = key();
        let id = SetId::new();
        store
            .create_set("alice", id, "legacy", "sys", false, &key)
            .unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SETS_POLICY).unwrap();
            table.remove(set_id_key(id).as_slice()).unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(
            store.load_policy("alice", id, &key).unwrap(),
            PrivacyLevel::default_chat()
        );
        assert!(matches!(
            store.load_policy("bob", id, &key),
            Err(StoreError::Forbidden)
        ));
        let txn = store.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SETS_POLICY).unwrap();
            table
                .insert(set_id_key(id).as_slice(), b"broken".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(
            store.load_policy("alice", id, &key).is_err(),
            "corrupt policy must not silently default"
        );
        let wrong = EncryptionKey::from_header_value(
            "d3Jvbmcta2V5LW1hdGVyaWFsLTAwMDAwMDAwMDAwMDAwMDAwMA==",
        )
        .unwrap();
        assert!(store.load_policy("alice", id, &wrong).is_err());
    }

    #[test]
    fn policy_ciphertext_rejects_owner_and_set_id_row_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("policy-swaps.redb")).unwrap();
        let key = key();
        let alice_id = SetId::new();
        let bob_id = SetId::new();
        store
            .create_set("alice", alice_id, "alice", "sys", false, &key)
            .unwrap();
        store
            .create_set_with_policy(
                "bob",
                bob_id,
                "bob",
                "sys",
                false,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();

        let txn = store.db.begin_write().unwrap();
        {
            let mut policies = txn.open_table(SETS_POLICY).unwrap();
            let alice = policies
                .get(set_id_key(alice_id).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let bob = policies
                .get(set_id_key(bob_id).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            policies
                .insert(set_id_key(alice_id).as_slice(), bob.as_slice())
                .unwrap();
            policies
                .insert(set_id_key(bob_id).as_slice(), alice.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(
            store.load_policy("alice", alice_id, &key).is_err(),
            "owner/set-bound ciphertext must not open after cross-owner swap"
        );
        assert!(store.load_policy("bob", bob_id, &key).is_err());

        let first = SetId::new();
        let second = SetId::new();
        store
            .create_set("carol", first, "first", "sys", false, &key)
            .unwrap();
        store
            .create_set_with_policy(
                "carol",
                second,
                "second",
                "sys",
                false,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut policies = txn.open_table(SETS_POLICY).unwrap();
            let a = policies
                .get(set_id_key(first).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let b = policies
                .get(set_id_key(second).as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            policies
                .insert(set_id_key(first).as_slice(), b.as_slice())
                .unwrap();
            policies
                .insert(set_id_key(second).as_slice(), a.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(
            store.load_policy("carol", first, &key).is_err(),
            "same-owner ciphertext must not open under another set ID"
        );
        assert!(store.load_policy("carol", second, &key).is_err());
    }

    #[test]
    fn missing_policy_is_seeded_private_by_authorized_content_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("legacy-policy-write.redb")).unwrap();
        let key = key();
        let id = SetId::new();
        let created = store
            .create_set("alice", id, "legacy", "sys", false, &key)
            .unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut policies = txn.open_table(SETS_POLICY).unwrap();
            policies.remove(set_id_key(id).as_slice()).unwrap();
        }
        txn.commit().unwrap();
        let mut snapshot = store.load_snapshot("alice", id, &key).unwrap();
        assert_eq!(snapshot.privacy_level, PrivacyLevel::default_chat());
        snapshot.privacy_level = PrivacyLevel::NonPrivate; // untrusted caller DTO must not set canonical policy
        snapshot.history.push(("u".into(), "a".into()));
        store
            .commit_snapshot("alice", created.version, snapshot, &key)
            .unwrap();
        assert_eq!(
            store.load_policy("alice", id, &key).unwrap(),
            PrivacyLevel::default_chat()
        );
        assert_eq!(
            store
                .load_snapshot("alice", id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::default_chat()
        );

        let version = store
            .change_policy("alice", id, SetVersion(2), PrivacyLevel::NonPrivate, &key)
            .unwrap();
        let mut forged = store.load_snapshot("alice", id, &key).unwrap();
        forged.privacy_level = PrivacyLevel::default_chat();
        forged.history.push(("another".into(), "pair".into()));
        store
            .commit_snapshot("alice", version, forged, &key)
            .unwrap();
        assert_eq!(
            store
                .load_snapshot("alice", id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::NonPrivate,
            "generic content commit cannot downgrade canonical policy"
        );
    }

    #[test]
    fn legacy_import_seeds_private_policy() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("import-policy.redb")).unwrap();
        let key = key();
        let id = SetId::new();
        let imported = ImportSet {
            set_id: id,
            display_name: "imported".into(),
            memory: "m".into(),
            system_prompt: "p".into(),
            history: vec![("u".into(), "a".into())],
            is_default: false,
            created_at: 1,
            updated_at: 2,
        };
        assert_eq!(
            store
                .import_sets_and_mark_migrated("alice", &[imported], &key)
                .unwrap(),
            1
        );
        assert_eq!(
            store.load_policy("alice", id, &key).unwrap(),
            PrivacyLevel::default_chat()
        );
    }

    #[test]
    fn policy_noop_checks_version_with_policy_in_same_read_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("policy-cas.redb")).unwrap();
        let key = key();
        let id = SetId::new();
        store
            .create_set("alice", id, "chat", "sys", false, &key)
            .unwrap();
        assert_eq!(
            store
                .change_policy("alice", id, SetVersion(1), PrivacyLevel::NonPrivate, &key)
                .unwrap(),
            SetVersion(2)
        );

        let (meta, policy) = store.load_meta_policy("alice", id, &key).unwrap();
        assert_eq!(meta.version, SetVersion(2));
        assert_eq!(policy, PrivacyLevel::NonPrivate);
        assert!(matches!(
            store.change_policy("alice", id, SetVersion(1), PrivacyLevel::NonPrivate, &key),
            Err(StoreError::Conflict {
                current: SetVersion(2)
            })
        ));

        let (after_meta, after_policy) = store.load_meta_policy("alice", id, &key).unwrap();
        assert_eq!(after_meta.version, SetVersion(2));
        assert_eq!(after_policy, PrivacyLevel::NonPrivate);
        assert_eq!(
            store
                .change_policy("alice", id, SetVersion(2), PrivacyLevel::NonPrivate, &key)
                .unwrap(),
            SetVersion(2),
            "current-mode no-op must not advance version"
        );
    }

    #[test]
    fn failed_chunk_policy_change_keeps_version_and_policy_together() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("policy-rollback.redb")).unwrap();
        let key = key();
        let id = SetId::new();
        store
            .create_set("alice", id, "chat", "sys", false, &key)
            .unwrap();
        let snap = store.load_snapshot("alice", id, &key).unwrap();
        store.migrate_set_to_chunks("alice", id, &key).unwrap();
        let meta = store.load_meta("alice", id).unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(tables::SETS_MANIFEST).unwrap();
            table
                .insert(set_id_key(id).as_slice(), b"corrupt".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(
            store
                .change_policy("alice", id, meta.version, PrivacyLevel::NonPrivate, &key)
                .is_err()
        );
        let (after, policy) = store.load_meta_policy("alice", id, &key).unwrap();
        assert_eq!(after.version, meta.version);
        assert_eq!(policy, PrivacyLevel::default_chat());
        assert_eq!(snap.version, meta.version);
    }

    #[test]
    fn rejects_newer_history_schema_without_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("newer.redb");
        let store = RedbHistoryStore::open(&path).unwrap();
        let txn = store.db.begin_write().unwrap();
        {
            let mut meta = txn.open_table(META).unwrap();
            meta.insert(SCHEMA_KEY, [SCHEMA_VERSION + 1].as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        drop(store);
        assert!(matches!(
            RedbHistoryStore::open(&path),
            Err(StoreError::Database(_))
        ));
        let db = Database::open(&path).unwrap();
        let txn = db.begin_read().unwrap();
        let meta = txn.open_table(META).unwrap();
        assert_eq!(
            meta.get(SCHEMA_KEY).unwrap().unwrap().value(),
            [SCHEMA_VERSION + 1]
        );
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
            .commit_snapshot("alice", SetVersion(1), s1, &key)
            .unwrap();
        let s1 = store.load_snapshot("alice", set_id, &key).unwrap();
        let s2 = append_pair(&s1, "u2", "a2").unwrap();
        store
            .commit_snapshot("alice", SetVersion(2), s2, &key)
            .unwrap();

        let loaded = store.load_snapshot("alice", set_id, &key).unwrap();
        let deleted = delete_pair(loaded, 0, "u1").unwrap();
        store
            .commit_snapshot("alice", SetVersion(3), deleted, &key)
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

        assert_eq!(
            store.load_display_name("alice", set_id, &key).unwrap(),
            secret_name
        );
        store.test_remove_history_blob("alice", set_id).unwrap();
        assert_eq!(
            store.load_display_name("alice", set_id, &key).unwrap(),
            secret_name,
            "name row must not depend on the history blob"
        );
        assert!(store.load_snapshot("alice", set_id, &key).is_err());
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
                store
                    .commit_snapshot("race", SetVersion(1), next, &key)
                    .map(|(v, _)| v)
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

    #[test]
    fn commit_snapshot_cannot_flip_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbHistoryStore::open(dir.path().join("history.redb")).unwrap();
        let key = key();
        let set_id = SetId::new();
        store
            .create_set("alice", set_id, "chat", "sys", false, &key)
            .unwrap();
        let mut snap = store.load_snapshot("alice", set_id, &key).unwrap();
        assert!(!snap.is_default);
        snap.is_default = true;
        snap.history.push(("u".into(), "a".into()));
        store
            .commit_snapshot("alice", SetVersion(1), snap, &key)
            .unwrap();
        let reloaded = store.load_snapshot("alice", set_id, &key).unwrap();
        assert!(
            !reloaded.is_default,
            "content commit must not flip is_default"
        );
        assert_eq!(reloaded.history.len(), 1);
    }

    /// Seed a redb 2.x (file format v2) database with real history rows, then open via
    /// `RedbHistoryStore` which must upgrade in place and still decrypt the payload.
    #[test]
    fn upgrades_v2_file_format_preserving_encrypted_sets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.redb");
        let key = key();
        let set_id = SetId::new();
        let user = "alice";
        let display_name = "legacy-v2-chat";
        let now = 1_700_000_000_000u64;

        let payload = SetPayloadV1 {
            display_name: display_name.to_owned(),
            memory: "remember the migration".into(),
            system_prompt: "sys".into(),
            history: vec![("hello from v2".into(), "hi back".into())],
        };
        let version = SetVersion(1);
        let blob =
            crypto::seal_blob(user, set_id, version, BlobFormat::AeadV1, &payload, &key).unwrap();
        let meta = SetMetaValue {
            user_id: user.to_owned(),
            version,
            created_at: now,
            updated_at: now,
            is_default: true,
            blob_format: BlobFormat::AeadV1,
            header_generation: 0,
            pair_count: None,
        };
        let meta_bytes = meta.encode();
        let id_key = set_id_key(set_id);
        let user_key = user_set_key(user, set_id);

        // redb 2.6 defaults to file format v2.
        {
            const SETS_META_V2: redb2::TableDefinition<'_, &[u8], &[u8]> =
                redb2::TableDefinition::new("sets_meta");
            const SETS_BLOB_V2: redb2::TableDefinition<'_, &[u8], &[u8]> =
                redb2::TableDefinition::new("sets_blob");
            const USER_SETS_V2: redb2::TableDefinition<'_, &[u8], u64> =
                redb2::TableDefinition::new("user_sets");
            const META_V2: redb2::TableDefinition<'_, &str, &[u8]> =
                redb2::TableDefinition::new("meta");

            let db = redb2::Database::create(&path).expect("create v2 redb");
            let txn = db.begin_write().unwrap();
            {
                let mut meta_tbl = txn.open_table(META_V2).unwrap();
                meta_tbl
                    .insert(SCHEMA_KEY, [SCHEMA_VERSION].as_slice())
                    .unwrap();
                let mut sets_meta = txn.open_table(SETS_META_V2).unwrap();
                sets_meta
                    .insert(id_key.as_slice(), meta_bytes.as_slice())
                    .unwrap();
                let mut sets_blob = txn.open_table(SETS_BLOB_V2).unwrap();
                sets_blob
                    .insert(id_key.as_slice(), blob.as_slice())
                    .unwrap();
                let mut user_sets = txn.open_table(USER_SETS_V2).unwrap();
                user_sets.insert(user_key.as_slice(), now).unwrap();
            }
            txn.commit().unwrap();
            drop(db);
        }

        assert!(
            matches!(
                Database::open(&path),
                Err(DatabaseError::UpgradeRequired(_))
            ),
            "seed file must still be pre-v3 so upgrade path is exercised"
        );

        let store = RedbHistoryStore::open(&path).expect("open should upgrade v2→v3");
        let listed = store.list_set_ids(user).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, set_id);

        let snap = store.load_snapshot(user, set_id, &key).unwrap();
        assert_eq!(snap.display_name, display_name);
        assert_eq!(snap.memory, "remember the migration");
        assert_eq!(snap.history.len(), 1);
        assert_eq!(snap.history[0].0, "hello from v2");
        assert_eq!(snap.history[0].1, "hi back");
        assert!(snap.is_default);
        assert_eq!(snap.version, SetVersion(1));

        // Post-upgrade writes must work on the same file.
        let next = append_pair(&snap, "after upgrade", "ok").unwrap();
        let (v2, _) = store
            .commit_snapshot(user, SetVersion(1), next, &key)
            .unwrap();
        assert_eq!(v2, SetVersion(2));
        let reloaded = store.load_snapshot(user, set_id, &key).unwrap();
        assert_eq!(reloaded.history.len(), 2);
    }

    #[test]
    fn open_fresh_path_does_not_require_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.redb");
        let store = RedbHistoryStore::open(&path).unwrap();
        let key = key();
        let set_id = SetId::new();
        store
            .create_set("bob", set_id, "fresh", "sys", true, &key)
            .unwrap();
        // Re-open existing v3 file (no UpgradeRequired).
        drop(store);
        let store = RedbHistoryStore::open(&path).unwrap();
        let snap = store.load_snapshot("bob", set_id, &key).unwrap();
        assert_eq!(snap.display_name, "fresh");
    }
}
