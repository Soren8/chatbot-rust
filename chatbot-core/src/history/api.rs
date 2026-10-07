//! Public safe API for durable history/set access.
//!
//! All HTTP handlers and session orchestration must go through [`HistoryService`].
//! redb handles, raw keys, and free-form blob writes are not exposed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use once_cell::sync::OnceCell;
use thiserror::Error;
use tracing::error;

use super::cache::SetCache;
use super::migration;
use super::ops::{self, OpsError};
use super::store::{ForkSpec, RedbHistoryStore, StoreError};
use super::types::{ImageId, LogicalSnapshot, PrepareCapture, SetId, SetSnapshot, SetSummary, SetVersion};
use crate::chat_images::{collect_image_refs, encode_data_url, materialize_full, ImageFidelity};
use crate::config::app_config;
use crate::config::PrivacyLevel;
use crate::enc_key::EncryptionKey;
use crate::operation_receipt::{
    OperationRequest, Receipt, ReceiptClock, ReceiptOutcome, SystemReceiptClock,
};

/// Source facts read for a fork.
struct ForkSource {
    set_id: SetId,
    version: SetVersion,
    pair_count: usize,
    summary: SetSummary,
}

/// Serializes create/rename uniqueness checks per user (names live only in ciphertext).
fn name_mutation_locks() -> &'static DashMap<String, Mutex<()>> {
    static LOCKS: OnceLock<DashMap<String, Mutex<()>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

/// Per-set lock for v1→v2 chunk migrate. Store helpers must not take this lock.
fn migrate_locks() -> &'static DashMap<SetId, Mutex<()>> {
    static LOCKS: OnceLock<DashMap<SetId, Mutex<()>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

/// Errors returned by [`HistoryService`]. Map to HTTP in the server layer.
#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("set not found")]
    NotFound,
    #[error("version conflict")]
    Conflict { current_version: SetVersion },
    #[error("forbidden")]
    Forbidden,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("encryption key required")]
    MissingKey,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("internal history error")]
    Internal,
}

impl From<StoreError> for HistoryError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound => HistoryError::NotFound,
            StoreError::Conflict { current } => HistoryError::Conflict {
                current_version: current,
            },
            StoreError::Forbidden => HistoryError::Forbidden,
            StoreError::DecryptFailed => HistoryError::DecryptFailed,
            StoreError::InvalidInput => HistoryError::InvalidInput("invalid history operation"),
            StoreError::Database(msg) => {
                error!(%msg, "history store database error");
                HistoryError::Internal
            }
            StoreError::Crypto => {
                error!("history crypto error");
                HistoryError::Internal
            }
            StoreError::Io(err) => {
                error!(?err, "history store io error");
                HistoryError::Internal
            }
        }
    }
}

impl From<OpsError> for HistoryError {
    fn from(err: OpsError) -> Self {
        match err {
            OpsError::PairIndexOutOfRange => HistoryError::InvalidInput("pair_index out of range"),
            OpsError::ContentMismatch => {
                HistoryError::InvalidInput("content mismatch at pair_index")
            }
            OpsError::EmptyUserMessage => HistoryError::InvalidInput("empty user message"),
            OpsError::EmptySetName => HistoryError::InvalidInput("empty set name"),
            OpsError::HistoryTooLarge => HistoryError::InvalidInput("history too large"),
            OpsError::MessageTooLarge => HistoryError::InvalidInput("message too large"),
            OpsError::MemoryTooLarge => HistoryError::InvalidInput("memory too large"),
            OpsError::PromptTooLarge => HistoryError::InvalidInput("system prompt too large"),
            OpsError::DisplayNameTooLarge => HistoryError::InvalidInput("set name too large"),
        }
    }
}

static GLOBAL: OnceCell<HistoryService> = OnceCell::new();

/// Sole entry point for durable history/set access.
#[derive(Clone)]
pub struct HistoryService {
    store: Arc<RedbHistoryStore>,
    /// Optional multi-set cache of decrypted plaintext snapshots; never authoritative.
    cache: SetCache,
    default_system_prompt: String,
    /// Host data dir containing `user_sets/` for legacy migration.
    data_dir: PathBuf,
    receipt_clock: Arc<dyn ReceiptClock>,
    #[cfg(test)]
    default_set_after_check: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl HistoryService {
    /// The process-global service if already opened; never initializes it.
    pub fn get() -> Option<&'static HistoryService> {
        GLOBAL.get()
    }

    /// Open (or reuse) the process-global service at `{HOST_DATA_DIR}/history/redb`.
    pub fn global() -> Result<&'static HistoryService, HistoryError> {
        GLOBAL.get_or_try_init(|| {
            let config = app_config();
            let path = config.host_data_dir.join("history").join("redb");
            Self::open_with_data_dir(
                path,
                config.host_data_dir.clone(),
                config.default_system_prompt.clone(),
            )
        })
    }

    pub fn open(
        path: impl AsRef<Path>,
        default_system_prompt: impl Into<String>,
    ) -> Result<Self, HistoryError> {
        let config = app_config();
        Self::open_with_data_dir(path, config.host_data_dir.clone(), default_system_prompt)
    }

    pub fn open_with_data_dir(
        redb_path: impl AsRef<Path>,
        data_dir: impl Into<PathBuf>,
        default_system_prompt: impl Into<String>,
    ) -> Result<Self, HistoryError> {
        let store = RedbHistoryStore::open(redb_path).map_err(HistoryError::from)?;
        Ok(Self {
            store: Arc::new(store),
            cache: SetCache::new(),
            default_system_prompt: default_system_prompt.into(),
            data_dir: data_dir.into(),
            receipt_clock: Arc::new(SystemReceiptClock),
            #[cfg(test)]
            default_set_after_check: None,
        })
    }

    /// Drop expired cached plaintext; returns the number of records removed.
    pub fn purge_expired_cache(&self) -> usize {
        self.cache.purge_expired()
    }

    /// Cache a durable-normalized logical snapshot (no re-load/decrypt).
    /// Only store-returned logical shapes reach here — never incoming
    /// `data:`-carrying working copies.
    /// CAS commit, comparing unchanged pairs against the cached snapshot at
    /// `expected` when one is present instead of decrypting them.
    fn commit(
        &self,
        user: &str,
        expected: SetVersion,
        next: SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<(SetVersion, LogicalSnapshot), HistoryError> {
        let known = self.cache.get_snapshot_if_version(user, next.set_id, expected);
        Ok(self.store.commit_snapshot_known(
            user,
            expected,
            next,
            key,
            known.as_deref().map(LogicalSnapshot::as_snapshot),
        )?)
    }

    fn remember(&self, user: &str, snap: impl Into<Arc<LogicalSnapshot>>) {
        self.cache.put_snapshot(user, snap);
    }

    /// Split a v0/v1 set into chunks if needed. Does not hold name-mutation locks.
    pub fn ensure_chunked(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<(), HistoryError> {
        let meta = match self.store.load_meta(user, set_id) {
            Ok(m) => m,
            Err(StoreError::NotFound) => return Err(HistoryError::NotFound),
            Err(StoreError::Forbidden) => return Err(HistoryError::Forbidden),
            Err(err) => return Err(err.into()),
        };
        if meta.blob_format.is_chunked() {
            return Ok(());
        }
        let lock_entry = migrate_locks()
            .entry(set_id)
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.store.migrate_set_to_chunks(user, set_id, key) {
            Ok(_) => {
                self.cache.invalidate(user, set_id);
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Load the normalized logical snapshot, preferring the process cache when
    /// durable meta version matches. The cache holds logical shapes only
    /// (format-2 image refs); materialization happens at the public `load`
    /// boundary on an owned copy.
    fn load_snapshot_cached(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<Arc<LogicalSnapshot>, HistoryError> {
        self.ensure_chunked(user, set_id, key)?;
        match self.store.load_meta(user, set_id) {
            Ok(meta) => {
                if let Some(cached) = self
                    .cache
                    .get_snapshot_if_version(user, set_id, meta.version)
                {
                    // The cache is plaintext: authenticate this request's key
                    // against the sealed, version-bound manifest before using it.
                    self.store.load_manifest(user, set_id, meta.version, key)?;
                    return Ok(cached);
                }
            }
            Err(StoreError::NotFound) => return Err(HistoryError::NotFound),
            Err(StoreError::Forbidden) => return Err(HistoryError::Forbidden),
            Err(err) => return Err(err.into()),
        }
        let snap = Arc::new(self.store.load_logical(user, set_id, key)?);
        self.remember(user, Arc::clone(&snap));
        Ok(snap)
    }

    /// Ref-shaped load for mutations. Format-2 pair texts use `[IMAGE:img:…]`.
    /// Compatibility DTO: logically shaped, cloned out of the cached entry.
    pub fn load_logical(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        Ok(Arc::unwrap_or_clone(self.load_snapshot_cached(&user, set_id, key)?).into_snapshot())
    }

    pub fn load_page(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
        limit: Option<usize>,
        before: Option<usize>,
        thumbnails: bool,
    ) -> Result<crate::history::types::SetPage, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.ensure_chunked(&user, set_id, key)?;
        Ok(self
            .store
            .load_page(&user, set_id, key, limit, before, thumbnails)?)
    }

    pub fn load_pair(
        &self,
        user: &str,
        set_id: SetId,
        pair_index: usize,
        key: &EncryptionKey,
    ) -> Result<(SetVersion, crate::history::types::HistoryPair), HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.ensure_chunked(&user, set_id, key)?;
        Ok(self.store.load_pair(&user, set_id, pair_index, key)?)
    }

    pub fn load_image(
        &self,
        user: &str,
        set_id: SetId,
        pair_index: usize,
        image_index: usize,
        key: &EncryptionKey,
    ) -> Result<(String, Vec<u8>), HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.ensure_chunked(&user, set_id, key)?;
        Ok(self
            .store
            .load_image(&user, set_id, pair_index, image_index, key)?)
    }

    pub fn load_thumb(
        &self,
        user: &str,
        set_id: SetId,
        pair_index: usize,
        image_index: usize,
        key: &EncryptionKey,
    ) -> Result<(String, Vec<u8>), HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.ensure_chunked(&user, set_id, key)?;
        Ok(self
            .store
            .load_thumb(&user, set_id, pair_index, image_index, key)?)
    }

    /// Test/helper: open a fresh service at a path without touching the process global.
    pub fn open_ephemeral(path: impl AsRef<Path>) -> Result<Self, HistoryError> {
        let path = path.as_ref();
        let data_dir = path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self::open_with_data_dir(path, data_dir, "You are a helpful assistant.")
    }

    pub fn db_path(&self) -> &Path {
        self.store.path()
    }

    fn ensure_migrated(&self, user: &str, key: &EncryptionKey) -> Result<(), HistoryError> {
        migration::ensure_user_migrated(
            &self.store,
            &self.data_dir,
            &self.default_system_prompt,
            user,
            key,
        )
        .map_err(HistoryError::from)
    }

    // --- reads ---

    pub fn list_sets(
        &self,
        user: &str,
        key: &EncryptionKey,
    ) -> Result<Vec<SetSummary>, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let ids = self.store.list_set_ids(&user)?;
        let mut out = Vec::with_capacity(ids.len());
        for (set_id, updated_at) in ids {
            if let Some(summary) = self.summary_of(&user, set_id, Some(updated_at), key)? {
                out.push(summary);
            }
        }
        Ok(out)
    }

    /// One owned set's summary from its meta, policy and name rows; history is
    /// opened only to backfill a missing name row. `None` for a foreign set.
    fn summary_of(
        &self,
        user: &str,
        set_id: SetId,
        updated_at: Option<u64>,
        key: &EncryptionKey,
    ) -> Result<Option<SetSummary>, HistoryError> {
        let (meta, privacy_level) = match self.store.load_meta_policy(user, set_id, key) {
            Ok(value) => value,
            Err(StoreError::Forbidden) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let updated_at = updated_at.unwrap_or(meta.updated_at);
        if let Some(summary) =
            self.cache
                .get_summary_if_version(user, set_id, meta.version, updated_at)
        {
            return Ok(Some(summary));
        }
        let display_name = match self.store.load_display_name(user, set_id, key) {
            Ok(name) => name,
            Err(StoreError::NotFound) => {
                // Pre-name-row sets: decrypt the snapshot once and persist the name.
                match self.store.load_snapshot(user, set_id, key) {
                    Ok(snap) => {
                        if let Err(err) =
                            self.store
                                .put_display_name(user, set_id, &snap.display_name, key)
                        {
                            return Err(err.into());
                        }
                        snap.display_name
                    }
                    Err(StoreError::DecryptFailed) => return Err(HistoryError::DecryptFailed),
                    Err(StoreError::Forbidden) => return Ok(None),
                    Err(err) => return Err(err.into()),
                }
            }
            Err(StoreError::DecryptFailed) => return Err(HistoryError::DecryptFailed),
            Err(StoreError::Forbidden) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let summary = SetSummary {
            set_id,
            version: meta.version,
            display_name,
            updated_at,
            is_default: meta.is_default,
            privacy_level,
        };
        self.cache.put_summary(user, &summary);
        Ok(Some(summary))
    }

    /// Summary of one owned set, read without loading its history.
    pub fn set_summary(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSummary, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.summary_of(&user, set_id, None, key)?
            .ok_or(HistoryError::Forbidden)
    }

    pub fn load(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        // Cache holds logical (ref) snapshots; materialize a copy for compat readers.
        let logical = self.load_snapshot_cached(&user, set_id, key)?;
        Ok(self.store.materialize_snapshot(&user, &logical, key)?)
    }

    /// Ownership check from the set's plaintext meta row; opens nothing.
    pub fn ensure_owned(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<(), HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        self.store.load_meta(&user, set_id)?;
        Ok(())
    }

    /// Durable privacy policy of an owned set, read without loading its history.
    pub fn privacy_level(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<PrivacyLevel, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        Ok(self.store.load_meta_policy(&user, set_id, key)?.1)
    }

    /// Resolve display name → set_id for transition shims (decrypts all sets).
    pub fn find_by_display_name(
        &self,
        user: &str,
        display_name: &str,
        key: &EncryptionKey,
    ) -> Result<Option<SetSnapshot>, HistoryError> {
        match self.find_summary_by_display_name(user, display_name, key)? {
            Some(summary) => Ok(Some(self.load(user, summary.set_id, key)?)),
            None => Ok(None),
        }
    }

    /// Resolve display name → summary without loading any set's history.
    pub fn find_summary_by_display_name(
        &self,
        user: &str,
        display_name: &str,
        key: &EncryptionKey,
    ) -> Result<Option<SetSummary>, HistoryError> {
        let want = display_name.trim();
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        for (set_id, updated_at) in self.store.list_set_ids(&user)? {
            let name = match self.store.load_display_name(&user, set_id, key) {
                Ok(name) => name,
                Err(StoreError::NotFound) => {
                    // Older rows have no separate name record; preserve their
                    // migration/backfill behavior before continuing the scan.
                    let Some(summary) = self.summary_of(&user, set_id, Some(updated_at), key)? else {
                        continue;
                    };
                    if summary.display_name == want {
                        return Ok(Some(summary));
                    }
                    continue;
                }
                Err(StoreError::Forbidden) => continue,
                Err(err) => return Err(err.into()),
            };
            if name == want {
                if let Some(summary) = self.summary_of(&user, set_id, Some(updated_at), key)? {
                    return Ok(Some(summary));
                }
            }
        }
        Ok(None)
    }

    // --- lifecycle ---

    pub fn create_set(
        &self,
        user: &str,
        display_name: &str,
        key: &EncryptionKey,
    ) -> Result<SetSummary, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;

        let lock_entry = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Empty name = low-friction auto placeholder (`New Chat`, `New Chat 2`, ...).
        let name = display_name.trim();
        let effective: String = if name.is_empty() {
            let existing = self
                .list_sets(&user, key)?
                .into_iter()
                .map(|s| s.display_name)
                .collect::<Vec<_>>();
            ops::dedup_name(ops::AUTO_NEW_CHAT_PREFIX, |c| {
                existing.iter().any(|e| e == c)
            })
        } else {
            // Reached only with a non-empty trimmed name; no second check needed.
            name.to_owned()
        };

        // Uniqueness among decrypted names (under per-user lock to close concurrent races).
        self.ensure_display_name_available(&user, &effective, None, key)?;

        let set_id = SetId::new();
        let is_default = effective == "default";
        let summary = self.store.create_set(
            &user,
            set_id,
            &effective,
            &self.default_system_prompt,
            is_default,
            key,
        )?;
        // Cache an empty snapshot without a second redb decrypt round-trip.
        // Imageless, so trivially in durable-normalized form.
        let snap = SetSnapshot {
            set_id: summary.set_id,
            version: summary.version,
            display_name: summary.display_name.clone(),
            memory: String::new(),
            system_prompt: self.default_system_prompt.clone(),
            history: Vec::new(),
            pair_ids: Vec::new(),
            is_default: summary.is_default,
            privacy_level: summary.privacy_level,
        };
        self.remember(&user, LogicalSnapshot::from_normalized(snap));
        self.cache.put_summary(&user, &summary);
        Ok(summary)
    }

    /// Fork a prefix of `source_set_id` (inclusive `up_to_pair_index`) into a new set.
    ///
    /// Copies memory, system prompt, and history pairs with full fidelity (stored
    /// image and thumb payloads re-sealed under the new set id, never decoded).
    /// The source set is untouched. `new_name`
    /// empty/None auto-derives `<source> - branch` (deduped). CAS-checked against
    /// `expected` when supplied.
    pub fn fork_set(
        &self,
        user: &str,
        source_set_id: SetId,
        expected: Option<SetVersion>,
        up_to_pair_index: usize,
        new_name: Option<&str>,
        key: &EncryptionKey,
    ) -> Result<SetSummary, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let source = self.fork_source(&user, source_set_id, key)?;
        if let Some(exp) = expected {
            if source.version != exp {
                return Err(HistoryError::Conflict {
                    current_version: source.version,
                });
            }
        }
        if up_to_pair_index >= source.pair_count {
            return Err(HistoryError::InvalidInput("pair_index out of range"));
        }

        let lock_entry = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let name = self.fork_name(&user, &source.summary.display_name, new_name, key)?;
        let spec = ForkSpec {
            set_id: SetId::new(),
            version: SetVersion(2),
            display_name: &name,
            privacy_level: source.summary.privacy_level,
        };
        let summary = self.store.create_chunked_fork(
            &user,
            source_set_id,
            source.version,
            up_to_pair_index + 1,
            &spec,
            key,
            None,
        )?;
        self.remember_fork(&user, &source, up_to_pair_index + 1, &summary);
        Ok(summary)
    }

    /// What a fork needs from its source: meta, name and policy only. No
    /// history payload is opened.
    fn fork_source(
        &self,
        user: &str,
        source_id: SetId,
        key: &EncryptionKey,
    ) -> Result<ForkSource, HistoryError> {
        self.ensure_chunked(user, source_id, key)?;
        let meta = self.store.load_meta(user, source_id)?;
        let summary = self
            .summary_of(user, source_id, None, key)?
            .ok_or(HistoryError::Forbidden)?;
        Ok(ForkSource {
            set_id: source_id,
            version: meta.version,
            pair_count: meta.pair_count.unwrap_or(0) as usize,
            summary,
        })
    }

    /// Requested or `<source> - branch` name, deduped among the user's sets.
    fn fork_name(
        &self,
        user: &str,
        source_name: &str,
        new_name: Option<&str>,
        key: &EncryptionKey,
    ) -> Result<String, HistoryError> {
        let base = match new_name.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name) => {
                if name.eq_ignore_ascii_case("default") {
                    return Err(HistoryError::InvalidInput("empty set name"));
                }
                if name.chars().count() > ops::MAX_DISPLAY_NAME_CHARS {
                    return Err(HistoryError::InvalidInput("set name too large"));
                }
                name.to_owned()
            }
            None => ops::branch_name_for(source_name),
        };
        let existing = self.list_sets(user, key)?;
        Ok(ops::dedup_name(&base, |name| {
            existing.iter().any(|set| set.display_name == name)
        }))
    }

    /// Cache the fork's logical shape when the source's is already cached.
    fn remember_fork(&self, user: &str, source: &ForkSource, pair_count: usize, summary: &SetSummary) {
        if let Some(cached) = self
            .cache
            .get_snapshot_if_version(user, source.set_id, source.version)
        {
            let src = cached.as_snapshot();
            if src.history.len() >= pair_count && src.pair_ids.len() >= pair_count {
                self.remember(
                    user,
                    LogicalSnapshot::from_normalized(SetSnapshot {
                        set_id: summary.set_id,
                        version: summary.version,
                        display_name: summary.display_name.clone(),
                        memory: src.memory.clone(),
                        system_prompt: src.system_prompt.clone(),
                        history: src.history[..pair_count].to_vec(),
                        pair_ids: src.pair_ids[..pair_count].to_vec(),
                        is_default: false,
                        privacy_level: summary.privacy_level,
                    }),
                );
            }
        }
        self.cache.put_summary(user, summary);
    }

    pub fn with_receipt_clock(mut self, clock: Arc<dyn ReceiptClock>) -> Self {
        self.receipt_clock = clock;
        self
    }

    pub fn fork_receipt(
        &self,
        user: &str,
        request: &OperationRequest,
        key: &EncryptionKey,
    ) -> Result<Option<Receipt>, HistoryError> {
        let user = normalise_user(user)?;
        let receipt =
            self.store
                .fork_receipt(&user, request, key, self.receipt_clock.now_secs())?;
        if let Some(receipt) = &receipt {
            if !receipt.matches(request) {
                return Err(HistoryError::InvalidInput("operation_id_reused"));
            }
        }
        Ok(receipt)
    }

    pub fn version_conflict_body(set_id: SetId, current_version: SetVersion) -> serde_json::Value {
        serde_json::json!({
            "error": "version_conflict",
            "set_id": set_id.to_string(),
            "current_version": current_version.get(),
            "message": "Set was modified; syncing latest version."
        })
    }

    pub fn fork_operation(
        &self,
        user: &str,
        source_id: SetId,
        expected: Option<SetVersion>,
        pair_index: usize,
        new_name: Option<&str>,
        key: &EncryptionKey,
        request: &OperationRequest,
    ) -> Result<Receipt, HistoryError> {
        let now = self.receipt_clock.now_secs();
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let lock = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(receipt) = self.store.fork_receipt(&user, request, key, now)? {
            if !receipt.matches(request) {
                return Err(HistoryError::InvalidInput("operation_id_reused"));
            }
            return Ok(receipt);
        }
        let source = self.fork_source(&user, source_id, key)?;
        let rejection = if expected.is_some_and(|expected| source.version != expected) {
            Some((409, Self::version_conflict_body(source_id, source.version)))
        } else if pair_index >= source.pair_count {
            Some((
                404,
                serde_json::json!({"status":"error","error":"pair_index out of range"}),
            ))
        } else {
            None
        };
        if let Some((status, body)) = rejection {
            let receipt = Receipt::new(
                request,
                ReceiptOutcome::Rejected,
                status,
                serde_json::to_vec(&body).map_err(|_| HistoryError::Internal)?,
                now,
            );
            self.store.record_fork_rejection(&user, key, &receipt)?;
            return Ok(receipt);
        }
        let name = match self.fork_name(&user, &source.summary.display_name, new_name, key) {
            Ok(name) => name,
            Err(HistoryError::InvalidInput(message)) => {
                let body = serde_json::json!({"status":"error","error":message});
                let receipt = Receipt::new(
                    request,
                    ReceiptOutcome::Rejected,
                    400,
                    serde_json::to_vec(&body).map_err(|_| HistoryError::Internal)?,
                    now,
                );
                self.store.record_fork_rejection(&user, key, &receipt)?;
                return Ok(receipt);
            }
            Err(error) => return Err(error),
        };
        let spec = ForkSpec {
            set_id: SetId::new(),
            version: SetVersion(2),
            display_name: &name,
            privacy_level: source.summary.privacy_level,
        };
        let body = serde_json::to_vec(&serde_json::json!({"status":"success", "set_id":spec.set_id.to_string(), "name":spec.display_name, "version":spec.version.get(), "privacy_level":spec.privacy_level})).map_err(|_| HistoryError::Internal)?;
        let receipt = Receipt::new(request, ReceiptOutcome::Applied, 200, body, now);
        let summary = self.store.create_chunked_fork(
            &user,
            source_id,
            source.version,
            pair_index + 1,
            &spec,
            key,
            Some(&receipt),
        )?;
        self.remember_fork(&user, &source, pair_index + 1, &summary);
        Ok(receipt)
    }

    /// Ensure a default set exists (empty history). Returns its snapshot.
    pub fn ensure_default_set(
        &self,
        user: &str,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, HistoryError> {
        let set_id = self.ensure_default_set_id(user, key)?;
        self.load(user, set_id, key)
    }

    /// The user's default set, created when missing, without loading it.
    pub fn ensure_default_set_id(
        &self,
        user: &str,
        key: &EncryptionKey,
    ) -> Result<SetId, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;

        // Serialize with the other per-user name mutations. Migration remains
        // outside this lock, and creation below goes straight to the store so
        // this non-reentrant mutex is not reacquired through `create_set`.
        let lock_entry = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for summary in self.list_sets(&user, key)? {
            if summary.is_default || summary.display_name == "default" {
                return Ok(summary.set_id);
            }
        }
        #[cfg(test)]
        if let Some(hook) = &self.default_set_after_check {
            hook();
        }
        let summary = self.store.create_set(
            &user,
            SetId::new(),
            "default",
            &self.default_system_prompt,
            true,
            key,
        )?;
        Ok(summary.set_id)
    }

    /// One stored image as a data URL for a model prompt; a missing
    /// thumbnail falls back to the full image. `None` when absent or unreadable.
    pub fn stored_image_data_url(
        &self,
        user: &str,
        set_id: SetId,
        image_id: ImageId,
        fidelity: ImageFidelity,
        key: &EncryptionKey,
    ) -> Option<String> {
        let user = normalise_user(user).ok()?;
        if fidelity == ImageFidelity::Thumb {
            if let Ok(Some((mime, bytes))) = self.store.load_thumb_by_id(&user, set_id, image_id, key) {
                return Some(encode_data_url(&mime, &bytes));
            }
        }
        let image = self.store.load_image_by_id(&user, set_id, image_id, key).ok()??;
        Some(encode_data_url(&image.mime, &image.bytes))
    }

    /// Replace `[IMAGE:img:…]` refs in one stored message with full-resolution
    /// data URLs (missing images become `[IMAGE:unavailable]`).
    pub fn materialize_message(
        &self,
        user: &str,
        set_id: SetId,
        text: &str,
        key: &EncryptionKey,
    ) -> Result<String, HistoryError> {
        let refs = collect_image_refs(text);
        if refs.is_empty() {
            return Ok(text.to_owned());
        }
        let user = normalise_user(user)?;
        let mut images = HashMap::new();
        for id in refs {
            if let Some(image) = self.store.load_image_by_id(&user, set_id, id, key)? {
                images.insert(id, (image.mime, image.bytes));
            }
        }
        Ok(materialize_full(text, &images))
    }

    pub fn rename_set(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        new_name: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;

        let lock_entry = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let snap = self.load_snapshot_cached(&user, set_id, key)?;
        let snap_ref = snap.as_snapshot();
        if snap_ref.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap_ref.version,
            });
        }
        if snap_ref.is_default {
            return Err(HistoryError::InvalidInput("cannot rename default set"));
        }
        let next = ops::rename(snap_ref, new_name)?;
        // Reject collision with any other set (same name on self is a no-op rename).
        self.ensure_display_name_available(&user, &next.display_name, Some(set_id), key)?;
        let (v, committed) = self.commit(&user, expected, next, key)?;
        self.remember(&user, committed);
        Ok(v)
    }

    /// Returns `Ok` if `name` is free, or already owned by `except_set_id`.
    fn ensure_display_name_available(
        &self,
        user: &str,
        name: &str,
        except_set_id: Option<SetId>,
        key: &EncryptionKey,
    ) -> Result<(), HistoryError> {
        for existing in self.list_sets(user, key)? {
            if existing.display_name == name {
                if except_set_id == Some(existing.set_id) {
                    return Ok(());
                }
                return Err(HistoryError::InvalidInput("set already exists"));
            }
        }
        Ok(())
    }

    pub fn delete_set(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        key: &EncryptionKey,
    ) -> Result<(), HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        // Verify ownership + decrypt access (key valid) before delete
        let snap = self.load_snapshot_cached(&user, set_id, key)?;
        let snap_ref = snap.as_snapshot();
        if snap_ref.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap_ref.version,
            });
        }
        if snap_ref.is_default {
            return Err(HistoryError::InvalidInput("cannot delete default set"));
        }
        self.store.delete_set(&user, set_id, expected)?;
        self.cache.invalidate(&user, set_id);
        Ok(())
    }

    pub fn change_privacy_level(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        level: PrivacyLevel,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let version = self
            .store
            .change_policy(&user, set_id, expected, level, key)?;
        self.cache.invalidate(&user, set_id);
        Ok(version)
    }

    // --- content mutations (all CAS) ---

    pub fn append_pair(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        user_msg: &str,
        assistant_msg: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.load_snapshot_cached(&user, set_id, key)?;
        let snap_ref = snap.as_snapshot();
        if snap_ref.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap_ref.version,
            });
        }
        let mut next = ops::append_pair(snap_ref, user_msg, assistant_msg)?;
        self.auto_name_first_turn(
            &user,
            snap_ref.history.is_empty(),
            snap_ref.set_id,
            &snap_ref.display_name,
            user_msg,
            key,
            &mut next,
        )?;
        let (v, committed) = self.commit(&user, expected, next, key)?;
        self.remember(&user, committed);
        Ok(v)
    }

    /// Commit chat finalize from an immutable prepare capture (ignores live cache content).
    pub fn commit_chat_append(
        &self,
        user: &str,
        capture: &PrepareCapture,
        user_msg: &str,
        assistant_msg: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let mut next = ops::apply_chat_append(capture, user_msg, assistant_msg)?;
        // First message in an auto placeholder (`New Chat`) adopts a contextual
        // name in the same CAS commit — one version bump, no extra round-trip.
        self.auto_name_first_turn(
            &user,
            capture.history.is_empty(),
            capture.set_id,
            &capture.display_name,
            user_msg,
            key,
            &mut next,
        )?;
        let (v, committed) = self
            .commit(&user, capture.version, next, key)?;
        self.remember(&user, committed);
        Ok(v)
    }

    fn auto_name_first_turn(
        &self,
        user: &str,
        history_is_empty: bool,
        set_id: SetId,
        display_name: &str,
        user_msg: &str,
        key: &EncryptionKey,
        next: &mut SetSnapshot,
    ) -> Result<(), HistoryError> {
        if history_is_empty && ops::is_auto_placeholder_name(display_name) {
            let derived = ops::derive_chat_name_from_message(user_msg);
            if derived != display_name
                && !derived.eq_ignore_ascii_case("default")
                && !ops::is_auto_placeholder_name(&derived)
            {
                let existing = self
                    .list_sets(user, key)?
                    .into_iter()
                    .filter(|s| s.set_id != set_id)
                    .map(|s| s.display_name)
                    .collect::<Vec<_>>();
                next.display_name = if existing.iter().any(|e| e == &derived) {
                    ops::dedup_name(&derived, |c| existing.iter().any(|e| e == c))
                } else {
                    derived
                };
            }
        }
        Ok(())
    }

    /// Commit regenerate/edit from prepare capture.
    pub fn commit_regenerate(
        &self,
        user: &str,
        capture: &PrepareCapture,
        assistant_response: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let next = ops::apply_regenerate(capture, assistant_response)?;
        let (v, committed) = self
            .commit(&user, capture.version, next, key)?;
        self.remember(&user, committed);
        Ok(v)
    }

    pub fn delete_pair(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        pair_index: usize,
        expected_user_msg: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        self.mutate_content(user, set_id, expected, key, |snap| {
            Ok(ops::delete_pair(
                Arc::unwrap_or_clone(snap).into_snapshot(),
                pair_index,
                expected_user_msg,
            )?)
        })
    }

    pub fn reset_history(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        self.mutate_content(user, set_id, expected, key, |snap| {
            Ok(ops::reset_history(Arc::unwrap_or_clone(snap).into_snapshot()))
        })
    }

    pub fn update_memory(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        memory: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        self.mutate_content(user, set_id, expected, key, |snap| {
            Ok(ops::update_memory(snap.as_snapshot(), memory)?)
        })
    }

    pub fn update_system_prompt(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        prompt: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        self.mutate_content(user, set_id, expected, key, |snap| {
            Ok(ops::update_system_prompt(snap.as_snapshot(), prompt)?)
        })
    }

    fn mutate_content(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        key: &EncryptionKey,
        operation: impl FnOnce(Arc<LogicalSnapshot>) -> Result<SetSnapshot, HistoryError>,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.load_snapshot_cached(&user, set_id, key)?;
        let snap_ref = snap.as_snapshot();
        if snap_ref.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap_ref.version,
            });
        }
        let next = operation(snap)?;
        let (v, committed) = self.commit(&user, expected, next, key)?;
        self.remember(&user, committed);
        Ok(v)
    }

    #[cfg(test)]
    pub fn test_chunk_ciphertexts(
        &self,
        set_id: SetId,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), HistoryError> {
        self.store
            .test_chunk_ciphertexts(set_id)
            .map_err(HistoryError::from)
    }

    #[cfg(test)]
    pub fn test_remove_history_blob(&self, user: &str, set_id: SetId) -> Result<(), HistoryError> {
        self.store
            .test_remove_history_blob(user, set_id)
            .map_err(HistoryError::from)
    }

    #[cfg(test)]
    pub fn test_remove_name_blob(&self, user: &str, set_id: SetId) -> Result<(), HistoryError> {
        self.store
            .test_remove_name_blob(user, set_id)
            .map_err(HistoryError::from)
    }

    /// Build a prepare capture from durable state (source of truth).
    pub fn prepare_capture(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<PrepareCapture, HistoryError> {
        let snap = self.load(user, set_id, key)?;
        Ok(PrepareCapture::from_snapshot(&snap))
    }
}

fn normalise_user(user: &str) -> Result<String, HistoryError> {
    let trimmed = user.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(HistoryError::InvalidInput("invalid username"));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PrivacyLevel;
    use crate::history::ops::apply_chat_append;

    fn key() -> EncryptionKey {
        EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
            .unwrap()
    }

    #[test]
    fn service_create_list_append_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();

        let created = svc.create_set("bob", "work", &key).unwrap();
        let listed = svc.list_sets("bob", &key).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].display_name, "work");

        let v = svc
            .append_pair("bob", created.set_id, created.version, "hi", "hello", &key)
            .unwrap();
        assert_eq!(v, SetVersion(2));

        let err = svc
            .append_pair(
                "bob",
                created.set_id,
                created.version,
                "stale",
                "nope",
                &key,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            HistoryError::Conflict {
                current_version: SetVersion(2)
            }
        ));
    }

    #[test]
    fn privacy_change_is_versioned_cached_and_inherited_by_fork() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("policy.redb")).unwrap();
        let key = key();
        let created = svc.create_set("policy-user", "source", &key).unwrap();
        let v2 = svc
            .append_pair(
                "policy-user",
                created.set_id,
                created.version,
                "question",
                "answer",
                &key,
            )
            .unwrap();
        let v3 = svc
            .change_privacy_level(
                "policy-user",
                created.set_id,
                v2,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();
        assert_eq!(v3, SetVersion(3));
        assert_eq!(
            svc.change_privacy_level(
                "policy-user",
                created.set_id,
                v3,
                PrivacyLevel::NonPrivate,
                &key
            )
            .unwrap(),
            v3
        );
        assert!(matches!(
            svc.change_privacy_level(
                "policy-user",
                created.set_id,
                v2,
                PrivacyLevel::Private,
                &key
            ),
            Err(HistoryError::Conflict {
                current_version: SetVersion(3)
            })
        ));
        let listed = svc.list_sets("policy-user", &key).unwrap();
        assert_eq!(listed[0].privacy_level, PrivacyLevel::NonPrivate);
        assert_eq!(
            svc.load("policy-user", created.set_id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::NonPrivate
        );
        let fork = svc
            .fork_set("policy-user", created.set_id, Some(v3), 0, None, &key)
            .unwrap();
        assert_eq!(fork.privacy_level, PrivacyLevel::NonPrivate);
        assert_eq!(
            svc.load("policy-user", fork.set_id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::NonPrivate
        );
    }

    #[test]
    fn privacy_policy_listing_refreshes_warm_and_reopened_caches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-list.redb");
        let key = key();
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let created = svc.create_set("policy-list", "chat", &key).unwrap();
        let warm = svc.list_sets("policy-list", &key).unwrap();
        assert_eq!(warm[0].privacy_level, PrivacyLevel::Private);
        let next = svc
            .change_privacy_level(
                "policy-list",
                created.set_id,
                created.version,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();
        let changed = svc.list_sets("policy-list", &key).unwrap();
        assert_eq!(changed[0].version, next);
        assert_eq!(changed[0].privacy_level, PrivacyLevel::NonPrivate);
        drop(svc);

        let reopened = HistoryService::open_ephemeral(&path).unwrap();
        let cold = reopened.list_sets("policy-list", &key).unwrap();
        assert_eq!(cold[0].version, next);
        assert_eq!(cold[0].privacy_level, PrivacyLevel::NonPrivate);
    }

    #[test]
    fn policy_change_and_load_work_for_chunked_sets() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("chunk-policy.redb")).unwrap();
        let key = key();
        let created = svc.create_set("chunk-policy", "chat", &key).unwrap();
        let v2 = svc
            .append_pair(
                "chunk-policy",
                created.set_id,
                created.version,
                "u",
                "a",
                &key,
            )
            .unwrap();
        svc.ensure_chunked("chunk-policy", created.set_id, &key)
            .unwrap();
        let v3 = svc
            .change_privacy_level(
                "chunk-policy",
                created.set_id,
                v2,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();
        let page = svc
            .load_page("chunk-policy", created.set_id, &key, Some(10), None, true)
            .unwrap();
        assert_eq!(page.version, v3);
        assert_eq!(page.privacy_level, PrivacyLevel::NonPrivate);
        assert_eq!(
            svc.load("chunk-policy", created.set_id, &key)
                .unwrap()
                .history,
            vec![("u".into(), "a".into())]
        );
    }

    #[test]
    fn standard_policy_changes_are_versioned_and_projected_by_list_load_and_page() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("standard-policy.redb");
        let key = key();
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let created = svc.create_set("standard-user", "chat", &key).unwrap();
        let v2 = svc
            .append_pair(
                "standard-user",
                created.set_id,
                created.version,
                "u",
                "a",
                &key,
            )
            .unwrap();
        let v3 = svc
            .change_privacy_level(
                "standard-user",
                created.set_id,
                v2,
                PrivacyLevel::Standard,
                &key,
            )
            .unwrap();
        assert_eq!(v3, SetVersion(3));
        assert!(matches!(
            svc.change_privacy_level(
                "standard-user",
                created.set_id,
                v2,
                PrivacyLevel::Private,
                &key
            ),
            Err(HistoryError::Conflict {
                current_version: SetVersion(3)
            })
        ));
        assert_eq!(
            svc.list_sets("standard-user", &key).unwrap()[0].privacy_level,
            PrivacyLevel::Standard
        );
        assert_eq!(
            svc.load("standard-user", created.set_id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::Standard
        );
        let page = svc
            .load_page("standard-user", created.set_id, &key, Some(1), None, true)
            .unwrap();
        assert_eq!(page.version, v3);
        assert_eq!(page.privacy_level, PrivacyLevel::Standard);
        assert_eq!(
            svc.change_privacy_level(
                "standard-user",
                created.set_id,
                v3,
                PrivacyLevel::Standard,
                &key
            )
            .unwrap(),
            v3
        );
        drop(svc);

        let reopened = HistoryService::open_ephemeral(&path).unwrap();
        assert_eq!(
            reopened.list_sets("standard-user", &key).unwrap()[0].privacy_level,
            PrivacyLevel::Standard
        );
        assert_eq!(
            reopened
                .load("standard-user", created.set_id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::Standard
        );
        assert_eq!(
            reopened
                .load_page("standard-user", created.set_id, &key, Some(1), None, true)
                .unwrap()
                .privacy_level,
            PrivacyLevel::Standard
        );

        let v4 = reopened
            .change_privacy_level(
                "standard-user",
                created.set_id,
                v3,
                PrivacyLevel::NonPrivate,
                &key,
            )
            .unwrap();
        assert_eq!(v4, SetVersion(4));
        let v5 = reopened
            .change_privacy_level(
                "standard-user",
                created.set_id,
                v4,
                PrivacyLevel::Standard,
                &key,
            )
            .unwrap();
        assert_eq!(v5, SetVersion(5));
        let v6 = reopened
            .change_privacy_level(
                "standard-user",
                created.set_id,
                v5,
                PrivacyLevel::Private,
                &key,
            )
            .unwrap();
        assert_eq!(v6, SetVersion(6));
        assert_eq!(
            reopened
                .load("standard-user", created.set_id, &key)
                .unwrap()
                .privacy_level,
            PrivacyLevel::Private
        );
    }

    #[test]
    fn commit_chat_append_preserves_image_data_url_payload() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("img-user", "vision", &key).unwrap();
        let snap = svc.load("img-user", created.set_id, &key).unwrap();
        let capture = PrepareCapture::from_snapshot(&snap);

        // Larger than the old 1M-char ops limit; still under the 5 MiB chat body.
        let image_msg = format!(
            "describe\n[IMAGE:data:image/png;base64,{}]",
            "B".repeat(1_200_000)
        );
        let new_v = svc
            .commit_chat_append("img-user", &capture, &image_msg, "a cat", &key)
            .unwrap();
        assert_eq!(new_v, SetVersion(2));

        let reloaded = svc.load("img-user", created.set_id, &key).unwrap();
        assert_eq!(reloaded.history.len(), 1);
        assert_eq!(reloaded.history[0].0, image_msg);
        assert_eq!(reloaded.history[0].1, "a cat");
        assert!(reloaded.history[0]
            .0
            .contains("[IMAGE:data:image/png;base64,"));
    }

    #[test]
    fn prepare_capture_finalize_survives_wrong_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();

        let a = svc.create_set("carol", "set-a", &key).unwrap();
        svc.append_pair("carol", a.set_id, a.version, "a1", "r1", &key)
            .unwrap();
        let snap_a = svc.load("carol", a.set_id, &key).unwrap();
        let capture = PrepareCapture::from_snapshot(&snap_a);

        // Create another set and pretend live RAM switched to it
        let b = svc.create_set("carol", "set-b", &key).unwrap();
        svc.append_pair("carol", b.set_id, b.version, "only-b", "x", &key)
            .unwrap();

        // Finalize must write to set-a from capture, not whatever is "live"
        let built = apply_chat_append(&capture, "a2", "r2").unwrap();
        assert_eq!(built.set_id, a.set_id);
        assert_eq!(built.history.len(), 2);
        assert_eq!(built.history[0].0, "a1");

        let new_v = svc
            .commit_chat_append("carol", &capture, "a2", "r2", &key)
            .unwrap();
        assert_eq!(new_v, SetVersion(3));

        let reloaded = svc.load("carol", a.set_id, &key).unwrap();
        assert_eq!(reloaded.history.len(), 2);
        assert_eq!(reloaded.history[1], ("a2".into(), "r2".into()));

        let set_b = svc.load("carol", b.set_id, &key).unwrap();
        assert_eq!(set_b.history.len(), 1);
        assert_eq!(set_b.history[0].0, "only-b");
    }

    #[test]
    fn stale_capture_finalize_returns_conflict_without_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("dave", "chat", &key).unwrap();
        let snap = svc.load("dave", created.set_id, &key).unwrap();
        let stale_capture = PrepareCapture::from_snapshot(&snap);

        // Another writer advances version
        svc.append_pair("dave", created.set_id, created.version, "first", "ok", &key)
            .unwrap();
        let after = svc.load("dave", created.set_id, &key).unwrap();
        assert_eq!(after.version, SetVersion(2));
        assert_eq!(after.history.len(), 1);

        let err = svc
            .commit_chat_append("dave", &stale_capture, "stale", "nope", &key)
            .unwrap_err();
        assert!(matches!(
            err,
            HistoryError::Conflict {
                current_version: SetVersion(2)
            }
        ));

        let final_snap = svc.load("dave", created.set_id, &key).unwrap();
        assert_eq!(final_snap.history.len(), 1);
        assert_eq!(final_snap.history[0].0, "first");
    }

    #[test]
    fn regenerate_commit_replaces_pair_without_dropping_later() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("erin", "chat", &key).unwrap();
        let mut v = created.version;
        for (u, a) in [("u1", "a1"), ("u2", "a2"), ("u3", "a3")] {
            v = svc
                .append_pair("erin", created.set_id, v, u, a, &key)
                .unwrap();
        }
        let snap = svc.load("erin", created.set_id, &key).unwrap();
        assert_eq!(snap.history.len(), 3);
        let capture = PrepareCapture::from_snapshot(&snap).with_regenerate(1, "u2-edit");
        // Non-destructive: capture still has 3 pairs
        assert_eq!(capture.history.len(), 3);
        assert_eq!(capture.context_history_for_model().len(), 1);

        let new_v = svc
            .commit_regenerate("erin", &capture, "new-a2", &key)
            .unwrap();
        assert_eq!(new_v, SetVersion(5));
        let after = svc.load("erin", created.set_id, &key).unwrap();
        assert_eq!(after.history.len(), 3);
        assert_eq!(after.history[1], ("u2-edit".into(), "new-a2".into()));
        assert_eq!(after.history[2].0, "u3");
    }

    #[test]
    fn delete_pair_content_mismatch_and_reset() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("frank", "chat", &key).unwrap();
        let v = svc
            .append_pair(
                "frank",
                created.set_id,
                created.version,
                "hello",
                "hi",
                &key,
            )
            .unwrap();
        let err = svc
            .delete_pair("frank", created.set_id, v, 0, "wrong", &key)
            .unwrap_err();
        assert!(matches!(err, HistoryError::InvalidInput(_)));

        let v2 = svc
            .delete_pair("frank", created.set_id, v, 0, "hello", &key)
            .unwrap();
        let empty = svc.load("frank", created.set_id, &key).unwrap();
        assert!(empty.history.is_empty());

        let v3 = svc
            .append_pair("frank", created.set_id, v2, "again", "ok", &key)
            .unwrap();
        let v4 = svc
            .reset_history("frank", created.set_id, v3, &key)
            .unwrap();
        let reset = svc.load("frank", created.set_id, &key).unwrap();
        assert!(reset.history.is_empty());
        assert_eq!(reset.version, v4);
    }

    /// Client deletes from the top of a loaded set: after pair 0 is removed, remaining
    /// pairs shift down. Each call must use the version returned by the previous delete.
    #[test]
    fn sequential_delete_pair_from_front_advances_version() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("seqdel", "chat", &key).unwrap();
        let mut v = created.version;
        for (u, a) in [("first", "a1"), ("second", "a2"), ("third", "a3")] {
            v = svc
                .append_pair("seqdel", created.set_id, v, u, a, &key)
                .unwrap();
        }
        for expected_user in ["first", "second", "third"] {
            v = svc
                .delete_pair("seqdel", created.set_id, v, 0, expected_user, &key)
                .unwrap();
        }
        let empty = svc.load("seqdel", created.set_id, &key).unwrap();
        assert!(empty.history.is_empty());
        assert_eq!(empty.version, v);
    }

    #[test]
    fn find_by_display_name_and_ensure_default() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let def = svc.ensure_default_set("gina", &key).unwrap();
        assert!(def.is_default || def.display_name == "default");
        let found = svc
            .find_by_display_name("gina", "default", &key)
            .unwrap()
            .expect("default");
        assert_eq!(found.set_id, def.set_id);
        assert!(svc
            .find_by_display_name("gina", "missing", &key)
            .unwrap()
            .is_none());
    }

    /// Large image-bearing histories must stay fast on warm list/delete (no multi-second
    /// re-encrypt of the whole blob for cache bookkeeping).
    #[test]
    fn warm_list_and_delete_stay_fast_with_large_history() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("perf", "big", &key).unwrap();
        // ~1.2 MiB synthetic attachment (base64-like payload).
        let big_user = format!(
            "see this\n[IMAGE:data:image/jpeg;base64,{}]",
            "A".repeat(1_200_000)
        );
        let v = svc
            .append_pair(
                "perf",
                created.set_id,
                created.version,
                &big_user,
                "looks like a photo",
                &key,
            )
            .unwrap();
        // Warm caches via load.
        let _ = svc.load("perf", created.set_id, &key).unwrap();

        let t0 = std::time::Instant::now();
        for _ in 0..20 {
            let listed = svc.list_sets("perf", &key).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].display_name, "big");
        }
        let list_elapsed = t0.elapsed();
        assert!(
            list_elapsed.as_millis() < 500,
            "warm list_sets too slow: {list_elapsed:?}"
        );

        let t1 = std::time::Instant::now();
        let v2 = svc
            .delete_pair("perf", created.set_id, v, 0, &big_user, &key)
            .unwrap();
        let delete_elapsed = t1.elapsed();
        assert!(
            delete_elapsed.as_secs() < 2,
            "delete_pair with large history too slow: {delete_elapsed:?}"
        );
        let after = svc.load("perf", created.set_id, &key).unwrap();
        assert!(after.history.is_empty());
        assert_eq!(after.version, v2);

        // Second list after delete should still be warm/fast.
        let t2 = std::time::Instant::now();
        let listed = svc.list_sets("perf", &key).unwrap();
        assert_eq!(listed[0].version, v2);
        assert!(t2.elapsed().as_millis() < 100);
    }

    #[test]
    fn list_sets_does_not_open_history_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.redb");
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let key = key();
        let created = svc.create_set("owner", "secret-project", &key).unwrap();
        svc.append_pair(
            "owner",
            created.set_id,
            created.version,
            "see this\n[IMAGE:data:image/jpeg;base64,AAAA]",
            "ok",
            &key,
        )
        .unwrap();
        svc.test_remove_history_blob("owner", created.set_id)
            .unwrap();
        drop(svc);

        let cold = HistoryService::open_ephemeral(&path).unwrap();
        let listed = cold.list_sets("owner", &key).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].display_name, "secret-project");
        assert!(
            cold.load("owner", created.set_id, &key).is_err(),
            "history blob was removed; load must fail"
        );
    }

    #[test]
    fn list_sets_backfills_missing_name_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.redb");
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let key = key();
        let created = svc.create_set("owner", "needs-backfill", &key).unwrap();
        svc.test_remove_name_blob("owner", created.set_id).unwrap();
        drop(svc);

        let cold = HistoryService::open_ephemeral(&path).unwrap();
        let listed = cold.list_sets("owner", &key).unwrap();
        assert_eq!(listed[0].display_name, "needs-backfill");

        // Name row now exists: listing still works if the history blob is gone.
        cold.test_remove_history_blob("owner", created.set_id)
            .unwrap();
        drop(cold);
        let colder = HistoryService::open_ephemeral(&path).unwrap();
        let listed = colder.list_sets("owner", &key).unwrap();
        assert_eq!(listed[0].display_name, "needs-backfill");
    }

    #[test]
    fn migrate_then_update_memory_does_not_rewrite_pair_or_image_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("owner", "photos", &key).unwrap();
        let jpeg = crate::chat_images::fixture_jpeg_data_url(80, 80);
        let v = svc
            .append_pair(
                "owner",
                created.set_id,
                created.version,
                &format!("look\n[IMAGE:{jpeg}]"),
                "nice",
                &key,
            )
            .unwrap();
        let (pairs_before, images_before) = svc.test_chunk_ciphertexts(created.set_id).unwrap();
        assert!(!images_before.is_empty(), "image should be extracted");
        let v2 = svc
            .update_memory("owner", created.set_id, v, "remember this", &key)
            .unwrap();
        assert_eq!(v2.get(), v.get() + 1);
        let (pairs_after, images_after) = svc.test_chunk_ciphertexts(created.set_id).unwrap();
        assert_eq!(pairs_before, pairs_after);
        assert_eq!(images_before, images_after);
        let loaded = svc.load("owner", created.set_id, &key).unwrap();
        assert!(loaded.history[0].0.contains("data:image/jpeg"));
        assert!(!loaded.history[0].0.contains("img:"));
        let page = svc
            .load_page("owner", created.set_id, &key, Some(10), None, true)
            .unwrap();
        assert_eq!(page.history_total, 1);
        assert!(!page.history[0].0.contains("img:"));
        assert!(!page.history[0].0.contains("data:image"));
        assert!(page.history[0].0.contains("[IMAGE:]"));
    }

    #[test]
    fn append_does_not_rewrite_old_image_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("owner", "chat", &key).unwrap();
        let jpeg = crate::chat_images::fixture_jpeg_data_url(64, 64);
        let v = svc
            .append_pair(
                "owner",
                created.set_id,
                created.version,
                &format!("one\n[IMAGE:{jpeg}]"),
                "a1",
                &key,
            )
            .unwrap();
        let (_, images_before) = svc.test_chunk_ciphertexts(created.set_id).unwrap();
        svc.append_pair("owner", created.set_id, v, "just text", "a2", &key)
            .unwrap();
        let (_, images_after) = svc.test_chunk_ciphertexts(created.set_id).unwrap();
        assert_eq!(images_before, images_after);
    }

    #[test]
    fn cold_list_stays_fast_with_large_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.redb");
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let key = key();
        let created = svc.create_set("perf", "big", &key).unwrap();
        let big_user = format!(
            "see this\n[IMAGE:data:image/jpeg;base64,{}]",
            "A".repeat(1_200_000)
        );
        svc.append_pair(
            "perf",
            created.set_id,
            created.version,
            &big_user,
            "looks like a photo",
            &key,
        )
        .unwrap();
        drop(svc);

        let cold = HistoryService::open_ephemeral(&path).unwrap();
        let t0 = std::time::Instant::now();
        let listed = cold.list_sets("perf", &key).unwrap();
        let elapsed = t0.elapsed();
        assert_eq!(listed[0].display_name, "big");
        assert!(
            elapsed.as_millis() < 200,
            "cold list_sets must not decrypt the history blob: {elapsed:?}"
        );
    }

    #[test]
    fn rename_is_visible_on_cold_list_without_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.redb");
        let svc = HistoryService::open_ephemeral(&path).unwrap();
        let key = key();
        let created = svc.create_set("owner", "alpha", &key).unwrap();
        svc.rename_set("owner", created.set_id, created.version, "omega", &key)
            .unwrap();
        svc.test_remove_history_blob("owner", created.set_id)
            .unwrap();
        drop(svc);

        let cold = HistoryService::open_ephemeral(&path).unwrap();
        let listed = cold.list_sets("owner", &key).unwrap();
        assert_eq!(listed[0].display_name, "omega");
    }

    #[test]
    fn rename_rejects_duplicate_display_name() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let a = svc.create_set("uniq", "alpha", &key).unwrap();
        let b = svc.create_set("uniq", "beta", &key).unwrap();
        let err = svc
            .rename_set("uniq", b.set_id, b.version, "alpha", &key)
            .unwrap_err();
        assert!(matches!(
            err,
            HistoryError::InvalidInput("set already exists")
        ));
        // Original names unchanged
        let listed = svc.list_sets("uniq", &key).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed
            .iter()
            .any(|s| s.set_id == a.set_id && s.display_name == "alpha"));
        assert!(listed
            .iter()
            .any(|s| s.set_id == b.set_id && s.display_name == "beta"));
    }

    #[test]
    fn rename_same_name_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let a = svc.create_set("same", "project", &key).unwrap();
        let v = svc
            .rename_set("same", a.set_id, a.version, "project", &key)
            .unwrap();
        assert!(v.get() > a.version.get());
        let snap = svc.load("same", a.set_id, &key).unwrap();
        assert_eq!(snap.display_name, "project");
    }

    #[test]
    fn concurrent_create_same_name_only_one_succeeds() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let svc = Arc::new(HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap());
        let key = Arc::new(key());
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = vec![];
        for _ in 0..2 {
            let svc = Arc::clone(&svc);
            let key = Arc::clone(&key);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                svc.create_set("raceuser", "shared-name", &key)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let dups = results
            .iter()
            .filter(|r| matches!(r, Err(HistoryError::InvalidInput("set already exists"))))
            .count();
        assert_eq!(wins, 1, "exactly one create should succeed");
        assert_eq!(dups, 1, "the other create must see set already exists");
        assert_eq!(svc.list_sets("raceuser", &key).unwrap().len(), 1);
    }

    #[test]
    fn concurrent_first_default_initialization_creates_one_undeletable_default() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

        let dir = tempfile::tempdir().unwrap();
        let mut service =
            HistoryService::open_ephemeral(dir.path().join("default-race.redb")).unwrap();
        let (checked_tx, checked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let checks = Arc::new(AtomicUsize::new(0));
        let hook_checks = Arc::clone(&checks);
        service.default_set_after_check = Some(Arc::new(move || {
            let check = hook_checks.fetch_add(1, Ordering::SeqCst);
            checked_tx.send(()).unwrap();
            if check == 0 {
                release_rx.lock().unwrap().recv().unwrap();
            }
        }));
        let service = Arc::new(service);
        let key = Arc::new(key());

        let first_service = Arc::clone(&service);
        let first_key = Arc::clone(&key);
        let first =
            thread::spawn(move || first_service.ensure_default_set_id("default-race", &first_key));
        if checked_rx.recv_timeout(HANDSHAKE_TIMEOUT).is_err() {
            let _ = release_tx.send(());
            let _ = first.join();
            panic!("first initializer did not reach the post-check test seam");
        }

        let second_service = Arc::clone(&service);
        let second_key = Arc::clone(&key);
        let (second_started_tx, second_started_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            second_service.ensure_default_set_id("default-race", &second_key)
        });
        if second_started_rx.recv_timeout(HANDSHAKE_TIMEOUT).is_err() {
            let _ = release_tx.send(());
            let _ = first.join();
            let _ = second.join();
            panic!("second initializer did not start");
        }
        // The first call is held just after observing no default. If the
        // second reaches the same seam, both initializers observed absence
        // before either can insert. With the mutation lock, the second stays
        // behind the first until this bounded wait expires. Do not inspect the
        // DashMap here: the first initializer still owns its entry guard.
        let second_checked = checked_rx.recv_timeout(HANDSHAKE_TIMEOUT).is_ok();
        release_tx.send(()).unwrap();

        let first_id = first.join().unwrap().unwrap();
        let second_id = second.join().unwrap().unwrap();
        assert!(
            !second_checked,
            "second initializer passed the missing-default check while the first was paused"
        );
        assert_eq!(first_id, second_id);
        let defaults = service
            .list_sets("default-race", &key)
            .unwrap()
            .into_iter()
            .filter(|summary| summary.is_default)
            .collect::<Vec<_>>();
        assert_eq!(defaults.len(), 1);
        assert!(matches!(
            service.delete_set(
                "default-race",
                defaults[0].set_id,
                defaults[0].version,
                &key,
            ),
            Err(HistoryError::InvalidInput("cannot delete default set"))
        ));
    }

    #[test]
    fn empty_create_gets_new_chat_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let a = svc.create_set("auto", "", &key).unwrap();
        assert_eq!(a.display_name, "New Chat");
        let b = svc.create_set("auto", "   ", &key).unwrap();
        assert_eq!(b.display_name, "New Chat 2");
    }

    #[test]
    fn first_chat_append_adopts_contextual_name() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("auto", "", &key).unwrap();
        assert_eq!(created.display_name, "New Chat");
        let snap = svc.load("auto", created.set_id, &key).unwrap();
        let capture = PrepareCapture::from_snapshot(&snap);
        svc.commit_chat_append("auto", &capture, "Plan my trip to Tokyo", "ok", &key)
            .unwrap();
        let after = svc.load("auto", created.set_id, &key).unwrap();
        assert_eq!(after.display_name, "Plan my trip to Tokyo");
        assert_eq!(after.history.len(), 1);
        // Second message keeps the adopted name.
        let cap2 = PrepareCapture::from_snapshot(&after);
        svc.commit_chat_append("auto", &cap2, "and more", "ok2", &key)
            .unwrap();
        let again = svc.load("auto", created.set_id, &key).unwrap();
        assert_eq!(again.display_name, "Plan my trip to Tokyo");
    }

    #[test]
    fn first_direct_append_deduplicates_contextual_name_in_same_commit() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        svc.create_set("auto", "Plan my trip to Tokyo", &key)
            .unwrap();
        let created = svc.create_set("auto", "", &key).unwrap();

        let version = svc
            .append_pair(
                "auto",
                created.set_id,
                created.version,
                "Plan my trip to Tokyo",
                "ok",
                &key,
            )
            .unwrap();

        assert_eq!(version, SetVersion(2));
        let after = svc.load("auto", created.set_id, &key).unwrap();
        assert_eq!(after.display_name, "Plan my trip to Tokyo 2");
        assert_eq!(
            after.history,
            vec![("Plan my trip to Tokyo".into(), "ok".into())]
        );
    }

    #[test]
    fn first_capture_append_deduplicates_contextual_name_in_same_commit() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        svc.create_set("auto", "Plan my trip to Tokyo", &key)
            .unwrap();
        let created = svc.create_set("auto", "", &key).unwrap();
        let capture =
            PrepareCapture::from_snapshot(&svc.load("auto", created.set_id, &key).unwrap());

        let version = svc
            .commit_chat_append("auto", &capture, "Plan my trip to Tokyo", "ok", &key)
            .unwrap();

        assert_eq!(version, SetVersion(2));
        let after = svc.load("auto", created.set_id, &key).unwrap();
        assert_eq!(after.display_name, "Plan my trip to Tokyo 2");
        assert_eq!(
            after.history,
            vec![("Plan my trip to Tokyo".into(), "ok".into())]
        );
    }

    #[test]
    fn fork_copies_prefix_and_leaves_source_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("forker", "trip", &key).unwrap();
        let mut v = created.version;
        for (u, a) in [("one", "a1"), ("two", "a2"), ("three", "a3")] {
            v = svc
                .append_pair("forker", created.set_id, v, u, a, &key)
                .unwrap();
        }
        let forked = svc
            .fork_set("forker", created.set_id, Some(v), 1, None, &key)
            .unwrap();
        assert_eq!(forked.display_name, "trip - branch");
        let fork_snap = svc.load("forker", forked.set_id, &key).unwrap();
        assert_eq!(fork_snap.history.len(), 2);
        assert_eq!(fork_snap.history[0].0, "one");
        assert_eq!(fork_snap.history[1].0, "two");
        // Memory and prompt carry over.
        assert_eq!(fork_snap.memory, "");
        let source = svc.load("forker", created.set_id, &key).unwrap();
        assert_eq!(source.history.len(), 3);
        assert_eq!(source.display_name, "trip");
        // Second fork dedups.
        let forked2 = svc
            .fork_set("forker", created.set_id, None, 1, None, &key)
            .unwrap();
        assert_eq!(forked2.display_name, "trip - branch 2");
        // Stale expected version conflicts.
        let err = svc
            .fork_set(
                "forker",
                created.set_id,
                Some(created.version),
                0,
                None,
                &key,
            )
            .unwrap_err();
        assert!(matches!(err, HistoryError::Conflict { .. }));
        // Out of range.
        let err = svc
            .fork_set("forker", created.set_id, None, 9, None, &key)
            .unwrap_err();
        assert!(matches!(err, HistoryError::InvalidInput(_)));
    }

    /// A fork is written chunked with the source's sealed image and thumb
    /// payloads copied, so it never inlines full-res images into a whole-set
    /// blob that the next load must re-decode and re-thumbnail.
    #[test]
    fn fork_writes_chunked_set_and_copies_image_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let created = svc.create_set("forker", "pics", &key).unwrap();
        let jpeg = crate::chat_images::fixture_jpeg_data_url(64, 64);
        let mut v = svc
            .append_pair(
                "forker",
                created.set_id,
                created.version,
                &format!("look\n[IMAGE:{jpeg}]"),
                "a1",
                &key,
            )
            .unwrap();
        v = svc
            .append_pair("forker", created.set_id, v, "two", "a2", &key)
            .unwrap();
        let source = svc.load("forker", created.set_id, &key).unwrap();
        let source_thumb = svc.load_thumb("forker", created.set_id, 0, 0, &key).unwrap();

        let plain = svc
            .fork_set("forker", created.set_id, Some(v), 0, None, &key)
            .unwrap();
        let request = OperationRequest::new(
            crate::operation_receipt::OperationId::parse("fork-operation-0001").unwrap(),
            "/fork_set",
            &serde_json::json!({"pair_index": 1}),
        );
        let receipt = svc
            .fork_operation("forker", created.set_id, Some(v), 1, None, &key, &request)
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&receipt.body).unwrap();
        let op_id = SetId::parse(body["set_id"].as_str().unwrap()).unwrap();

        for (fork_id, pairs) in [(plain.set_id, 1), (op_id, 2)] {
            let meta = svc.store.load_meta("forker", fork_id).unwrap();
            assert!(meta.blob_format.is_chunked(), "fork must be stored chunked");
            assert_eq!(meta.version, SetVersion(2));
            let fork = svc.load("forker", fork_id, &key).unwrap();
            assert_eq!(fork.history, source.history[..pairs].to_vec());
            assert_eq!(
                svc.load_thumb("forker", fork_id, 0, 0, &key).unwrap(),
                source_thumb
            );
        }
        let after = svc.load("forker", created.set_id, &key).unwrap();
        assert_eq!(after.history, source.history);
    }

    fn chat_with_image(svc: &HistoryService, key: &EncryptionKey) -> (SetId, SetVersion) {
        let created = svc.create_set("forker", "pics", key).unwrap();
        let jpeg = crate::chat_images::fixture_jpeg_data_url(64, 64);
        let v = svc
            .append_pair(
                "forker",
                created.set_id,
                created.version,
                &format!("look\n[IMAGE:{jpeg}]"),
                "a1",
                key,
            )
            .unwrap();
        let v = svc
            .append_pair("forker", created.set_id, v, "two", "a2", key)
            .unwrap();
        (created.set_id, v)
    }

    fn set_assistant(
        svc: &HistoryService,
        set_id: SetId,
        expected: SetVersion,
        pair_index: usize,
        text: &str,
        key: &EncryptionKey,
    ) -> SetVersion {
        svc.mutate_content("forker", set_id, expected, key, |snap| {
            let mut snap = Arc::unwrap_or_clone(snap).into_snapshot();
            snap.history[pair_index].1 = text.to_owned();
            Ok(snap)
        })
        .unwrap()
    }

    /// Branching is copy-on-write: the fork points at the source's sealed
    /// blobs, so it opens, copies and seals no pair, image or thumb.
    #[test]
    fn fork_shares_source_blobs_without_opening_or_copying() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let (source_id, v) = chat_with_image(&svc, &key);
        let source = svc.store.load_logical("forker", source_id, &key).unwrap();
        let image = svc.load_image("forker", source_id, 0, 0, &key).unwrap();
        let thumb = svc.load_thumb("forker", source_id, 0, 0, &key).unwrap();
        let rows = svc.store.test_blob_rows().unwrap();

        crate::history::cost::take_blob_opens();
        let fork = svc
            .fork_set("forker", source_id, Some(v), 1, None, &key)
            .unwrap();
        assert_eq!(
            crate::history::cost::take_blob_opens(),
            crate::history::cost::BlobOpens::default(),
            "fork must not open history blobs"
        );
        let after = svc.store.test_blob_rows().unwrap();
        assert_eq!(after[..4], rows[..4], "fork must not copy history blobs");

        let forked = svc.store.load_logical("forker", fork.set_id, &key).unwrap();
        assert_eq!(forked.as_snapshot().history, source.as_snapshot().history);
        assert_eq!(forked.as_snapshot().memory, source.as_snapshot().memory);
        assert_eq!(svc.load_image("forker", fork.set_id, 0, 0, &key).unwrap(), image);
        assert_eq!(svc.load_thumb("forker", fork.set_id, 0, 0, &key).unwrap(), thumb);
    }

    /// Edits on either side stay on that side, and a fork outlives the
    /// source it shares blobs with.
    #[test]
    fn fork_and_source_diverge_and_fork_survives_source_delete() {
        let dir = tempfile::tempdir().unwrap();
        let svc = HistoryService::open_ephemeral(dir.path().join("h.redb")).unwrap();
        let key = key();
        let (source_id, v) = chat_with_image(&svc, &key);
        let original = svc.store.load_logical("forker", source_id, &key).unwrap();
        let original = original.as_snapshot().history.clone();
        let image = svc.load_image("forker", source_id, 0, 0, &key).unwrap();
        let thumb = svc.load_thumb("forker", source_id, 0, 0, &key).unwrap();
        let fork = svc
            .fork_set("forker", source_id, Some(v), 1, None, &key)
            .unwrap();

        // Source overwrites a shared pair and drops another.
        let v = set_assistant(&svc, source_id, v, 0, "a1 edited", &key);
        svc.delete_pair("forker", source_id, v, 1, "two", &key).unwrap();
        let forked = svc.store.load_logical("forker", fork.set_id, &key).unwrap();
        assert_eq!(forked.as_snapshot().history, original);

        // Fork edits stay out of the source.
        let fv = set_assistant(&svc, fork.set_id, fork.version, 1, "a2 forked", &key);
        let source = svc.store.load_logical("forker", source_id, &key).unwrap();
        assert_eq!(source.as_snapshot().history.len(), 1);
        assert_eq!(source.as_snapshot().history[0].1, "a1 edited");

        let meta = svc.store.load_meta("forker", source_id).unwrap();
        svc.delete_set("forker", source_id, meta.version, &key).unwrap();
        let forked = svc.store.load_logical("forker", fork.set_id, &key).unwrap();
        assert_eq!(forked.as_snapshot().history[0], original[0]);
        assert_eq!(forked.as_snapshot().history[1].1, "a2 forked");
        assert_eq!(svc.load_image("forker", fork.set_id, 0, 0, &key).unwrap(), image);
        assert_eq!(svc.load_thumb("forker", fork.set_id, 0, 0, &key).unwrap(), thumb);

        svc.delete_set("forker", fork.set_id, fv, &key).unwrap();
        assert_eq!(svc.store.test_blob_rows().unwrap(), [0; 5]);
    }

}
