//! Public safe API for durable history/set access.
//!
//! All HTTP handlers and session orchestration must go through [`HistoryService`].
//! redb handles, raw keys, and free-form blob writes are not exposed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use once_cell::sync::OnceCell;
use thiserror::Error;
use tracing::error;

use super::migration;
use super::ops::{self, OpsError};
use super::store::{RedbHistoryStore, StoreError};
use super::types::{PrepareCapture, SetId, SetSnapshot, SetSummary, SetVersion};
use crate::config::app_config;
use crate::enc_key::EncryptionKey;

/// Serializes create/rename uniqueness checks per user (names live only in ciphertext).
fn name_mutation_locks() -> &'static DashMap<String, Mutex<()>> {
    static LOCKS: OnceLock<DashMap<String, Mutex<()>>> = OnceLock::new();
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
            OpsError::ContentMismatch => HistoryError::InvalidInput("content mismatch at pair_index"),
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
    default_system_prompt: String,
    /// Host data dir containing `user_sets/` for legacy migration.
    data_dir: PathBuf,
}

impl HistoryService {
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
            default_system_prompt: default_system_prompt.into(),
            data_dir: data_dir.into(),
        })
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
            match self.store.load_snapshot(&user, set_id, key) {
                Ok(snap) => out.push(SetSummary {
                    set_id: snap.set_id,
                    version: snap.version,
                    display_name: snap.display_name,
                    updated_at,
                    is_default: snap.is_default,
                }),
                Err(StoreError::DecryptFailed) => return Err(HistoryError::DecryptFailed),
                Err(StoreError::Forbidden) => continue,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(out)
    }

    pub fn load(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        Ok(self.store.load_snapshot(&user, set_id, key)?)
    }

    /// Resolve display name → set_id for transition shims (decrypts all sets).
    pub fn find_by_display_name(
        &self,
        user: &str,
        display_name: &str,
        key: &EncryptionKey,
    ) -> Result<Option<SetSnapshot>, HistoryError> {
        let want = display_name.trim();
        for summary in self.list_sets(user, key)? {
            if summary.display_name == want {
                return Ok(Some(self.load(user, summary.set_id, key)?));
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
        let name = display_name.trim();
        if name.is_empty() {
            return Err(HistoryError::InvalidInput("empty set name"));
        }

        let lock_entry = name_mutation_locks()
            .entry(user.clone())
            .or_insert_with(|| Mutex::new(()));
        let _guard = lock_entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Uniqueness among decrypted names (under per-user lock to close concurrent races).
        self.ensure_display_name_available(&user, name, None, key)?;

        let set_id = SetId::new();
        let is_default = name == "default";
        Ok(self.store.create_set(
            &user,
            set_id,
            name,
            &self.default_system_prompt,
            is_default,
            key,
        )?)
    }

    /// Ensure a default set exists (empty history). Returns its snapshot.
    pub fn ensure_default_set(
        &self,
        user: &str,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        for summary in self.list_sets(&user, key)? {
            if summary.is_default || summary.display_name == "default" {
                return self.load(&user, summary.set_id, key);
            }
        }
        let summary = self.store.create_set(
            &user,
            SetId::new(),
            "default",
            &self.default_system_prompt,
            true,
            key,
        )?;
        self.load(&user, summary.set_id, key)
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

        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        if snap.is_default {
            return Err(HistoryError::InvalidInput("cannot rename default set"));
        }
        let next = ops::rename(&snap, new_name)?;
        // Reject collision with any other set (same name on self is a no-op rename).
        self.ensure_display_name_available(&user, &next.display_name, Some(set_id), key)?;
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
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
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        if snap.is_default {
            return Err(HistoryError::InvalidInput("cannot delete default set"));
        }
        Ok(self.store.delete_set(&user, set_id, expected)?)
    }

    // --- content mutations (all CAS) ---

    pub fn commit_snapshot(
        &self,
        user: &str,
        expected: SetVersion,
        snapshot: &SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        Ok(self
            .store
            .commit_snapshot(&user, expected, snapshot, key)?)
    }

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
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        let next = ops::append_pair(&snap, user_msg, assistant_msg)?;
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
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
        let next = ops::apply_chat_append(capture, user_msg, assistant_msg)?;
        Ok(self
            .store
            .commit_snapshot(&user, capture.version, &next, key)?)
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
        Ok(self
            .store
            .commit_snapshot(&user, capture.version, &next, key)?)
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
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        let next = ops::delete_pair(&snap, pair_index, expected_user_msg)?;
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
    }

    pub fn reset_history(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        let next = ops::reset_history(&snap);
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
    }

    pub fn update_memory(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        memory: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        let next = ops::update_memory(&snap, memory)?;
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
    }

    pub fn update_system_prompt(
        &self,
        user: &str,
        set_id: SetId,
        expected: SetVersion,
        prompt: &str,
        key: &EncryptionKey,
    ) -> Result<SetVersion, HistoryError> {
        let user = normalise_user(user)?;
        self.ensure_migrated(&user, key)?;
        let snap = self.store.load_snapshot(&user, set_id, key)?;
        if snap.version != expected {
            return Err(HistoryError::Conflict {
                current_version: snap.version,
            });
        }
        let next = ops::update_system_prompt(&snap, prompt)?;
        Ok(self.store.commit_snapshot(&user, expected, &next, key)?)
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
            .append_pair(
                "bob",
                created.set_id,
                created.version,
                "hi",
                "hello",
                &key,
            )
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
            v = svc.append_pair("erin", created.set_id, v, u, a, &key).unwrap();
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
            .append_pair("frank", created.set_id, created.version, "hello", "hi", &key)
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
        let v4 = svc.reset_history("frank", created.set_id, v3, &key).unwrap();
        let reset = svc.load("frank", created.set_id, &key).unwrap();
        assert!(reset.history.is_empty());
        assert_eq!(reset.version, v4);
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
        assert!(matches!(err, HistoryError::InvalidInput("set already exists")));
        // Original names unchanged
        let listed = svc.list_sets("uniq", &key).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|s| s.set_id == a.set_id && s.display_name == "alpha"));
        assert!(listed.iter().any(|s| s.set_id == b.set_id && s.display_name == "beta"));
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
}
