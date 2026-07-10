//! Lazy one-shot migration from legacy `user_sets/{user}/sets.json` into redb.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use dashmap::DashMap;
use tracing::{info, warn};

use super::store::{ImportSet, RedbHistoryStore, StoreError};
use super::types::SetId;
use crate::enc_key::EncryptionKey;
use crate::persistence::{DataPersistence, EncryptionMode, PersistenceError};

fn migration_locks() -> &'static DashMap<String, Mutex<()>> {
    static LOCKS: OnceLock<DashMap<String, Mutex<()>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

/// Ensure legacy data for `user` is in redb. Idempotent.
///
/// - If META flag set → no-op.
/// - If no `sets.json` → mark migrated empty.
/// - Else decrypt via `DataPersistence`, bulk-import, flag, rename to `.migrated.bak`.
pub fn ensure_user_migrated(
    store: &RedbHistoryStore,
    data_dir: &Path,
    default_system_prompt: &str,
    user: &str,
    key: &EncryptionKey,
) -> Result<(), StoreError> {
    if store.is_user_migrated(user)? {
        return Ok(());
    }

    let lock_entry = migration_locks()
        .entry(user.to_owned())
        .or_insert_with(|| Mutex::new(()));
    let _guard = lock_entry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Re-check under lock
    if store.is_user_migrated(user)? {
        return Ok(());
    }

    let persistence = DataPersistence::with_data_dir(data_dir, default_system_prompt)
        .map_err(|err| map_persistence(err))?;

    let sets_path = persistence
        .sets_json_path(user)
        .map_err(map_persistence)?;

    if !sets_path.exists() {
        // Already bak'd or brand-new user
        let bak = sets_path.with_extension("json.migrated.bak");
        if bak.exists() {
            // File was renamed earlier but flag missing — do not re-import; just flag.
            store.mark_user_migrated_empty(user)?;
            return Ok(());
        }
        store.mark_user_migrated_empty(user)?;
        return Ok(());
    }

    let mode = EncryptionMode::Fernet(key.as_bytes());
    let listed = persistence
        .list_sets(user, Some(mode))
        .map_err(map_persistence)?;

    let mut imports = Vec::with_capacity(listed.len());
    for (name, meta) in listed {
        let loaded = persistence
            .load_set(user, &name, Some(mode))
            .map_err(map_persistence)?;
        let created_at = (meta.created.max(0.0) * 1000.0) as u64;
        let updated_at = {
            let m = if meta.modified > 0.0 {
                meta.modified
            } else {
                meta.created
            };
            (m.max(0.0) * 1000.0) as u64
        };
        let is_default = name == "default";
        imports.push(ImportSet {
            set_id: SetId::new(),
            display_name: name,
            memory: loaded.memory,
            system_prompt: loaded.system_prompt,
            history: loaded.history,
            is_default,
            created_at,
            updated_at,
        });
    }

    // Ensure exactly one default flag after migration.
    if imports.is_empty() {
        imports.push(ImportSet {
            set_id: SetId::new(),
            display_name: "default".into(),
            memory: String::new(),
            system_prompt: default_system_prompt.to_owned(),
            history: Vec::new(),
            is_default: true,
            created_at: 0,
            updated_at: 0,
        });
    } else if !imports.iter().any(|s| s.is_default) {
        // Prefer name "default" if present; otherwise create an empty default set
        // so ensure_default_set does not invent a second empty set later.
        if let Some(slot) = imports.iter_mut().find(|s| s.display_name == "default") {
            slot.is_default = true;
        } else {
            imports.push(ImportSet {
                set_id: SetId::new(),
                display_name: "default".into(),
                memory: String::new(),
                system_prompt: default_system_prompt.to_owned(),
                history: Vec::new(),
                is_default: true,
                created_at: 0,
                updated_at: 0,
            });
        }
    }

    let count = store.import_sets_and_mark_migrated(user, &imports, key)?;
    info!(
        user = %user,
        set_count = count,
        "history_migration_completed"
    );

    rename_legacy_sets_json(&sets_path);

    Ok(())
}

fn rename_legacy_sets_json(sets_path: &Path) {
    let bak = sets_path
        .parent()
        .map(|p| p.join("sets.json.migrated.bak"))
        .unwrap_or_else(|| PathBuf::from("sets.json.migrated.bak"));

    if let Err(err) = std::fs::rename(sets_path, &bak) {
        warn!(
            ?err,
            path = %sets_path.display(),
            "failed to rename sets.json after migration; redb is authoritative"
        );
    }
}

fn map_persistence(err: PersistenceError) -> StoreError {
    match err {
        PersistenceError::DecryptionFailed | PersistenceError::InvalidEncryptionKey => {
            StoreError::DecryptFailed
        }
        PersistenceError::MissingEncryptionKey => StoreError::DecryptFailed,
        PersistenceError::InvalidUsername | PersistenceError::InvalidSetName => {
            StoreError::InvalidInput
        }
        other => {
            warn!(?other, "legacy persistence error during migration");
            StoreError::Database(other.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::api::HistoryService;
    use crate::history::types::SetVersion;
    use crate::persistence::{DataPersistence, EncryptionMode};

    fn key() -> EncryptionKey {
        let fernet_key = fernet::Fernet::generate_key();
        EncryptionKey::from_header_value(&fernet_key).expect("fernet key header")
    }

    #[test]
    fn migrates_encrypted_sets_json_and_is_idempotent() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let key = key();
        let user = "miguser";

        let persistence =
            DataPersistence::with_data_dir(data.path(), "You are helpful.").unwrap();
        let mode = EncryptionMode::Fernet(key.as_bytes());
        persistence
            .store_history(
                user,
                "default",
                &[("hello".into(), "world".into()), ("q".into(), "a".into())],
                mode,
            )
            .unwrap();
        persistence
            .store_memory(user, "default", "remember this", mode)
            .unwrap();
        persistence
            .create_set(user, "secret-project", Some(mode))
            .unwrap();
        persistence
            .store_history(
                user,
                "secret-project",
                &[("private".into(), "reply".into())],
                mode,
            )
            .unwrap();

        let sets_json = data
            .path()
            .join("user_sets")
            .join(user)
            .join("sets.json");
        assert!(sets_json.exists());
        let raw_before = std::fs::read(&sets_json).unwrap();
        // Encrypted file should not contain plaintext set name or history
        assert!(!String::from_utf8_lossy(&raw_before).contains("secret-project"));
        assert!(!String::from_utf8_lossy(&raw_before).contains("remember this"));

        let svc = HistoryService::open_with_data_dir(&redb_path, data.path(), "You are helpful.")
            .unwrap();

        let listed = svc.list_sets(user, &key).unwrap();
        assert_eq!(listed.len(), 2);

        let default = listed
            .iter()
            .find(|s| s.is_default || s.display_name == "default")
            .expect("default set");
        let snap = svc.load(user, default.set_id, &key).unwrap();
        assert_eq!(snap.history.len(), 2);
        assert_eq!(snap.history[0], ("hello".into(), "world".into()));
        assert_eq!(snap.memory, "remember this");

        let secret = listed
            .iter()
            .find(|s| s.display_name == "secret-project")
            .expect("secret set");
        let secret_snap = svc.load(user, secret.set_id, &key).unwrap();
        assert_eq!(secret_snap.history.len(), 1);

        // Legacy renamed
        assert!(!sets_json.exists());
        assert!(sets_json
            .parent()
            .unwrap()
            .join("sets.json.migrated.bak")
            .exists());

        // redb file must not contain sensitive display name in plaintext
        let db_bytes = std::fs::read(&redb_path).unwrap();
        assert!(!db_bytes
            .windows(b"secret-project".len())
            .any(|w| w == b"secret-project"));

        // Idempotent second call
        let listed2 = svc.list_sets(user, &key).unwrap();
        assert_eq!(listed2.len(), 2);

        // Mutate after migration still works
        let v = svc
            .append_pair(
                user,
                default.set_id,
                snap.version,
                "new",
                "msg",
                &key,
            )
            .unwrap();
        assert_eq!(v, SetVersion(2));
    }

    #[test]
    fn new_user_without_legacy_file_marks_migrated() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let key = key();
        let svc =
            HistoryService::open_with_data_dir(&redb_path, data.path(), "sys").unwrap();
        let created = svc.create_set("fresh", "default", &key).unwrap();
        assert!(created.is_default || created.display_name == "default");
        assert_eq!(svc.list_sets("fresh", &key).unwrap().len(), 1);
    }

    #[test]
    fn bak_without_flag_marks_migrated_without_reimport() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let key = key();
        let user = "bakonly";

        // Create bak as if rename already happened; no live sets.json
        let user_dir = data.path().join("user_sets").join(user);
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("sets.json.migrated.bak"), b"not-used").unwrap();

        let svc =
            HistoryService::open_with_data_dir(&redb_path, data.path(), "sys").unwrap();
        // First list should mark migrated empty and not panic
        let listed = svc.list_sets(user, &key).unwrap();
        assert!(listed.is_empty());
        // Creating still works
        let created = svc.create_set(user, "default", &key).unwrap();
        assert_eq!(created.display_name, "default");
        assert_eq!(svc.list_sets(user, &key).unwrap().len(), 1);
    }

    #[test]
    fn wrong_key_on_legacy_sets_json_fails_without_marking_migrated() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let good = key();
        let bad = key(); // different fernet key
        let user = "wrongkey";

        let persistence =
            DataPersistence::with_data_dir(data.path(), "sys").unwrap();
        let mode = EncryptionMode::Fernet(good.as_bytes());
        persistence
            .store_history(user, "default", &[("x".into(), "y".into())], mode)
            .unwrap();

        let svc =
            HistoryService::open_with_data_dir(&redb_path, data.path(), "sys").unwrap();
        let err = svc.list_sets(user, &bad).unwrap_err();
        assert!(matches!(err, crate::history::HistoryError::DecryptFailed));

        // sets.json still present (not renamed)
        assert!(data
            .path()
            .join("user_sets")
            .join(user)
            .join("sets.json")
            .exists());

        // Correct key still migrates
        let listed = svc.list_sets(user, &good).unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn migration_adds_default_when_legacy_has_only_custom_sets() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let key = key();
        let user = "nodefault";

        let persistence = DataPersistence::with_data_dir(data.path(), "sys").unwrap();
        let mode = EncryptionMode::Fernet(key.as_bytes());
        persistence
            .create_set(user, "project-only", Some(mode))
            .unwrap();
        persistence
            .store_history(
                user,
                "project-only",
                &[("u".into(), "a".into())],
                mode,
            )
            .unwrap();

        let svc =
            HistoryService::open_with_data_dir(&redb_path, data.path(), "sys").unwrap();
        let listed = svc.list_sets(user, &key).unwrap();
        assert!(
            listed.iter().any(|s| s.is_default && s.display_name == "default"),
            "migration must create a default set: {listed:?}"
        );
        assert!(
            listed.iter().any(|s| s.display_name == "project-only"),
            "custom set must remain"
        );
        let project = listed
            .iter()
            .find(|s| s.display_name == "project-only")
            .unwrap();
        let snap = svc.load(user, project.set_id, &key).unwrap();
        assert_eq!(snap.history.len(), 1);
        // Exactly one default flag
        assert_eq!(listed.iter().filter(|s| s.is_default).count(), 1);
    }

    #[test]
    fn migrates_plaintext_split_files() {
        let data = tempfile::tempdir().unwrap();
        let redb_path = data.path().join("history").join("redb");
        let key = key();
        let user = "splituser";
        let user_dir = data.path().join("user_sets").join(user);
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(
            user_dir.join("sets.json"),
            serde_json::to_vec(&serde_json::json!({
                "default": { "created": 1.0, "modified": 1.0, "encrypted": false }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(user_dir.join("default_memory.txt"), b"mem-from-file").unwrap();
        std::fs::write(user_dir.join("default_prompt.txt"), b"prompt-from-file").unwrap();
        std::fs::write(
            user_dir.join("default_history.json"),
            serde_json::to_vec(&serde_json::json!([["u", "a"]])).unwrap(),
        )
        .unwrap();

        let svc =
            HistoryService::open_with_data_dir(&redb_path, data.path(), "fallback").unwrap();
        let snap = svc
            .find_by_display_name(user, "default", &key)
            .unwrap()
            .expect("default migrated");
        assert_eq!(snap.memory, "mem-from-file");
        assert_eq!(snap.system_prompt, "prompt-from-file");
        assert_eq!(snap.history.len(), 1);
        assert_eq!(snap.history[0].0, "u");
    }
}
