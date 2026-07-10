//! **Permanent** legacy chat-history format: `data/user_sets/{user}/sets.json`.
//!
//! This module is the long-lived bridge for servers that still have encrypted
//! `sets.json` (or older split files) on disk. Migration orchestration into redb
//! lives in [`crate::history`] (`history::migration::ensure_user_migrated` via
//! `HistoryService`). Do not delete or gut this module during history-store
//! cleanups without a versioned replacement path.
//!
//! Live authed traffic must use [`crate::history::HistoryService`], never this
//! module's write path (writes exist for tests and controlled migration seeds).

mod store;

pub use store::{
    EncryptionMode, LegacySetsStore, LoadedSet, PersistenceError, SetData, SetMetadata,
};

/// Operator note: after a successful migration, `sets.json` is renamed to
/// `sets.json.migrated.bak` under the same user directory. Safe to delete after
/// one stable release once redb is confirmed healthy; keep bak files if you may
/// need to roll back an image that cannot read redb.
pub const MIGRATED_BAK_FILENAME: &str = "sets.json.migrated.bak";
