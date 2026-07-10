//! Fernet helpers and compatibility re-exports.
//!
//! **History sets.json I/O lives permanently in [`crate::legacy_sets_json`].**
//! Do not reintroduce live `store_history` call sites for authenticated traffic.

pub use crate::legacy_sets_json::{
    EncryptionMode, LegacySetsStore as DataPersistence, LoadedSet, PersistenceError, SetData,
    SetMetadata,
};
