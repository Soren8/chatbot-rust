//! Chat history and set storage — **only** public entry points for durable set data.
//!
//! Handlers and session code must use [`api::HistoryService`] and the types re-exported
//! here. Do not access `store` internals or redb from outside this module.
//!
//! Pre-redb `sets.json` migration is permanent under [`crate::legacy_sets_json`].

mod api;
mod cache;
mod crypto;
mod migration;
mod ops;
mod store;
mod types;

pub use api::{HistoryError, HistoryService};
pub use cache::SetCache;
pub use ops::{
    append_pair, apply_chat_append, apply_regenerate, delete_pair, rename, reset_history,
    update_memory, update_system_prompt, with_version, OpsError,
};
pub use types::{
    BlobFormat, HistoryPair, PrepareCapture, SetId, SetPayloadV1, SetSnapshot, SetSummary,
    SetVersion,
};

/// Display-name validation shared by HTTP handlers (not storage keys).
pub fn normalise_set_name(set_name: Option<&str>) -> Result<String, crate::persistence::PersistenceError> {
    crate::persistence::DataPersistence::normalise_set_name(set_name)
}

pub fn normalise_custom_set_name(
    set_name: &str,
) -> Result<String, crate::persistence::PersistenceError> {
    crate::persistence::DataPersistence::normalise_custom_set_name(set_name)
}
