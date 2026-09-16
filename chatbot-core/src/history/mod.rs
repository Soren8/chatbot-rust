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
    append_pair, apply_chat_append, apply_regenerate, branch_name_for, dedup_name,
    delete_pair, derive_chat_name_from_message, is_auto_placeholder_name, page_history, rename,
    reset_history, update_memory, update_system_prompt, with_version, HistoryPage, OpsError,
    AUTO_NEW_CHAT_PREFIX, DEFAULT_HISTORY_PAGE_SIZE, MAX_AUTO_NAME_CHARS, MAX_HISTORY_PAGE_SIZE,
};
pub use types::{
    BlobFormat, HeaderV1, HistoryPair, ImageId, ImagePayloadV1, ManifestPair, ManifestV1, PairId,
    PairPayloadV1, PrepareCapture, SetId, SetPage, SetPayloadV1, SetSnapshot, SetSummary,
    SetVersion, ThumbPayloadV1,
};

pub use crate::names::SetNameError;

/// Display-name validation shared by HTTP handlers (not storage keys).
pub use crate::names::{normalise_custom_set_name, normalise_set_name};
