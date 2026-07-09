//! Chat history and set storage — **only** public entry points for durable set data.
//!
//! Handlers and session code must use [`api::HistoryService`] and the types re-exported
//! here. Do not access `store` internals or redb from outside this module.

mod api;
mod crypto;
mod ops;
mod store;
mod types;

pub use api::{HistoryError, HistoryService};
pub use ops::{
    append_pair, apply_chat_append, apply_regenerate, delete_pair, rename, reset_history,
    update_memory, update_system_prompt, with_version, OpsError,
};
pub use types::{
    BlobFormat, HistoryPair, PrepareCapture, SetId, SetPayloadV1, SetSnapshot, SetSummary,
    SetVersion,
};
