pub mod chat;
pub mod config;
pub mod logging;
pub mod enc_key;
pub mod history;
/// Permanent pre-redb `sets.json` migration surface — do not remove casually.
pub mod legacy_sets_json;
pub mod persistence;
pub mod session;
pub mod user_store;
