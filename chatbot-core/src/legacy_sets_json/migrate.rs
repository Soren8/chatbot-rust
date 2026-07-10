//! Re-export migration orchestrator (redb import) for discoverability.
//!
//! Format parsing stays in this crate module (`store`); the redb write path lives
//! in [`crate::history::migration`] next to the store it fills.

pub use crate::history::migration::ensure_user_migrated;
