use std::{
    path::PathBuf,
    sync::Arc,
};

use crate::{
    remember_store::{RememberError, RememberStore},
    user_store::{UserStore, UserStoreError},
};

struct OwnedAccountDependencies {
    root: PathBuf,
    verifier_secret: Arc<str>,
}

/// Owned account storage: user records plus remember tokens.
///
/// Concrete composition root for account HTTP handlers and chat key/tier
/// gates. `Clone` shares one `Arc` of root plus HMAC verifier secret; two
/// services built from separate roots/secrets share nothing even for the
/// same username.
///
/// Compatibility: [`AccountService::global`] touches neither config nor any
/// store. Each of its `users()`/`remember()` calls opens the existing
/// process-global stores with their lazy first-use timing untouched (per-call
/// `UserStore::new` / `RememberStore::new` plus live verifier secret).
/// Owned handles ([`AccountService::with_root_and_secret`]) open only their
/// explicit root and never read ambient config; `users()` returns a store
/// already configured with the explicit secret so callers use the ordinary
/// `ensure`/`verify` APIs and cannot forget it.
///
/// Only the server HMAC secret is stored; no data-key is retained.
#[derive(Clone)]
pub struct AccountService {
    owned: Option<Arc<OwnedAccountDependencies>>,
}

impl AccountService {
    /// Compatibility handle. Constructing it touches neither config nor any
    /// store; each operation resolves the existing process-global
    /// dependencies lazily, preserving per-call open and live-secret timing.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// Explicit owned construction from an account root plus the HMAC
    /// verifier secret. Touches no config/store; inputs are used as-is.
    pub fn with_root_and_secret(root: PathBuf, secret: impl Into<Arc<str>>) -> Self {
        Self {
            owned: Some(Arc::new(OwnedAccountDependencies {
                root,
                verifier_secret: secret.into(),
            })),
        }
    }

    /// Configured user store for this service. Opens per call: the global
    /// handle preserves `UserStore::new` timing (directory creation,
    /// migration reads, dynamic secret); the owned handle opens its explicit
    /// root with its explicit secret and performs no config reads.
    pub fn users(&self) -> Result<UserStore, UserStoreError> {
        match self.owned.as_ref() {
            Some(deps) => {
                UserStore::open_with_secret(&deps.root, Arc::clone(&deps.verifier_secret))
            }
            None => UserStore::new(),
        }
    }

    /// Remember-token store for this service. Opens per call: the global
    /// handle preserves `RememberStore::new` timing; the owned handle opens
    /// its explicit root and performs no environment reads.
    pub fn remember(&self) -> Result<RememberStore, RememberError> {
        match self.owned.as_ref() {
            Some(deps) => RememberStore::open(&deps.root),
            None => RememberStore::new(),
        }
    }

    /// Owned remember purge hook. Opens per call like [`AccountService::remember`];
    /// failures report zero removals, matching the background task's
    /// best-effort semantics.
    pub fn purge_remember_expired(&self) -> usize {
        self.remember().map(|store| store.purge_expired()).unwrap_or(0)
    }
}

impl std::fmt::Debug for AccountService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountService")
            .field("owned", &self.owned.is_some())
            .finish_non_exhaustive()
    }
}
