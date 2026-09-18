//! Narrow application services context (MOD-003 resource composition).
//!
//! One owned [`AppServices`] bundles the three per-router resources that must
//! stay isolated together: the HTTP identity store, the TTS pending-token
//! store, and the rate-limit counters. Production builds one at startup and
//! clones it into every request via an Axum `Extension` layer; the same
//! identity value is also installed as the legacy `RequestIdentity` extension
//! so existing handlers keep working from a single source.
//!
//! Compatibility: [`AppServices::global`] and [`AppServices::with_identity`]
//! resolve the TTS and limiter dimensions to the existing process-global
//! stores (the `tts` static and the `chatbot_core::rate_limit` free
//! functions), preserving lazy initialization and the `rate_limit::reset`
//! test hook. [`AppServices::with_owned_stores`] backs
//! a router with fully independent tokens and counters.
//!
//! Config-free state only: token admission and rate windows live here. Live
//! `app_config()` limits (`rate_limit_*`, `tts_*`) and the user, remember,
//! history, and chat stores stay process-global for now.

use std::sync::{Arc, Mutex};

use axum::http::Extensions;

use chatbot_core::rate_limit::{self, RateLimitExceeded, RateLimiter};

use crate::identity::RequestIdentity;
use crate::tts::store::PendingTtsStore;

/// Owned router resources: one identity plus one pending-token store plus one
/// rate-limit counter set. Cloned into every request; the inner stores stay
/// shared via `Arc`.
#[derive(Clone)]
pub struct AppServices {
    identity: RequestIdentity,
    pending_tts: Option<Arc<PendingTtsStore>>,
    limiter: Option<Arc<Mutex<RateLimiter>>>,
}

impl AppServices {
    /// Compatibility context: the global identity plus the existing global
    /// TTS and limiter stores, with their lazy first-use timing untouched.
    pub fn global() -> Self {
        Self {
            identity: RequestIdentity::global(),
            pending_tts: None,
            limiter: None,
        }
    }

    /// Compatibility context for an owned identity: TTS tokens and
    /// rate-limit counters stay process-global. Prefer
    /// [`AppServices::with_owned_stores`] for fully independent routers.
    pub fn with_identity(identity: RequestIdentity) -> Self {
        Self {
            identity,
            pending_tts: None,
            limiter: None,
        }
    }

    /// Fully owned context: `pending_tts` and `limiter` back this router
    /// only. Tokens admitted here are unknown elsewhere; counters are
    /// independent. Crate-internal: external callers use
    /// [`AppServices::with_owned_stores`] so the narrow public surface never
    /// names the store types.
    fn new(
        identity: RequestIdentity,
        pending_tts: Arc<PendingTtsStore>,
        limiter: Arc<Mutex<RateLimiter>>,
    ) -> Self {
        Self {
            identity,
            pending_tts: Some(pending_tts),
            limiter: Some(limiter),
        }
    }

    /// Fully owned context with fresh stores for `identity`.
    pub fn with_owned_stores(identity: RequestIdentity) -> Self {
        Self::new(
            identity,
            Arc::new(PendingTtsStore::new()),
            Arc::new(Mutex::new(RateLimiter::new())),
        )
    }

    /// The single identity for this router; the same value is installed as
    /// the legacy `RequestIdentity` extension.
    pub fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// Pending-token store for all three TTS endpoints. Owned when present,
    /// otherwise the existing process-global store. Crate-internal; the
    /// public surface stays narrow.
    pub(crate) fn pending_tts(&self) -> &PendingTtsStore {
        match &self.pending_tts {
            Some(store) => store.as_ref(),
            None => crate::tts::global_pending_store(),
        }
    }

    /// Rate-limit check against this router's counters, or the
    /// process-global limiter for compatibility contexts. Limits come from
    /// live config at the call site; only the counters are owned here.
    /// Crate-internal; handlers reach it through the middleware.
    pub(crate) fn check_rate_limit(
        &self,
        key: &str,
        per_user_limit: u32,
        global_limit: u32,
    ) -> Result<(), RateLimitExceeded> {
        match &self.limiter {
            Some(limiter) => limiter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .check(key, per_user_limit, global_limit),
            None => rate_limit::check(key, per_user_limit, global_limit),
        }
    }

    /// Resolve the services installed by the router layer. Panics when the
    /// route was built without them — a construction bug, never a client
    /// error. All public constructors install them.
    pub fn from_extensions(extensions: &Extensions) -> Self {
        extensions.get::<AppServices>().cloned().expect(
            "app services extension missing; build the router with \
             build_router(), build_router_with_identity(), or \
             build_router_with_services()",
        )
    }
}
