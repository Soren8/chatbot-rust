//! Narrow application services context (MOD-003 resource composition).
//!
//! One owned [`AppServices`] bundles the per-router resources that must stay
//! isolated together: the HTTP identity store, the TTS pending-token store,
//! the rate-limit counters, and the chat service (session RAM mirror plus
//! durable history plus account-key/tier gates). Production builds one at
//! startup and clones it into every request via an Axum `Extension` layer;
//! the same identity value is also installed as the legacy `RequestIdentity`
//! extension so existing handlers keep working from a single source.
//!
//! Compatibility: [`AppServices::global`] and [`AppServices::with_identity`]
//! and [`AppServices::with_owned_stores`] resolve the chat dimension to the
//! existing process-global [`ChatService::global`] (lazy first-use timing
//! untouched). Use [`AppServices::with_chat_service`] to back a router with an
//! explicit chat service.
//!
//! Config-free state only, except the deliberate production root capture in
//! `run()`: token admission, rate windows, session mirrors, durable history
//! handles, and account roots/secrets live here. Live `app_config()` limits
//! (`rate_limit_*`, `tts_*`, providers, CSRF) and the user, remember,
//! login/signup/home/preferences, and voice-service configuration stay
//! process-global for now.

use std::sync::{Arc, Mutex};

use axum::http::Extensions;

use chatbot_core::rate_limit::{self, RateLimitExceeded, RateLimiter};
use chatbot_core::session::ChatService;

use crate::identity::RequestIdentity;
use crate::tts::store::PendingTtsStore;

/// Owned router resources: one identity plus one pending-token store plus one
/// rate-limit counter set plus one chat service. Cloned into every request;
/// the inner stores stay shared via `Arc`.
#[derive(Clone)]
pub struct AppServices {
    identity: RequestIdentity,
    pending_tts: Option<Arc<PendingTtsStore>>,
    limiter: Option<Arc<Mutex<RateLimiter>>>,
    chat: ChatService,
}

impl AppServices {
    /// Compatibility context: the global identity plus the existing global
    /// TTS, limiter, and chat stores, with their lazy first-use timing untouched.
    pub fn global() -> Self {
        Self {
            identity: RequestIdentity::global(),
            pending_tts: None,
            limiter: None,
            chat: ChatService::global(),
        }
    }

    /// Compatibility context for an owned identity: TTS tokens, rate-limit
    /// counters, and chat stay process-global. Prefer
    /// [`AppServices::with_owned_stores`] plus
    /// [`AppServices::with_chat_service`] for fully independent routers.
    pub fn with_identity(identity: RequestIdentity) -> Self {
        Self {
            identity,
            pending_tts: None,
            limiter: None,
            chat: ChatService::global(),
        }
    }

    /// Fully owned context: `pending_tts` and `limiter` back this router
    /// only. Tokens admitted here are unknown elsewhere; counters are
    /// independent. Chat stays process-global for compatibility; use
    /// [`AppServices::with_chat_service`] for an explicit chat service.
    /// Crate-internal: external callers use
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
            chat: ChatService::global(),
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

    /// Back this router with an explicit chat service (owned session mirror
    /// plus durable history plus account-key/tier gates). Consumes and
    /// returns `Self` so existing constructors keep their global-chat
    /// defaults while owned production and isolation tests opt in.
    pub fn with_chat_service(mut self, chat: ChatService) -> Self {
        self.chat = chat;
        self
    }

    /// The single identity for this router; the same value is installed as
    /// the legacy `RequestIdentity` extension.
    pub fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// The single chat service for this router: prepare/finalize, durable
    /// history, session mirror, key/tier gates, and generation leases all
    /// resolve through this handle. Compatibility contexts return the global
    /// handle; owned routers return their explicit service.
    pub fn chat(&self) -> &ChatService {
        &self.chat
    }

    /// Purge step for the background task, returning
    /// `(http_removed, chat_removed)`. Composes this router's HTTP store with
    /// this router's chat sessions, so a fully owned router never initializes
    /// or purges the unrelated global HTTP/chat stores. The remember store
    /// stays global.
    pub fn purge_for_background(&self) -> (usize, usize) {
        let http_removed = self.identity.purge_http_for_background();
        let chat_removed = self.chat.purge_expired_chat_sessions();
        (http_removed, chat_removed)
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
