//! Narrow request-scoped HTTP identity context (MOD-003).
//!
//! Every route handler and middleware resolves its session identity through
//! [`RequestIdentity`], read from the request extensions installed by
//! [`crate::build_router`] / [`crate::build_router_with_identity`] /
//! [`crate::build_router_with_services`]. There is
//! one lookup path: handlers never call the `chatbot_core::session` identity
//! free functions directly.
//!
//! The default router carries [`RequestIdentity::global`], which delegates to
//! the same single process-global store behind those free functions —
//! including their lazy first-use initialization and early returns — so
//! existing fixtures that bootstrap via the global API keep matching.
//! [`RequestIdentity::with_store`] / `with_store_and_csrf` back a router
//! with an independent [`HttpSessionStore`]; two such routers share no
//! cookies, CSRF tokens, or login bindings.
//!
//! Only identity plus its CSRF request config is scoped here. Full
//! per-router resource composition (this identity plus TTS pending tokens
//! plus rate-limit counters plus chat/accounts/generation/policies/config)
//! lives in [`crate::services::AppServices`]; that context installs this same
//! identity value as the legacy extension, so the two never diverge. Chat
//! history, the remember store and user store stay process-global unless an
//! explicit [`crate::services::AppServices`] backs them.

use std::sync::Arc;

use axum::http::Extensions;
use chatbot_core::config_source::ConfigSource;
use chatbot_core::session_identity::{
    self, HomeBootstrap, HttpSessionStore, LoginFinalize, LogoutFinalize, SessionContext,
    SessionError,
};

/// Request-scoped HTTP identity: either the shared process-global store or
/// an explicitly owned one. Cloned into every request by the router layer.
#[derive(Clone)]
pub struct RequestIdentity {
    store: Option<Arc<HttpSessionStore>>,
    csrf_override: Option<bool>,
    config: ConfigSource,
}

impl RequestIdentity {
    /// Compatibility identity: delegates to the single process-global store
    /// behind the `chatbot_core::session` free functions. Constructing this
    /// touches neither config nor the global store, so installing it in
    /// [`crate::build_router`] preserves the lazy first-use freeze.
    pub fn global() -> Self {
        Self {
            store: None,
            csrf_override: None,
            config: ConfigSource::global(),
        }
    }

    /// Independent identity backed by `store`. The CSRF policy stays live
    /// from the global config, exactly like the compatibility path.
    /// Use [`RequestIdentity::with_store_and_config`] for an owned policy.
    pub fn with_store(store: Arc<HttpSessionStore>) -> Self {
        Self {
            store: Some(store),
            csrf_override: None,
            config: ConfigSource::global(),
        }
    }

    /// Independent identity with an explicit CSRF policy, immune to ambient
    /// config. Prefer [`RequestIdentity::with_store_and_config`] for full
    /// request-config ownership; this bool form stays for focused CSRF tests.
    /// The override wins over any [`ConfigSource`] set later via
    /// [`RequestIdentity::with_config_source`].
    pub fn with_store_and_csrf(store: Arc<HttpSessionStore>, csrf_enabled: bool) -> Self {
        Self {
            store: Some(store),
            csrf_override: Some(csrf_enabled),
            config: ConfigSource::global(),
        }
    }

    /// Independent identity with an explicit request config, immune to ambient
    /// config. The CSRF flag resolves from `config` unless an explicit
    /// override was set via [`RequestIdentity::with_store_and_csrf`].
    /// Requires an owned store; the global store stays on the live path
    /// unless [`RequestIdentity::with_config_source`] is used to scope it.
    pub fn with_store_and_config(store: Arc<HttpSessionStore>, config: ConfigSource) -> Self {
        Self {
            store: Some(store),
            csrf_override: None,
            config,
        }
    }

    /// Scope this identity (owned or global store) to an explicit request
    /// config, preserving any explicit CSRF override. Both stores resolve
    /// CSRF from `config` (one read per call when live, none when owned);
    /// the global store keeps its records and store-first first-use order.
    /// Used by [`crate::services::AppServices::with_config_source`] so the
    /// router identity and the services config stay a single source. For full
    /// session isolation use [`RequestIdentity::with_store_and_config`].
    pub fn with_config_source(mut self, config: ConfigSource) -> Self {
        self.config = config;
        self
    }

    /// The request config backing CSRF resolution for this identity.
    pub fn config_source(&self) -> ConfigSource {
        self.config.clone()
    }

    fn csrf_enabled(&self) -> bool {
        self.csrf_override.unwrap_or_else(|| self.config.csrf())
    }

    /// Resolve the identity installed by the router layer. Panics when the
    /// route was built without one — a construction bug, never a client
    /// error — so injected routers can never silently fall back to the
    /// global store. Both public constructors install it.
    pub fn from_extensions(extensions: &Extensions) -> Self {
        extensions.get::<RequestIdentity>().cloned().expect(
            "request identity extension missing; build the router with \
             build_router(), build_router_with_identity(), or \
             build_router_with_services()",
        )
    }

    pub fn prepare_home_context(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<HomeBootstrap, SessionError> {
        // Store-first with scoped CSRF: init the backing store before
        // resolving the flag, matching the free-function first-use order.
        // Owned stores never touch globals; the global store keeps its
        // records with per-identity CSRF.
        match &self.store {
            None => {
                let store = HttpSessionStore::global();
                let csrf = self.csrf_enabled();
                store.prepare_home_context(cookie_header, csrf)
            }
            Some(store) => store.prepare_home_context(cookie_header, self.csrf_enabled()),
        }
    }

    pub fn validate_csrf_token(
        &self,
        cookie_header: Option<&str>,
        token: Option<&str>,
    ) -> Result<bool, SessionError> {
        // Same disabled/missing/empty early returns before global init as the
        // free function; the flag is scoped per identity.
        match &self.store {
            None => session_identity::validate_csrf_token_with_csrf(
                cookie_header,
                token,
                self.csrf_enabled(),
            ),
            Some(store) => {
                store.validate_csrf_token(cookie_header, token, self.csrf_enabled())
            }
        }
    }

    pub fn session_context(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<SessionContext, SessionError> {
        match &self.store {
            None => session_identity::session_context(cookie_header),
            Some(store) => store.session_context(cookie_header),
        }
    }

    /// Stable rate-limit identity without creating a session. Preserves the
    /// unknown-cookie fallback (`guest:{cookie}`); callers fall back to an
    /// IP key when this returns `None`.
    pub fn rate_limit_identity(&self, cookie_header: Option<&str>) -> Option<String> {
        match &self.store {
            None => session_identity::rate_limit_identity(cookie_header),
            Some(store) => store.rate_limit_identity(cookie_header),
        }
    }

    pub fn finalize_login(
        &self,
        cookie_header: Option<&str>,
        username: &str,
    ) -> Result<LoginFinalize, SessionError> {
        // Store-first with scoped CSRF; see `prepare_home_context`.
        match &self.store {
            None => {
                let store = HttpSessionStore::global();
                let csrf = self.csrf_enabled();
                store.finalize_login(cookie_header, username, csrf)
            }
            Some(store) => store.finalize_login(cookie_header, username, self.csrf_enabled()),
        }
    }

    pub fn logout_user(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<LogoutFinalize, SessionError> {
        // Store-first with scoped CSRF; see `prepare_home_context`.
        match &self.store {
            None => {
                let store = HttpSessionStore::global();
                let csrf = self.csrf_enabled();
                store.logout_user(cookie_header, csrf)
            }
            Some(store) => store.logout_user(cookie_header, self.csrf_enabled()),
        }
    }

    /// Purge step for the background task, returning
    /// `(http_removed, chat_removed)`. The global identity runs one composed
    /// purge. An owned identity purges its own HTTP store plus the shared
    /// chat store; the global HTTP store is never touched here.
    pub fn purge_for_background(&self) -> (usize, usize) {
        match &self.store {
            None => {
                let stats = chatbot_core::session::purge_expired_sessions();
                (stats.http_sessions_removed, stats.chat_sessions_removed)
            }
            Some(store) => {
                let http_removed = store.purge_expired();
                let chat_removed = chatbot_core::session::purge_expired_chat_sessions();
                (http_removed, chat_removed)
            }
        }
    }

    /// HTTP-only purge step for composed [`crate::services::AppServices`]
    /// background tasks. Purges only this identity's HTTP store (global or
    /// owned) without touching any chat store, so an owned router can compose
    /// it with its own chat service and never initialize the unrelated global
    /// chat store. The legacy [`RequestIdentity::purge_for_background`] stays
    /// for identity-only callers.
    pub fn purge_http_for_background(&self) -> usize {
        match &self.store {
            None => chatbot_core::session::purge_expired_http_sessions(),
            Some(store) => store.purge_expired(),
        }
    }
}
