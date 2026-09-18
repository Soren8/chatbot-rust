//! Narrow request-scoped HTTP identity context (MOD-003).
//!
//! Every route handler and middleware resolves its session identity through
//! [`RequestIdentity`], read from the request extensions installed by
//! [`crate::build_router`] / [`crate::build_router_with_identity`]. There is
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
//! Only identity is scoped here. Chat history, rate-limit counters, the
//! remember store, user store, and configuration stay process-global.

use std::sync::Arc;

use axum::http::Extensions;
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
        }
    }

    /// Independent identity backed by `store`. The CSRF policy stays live
    /// from the global config, exactly like the compatibility path.
    pub fn with_store(store: Arc<HttpSessionStore>) -> Self {
        Self {
            store: Some(store),
            csrf_override: None,
        }
    }

    /// Independent identity with an explicit CSRF policy, immune to ambient
    /// config. Prefer this in tests that assert CSRF behavior.
    pub fn with_store_and_csrf(store: Arc<HttpSessionStore>, csrf_enabled: bool) -> Self {
        Self {
            store: Some(store),
            csrf_override: Some(csrf_enabled),
        }
    }

    fn csrf_enabled(&self) -> bool {
        self.csrf_override
            .unwrap_or_else(|| chatbot_core::config::app_config().csrf)
    }

    /// Resolve the identity installed by the router layer. Panics when the
    /// route was built without one — a construction bug, never a client
    /// error — so injected routers can never silently fall back to the
    /// global store. Both public constructors install it.
    pub fn from_extensions(extensions: &Extensions) -> Self {
        extensions.get::<RequestIdentity>().cloned().expect(
            "request identity extension missing; build the router with \
             build_router() or build_router_with_identity()",
        )
    }

    pub fn prepare_home_context(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<HomeBootstrap, SessionError> {
        match &self.store {
            None => session_identity::prepare_home_context(cookie_header),
            Some(store) => store.prepare_home_context(cookie_header, self.csrf_enabled()),
        }
    }

    pub fn validate_csrf_token(
        &self,
        cookie_header: Option<&str>,
        token: Option<&str>,
    ) -> Result<bool, SessionError> {
        match &self.store {
            None => session_identity::validate_csrf_token(cookie_header, token),
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
        match &self.store {
            None => session_identity::finalize_login(cookie_header, username),
            Some(store) => store.finalize_login(cookie_header, username, self.csrf_enabled()),
        }
    }

    pub fn logout_user(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<LogoutFinalize, SessionError> {
        match &self.store {
            None => session_identity::logout_user(cookie_header),
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
}
