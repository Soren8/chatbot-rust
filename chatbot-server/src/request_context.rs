//! Bounded request-transport extraction.
//!
//! Raw HTTP header parsing only: `Cookie` / `X-CSRF-Token` / client IP.
//! No session lookup, no CSRF validation, no auth decisions, no logging.

use axum::{
    extract::ConnectInfo,
    http::{header, Extensions, HeaderMap, StatusCode},
};
use std::net::SocketAddr;

use chatbot_core::{
    enc_key::EncryptionKey,
    session::{ChatService, SessionContext},
};

use crate::http_error::{api_error, map_encryption_key_validation_err, map_session_err, HttpError};
use crate::identity::RequestIdentity;

/// Owned `Cookie` header value (`None` when absent or malformed UTF-8).
pub fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    extract_cookie_ref(headers).map(|s| s.to_owned())
}

/// Borrowed `Cookie` header value (`None` when absent or malformed UTF-8).
///
/// Exists so borrowed call sites (rate-limit identity) keep zero-copy
/// semantics instead of being forced through the owned adapter.
pub fn extract_cookie_ref(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
}

/// Borrowed `X-CSRF-Token` header value (`None` when absent or malformed UTF-8).
pub fn extract_csrf(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
}

pub fn get_ip(headers: &HeaderMap, extensions: &Extensions) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Guest-capable data request context: resolved session plus optional key.
///
/// Preserves the data-route order: key selection (`X-Enc-Key` / account /
/// generic via the existing key-cookie module) first, then
/// `session_context` with its create-on-lookup guest semantics. No key
/// validation here: direct routes use [`DataRequestContext::require_authenticated`],
/// chat/regenerate use [`DataRequestContext::into_unverified_parts`] and rely
/// on core prepare validation later.
#[derive(Debug)]
pub struct DataRequestContext {
    session: SessionContext,
    encryption_key: Option<EncryptionKey>,
}

impl DataRequestContext {
    /// Resolve session and optional key. `cookie_header` is the value already
    /// extracted for the CSRF check, so CSRF keeps preceding key errors.
    /// `session_error_context` preserves the per-route session-error label.
    pub fn resolve(
        identity: &RequestIdentity,
        headers: &HeaderMap,
        cookie_header: Option<&str>,
        session_error_context: &'static str,
    ) -> Result<Self, HttpError> {
        let encryption_key =
            crate::enc_key_cookies::extract_enc_key_with_identity(identity, headers);
        let session = identity
            .session_context(cookie_header)
            .map_err(|err| map_session_err(err, session_error_context))?;
        Ok(Self {
            session,
            encryption_key,
        })
    }

    /// Resolve for `GET /history_image/...`, which also accepts the
    /// `<img>`-only `hist_enc_key` cookie. Order and session semantics match
    /// [`Self::resolve`].
    pub fn resolve_for_history_image(
        identity: &RequestIdentity,
        headers: &HeaderMap,
        cookie_header: Option<&str>,
        session_error_context: &'static str,
    ) -> Result<Self, HttpError> {
        let encryption_key =
            crate::enc_key_cookies::extract_enc_key_with_identity(identity, headers)
                .or_else(|| extract_hist_enc_cookie(cookie_header));
        let session = identity
            .session_context(cookie_header)
            .map_err(|err| map_session_err(err, session_error_context))?;
        Ok(Self {
            session,
            encryption_key,
        })
    }

    pub fn session(&self) -> &SessionContext {
        &self.session
    }

    /// Presented key, explicitly unverified.
    pub fn unverified_encryption_key(&self) -> Option<&EncryptionKey> {
        self.encryption_key.as_ref()
    }

    /// Owned session plus optional key for chat/regenerate prepare, still
    /// unverified until core prepare validates it.
    pub fn into_unverified_parts(self) -> (SessionContext, Option<EncryptionKey>) {
        (self.session, self.encryption_key)
    }

    /// Required-auth adapter. Guests get the exact `Not authenticated` 401;
    /// otherwise validates through the router's [`ChatService`]. Borrows the
    /// proven pair; core/history calls still own later validation.
    pub fn require_authenticated(
        &self,
        chat: &ChatService,
    ) -> Result<VerifiedDataContext<'_>, HttpError> {
        let username = match self.session.username.as_deref() {
            Some(value) => value,
            None => {
                return Err(api_error(StatusCode::UNAUTHORIZED, "Not authenticated"));
            }
        };
        if let Err(err) =
            chat.validate_encryption_key_for_user(username, self.encryption_key.as_ref())
        {
            return Err(map_encryption_key_validation_err(err));
        }
        let key = self.encryption_key.as_ref().expect("validated encryption key");
        Ok(VerifiedDataContext::verified(username, &self.session, key))
    }
}

/// Proven authenticated pair. Fields and construction stay private; only
/// [`DataRequestContext::require_authenticated`] (which validates through
/// [`ChatService`]) can create one. Borrows the context, so no key or
/// session clone is made.
#[derive(Debug)]
pub struct VerifiedDataContext<'a> {
    username: &'a str,
    session: &'a SessionContext,
    key: &'a EncryptionKey,
}

impl<'a> VerifiedDataContext<'a> {
    fn verified(username: &'a str, session: &'a SessionContext, key: &'a EncryptionKey) -> Self {
        Self {
            username,
            session,
            key,
        }
    }

    pub fn username(&self) -> &'a str {
        self.username
    }

    pub fn session(&self) -> &'a SessionContext {
        self.session
    }

    pub fn key(&self) -> &'a EncryptionKey {
        self.key
    }
}

fn extract_hist_enc_cookie(cookie_header: Option<&str>) -> Option<EncryptionKey> {
    let header = cookie_header?;
    for part in header.split(';') {
        let part = part.trim();
        let Some(value) = part.strip_prefix("hist_enc_key=") else {
            continue;
        };
        let decoded = urlencoding::decode(value).ok()?;
        return EncryptionKey::from_header_value(decoded.as_ref());
    }
    None
}
