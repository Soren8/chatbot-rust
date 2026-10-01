use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use axum::http::StatusCode;
use chatbot_core::config::{destination_is_eligible, PrivacyLevel};
use chatbot_core::config_source::DestinationPolicy;
use chatbot_core::history::SetId;
use chatbot_core::history::{HistoryError, HistoryService};
use chatbot_core::enc_key::EncryptionKey;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::http_error::{api_error_json, HttpError};

#[derive(Clone, Default)]
pub struct SetPrivacyCoordinator {
    locks: Arc<Mutex<HashMap<(String, SetId), Weak<RwLock<()>>>>>,
}

pub struct ContentPermit {
    _guard: OwnedRwLockReadGuard<()>,
}
pub struct UpdatePermit {
    _guard: OwnedRwLockWriteGuard<()>,
}

impl SetPrivacyCoordinator {
    fn lock_for(&self, user: &str, set_id: SetId) -> Arc<RwLock<()>> {
        let key = (user.trim().to_lowercase(), set_id);
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(RwLock::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    pub async fn content(&self, user: &str, set_id: SetId) -> ContentPermit {
        ContentPermit {
            _guard: self.lock_for(user, set_id).read_owned().await,
        }
    }

    pub fn try_update(&self, user: &str, set_id: SetId) -> Option<UpdatePermit> {
        self.lock_for(user, set_id)
            .try_write_owned()
            .ok()
            .map(|guard| UpdatePermit { _guard: guard })
    }
}

pub fn resolve_content_set(
    history: &HistoryService,
    user: &str,
    set_id: Option<&str>,
    set_name: Option<&str>,
    key: &EncryptionKey,
) -> Result<SetId, HistoryError> {
    if let Some(raw) = set_id.filter(|id| !id.trim().is_empty()) {
        let id = SetId::parse(raw).map_err(|_| HistoryError::InvalidInput("invalid set_id"))?;
        return match history.ensure_owned(user, id, key) {
            Ok(()) => Ok(id),
            Err(HistoryError::Forbidden) => Err(HistoryError::NotFound),
            Err(err) => Err(err),
        };
    }
    let name = set_name.map(str::trim).filter(|name| !name.is_empty()).unwrap_or("default");
    match history.find_summary_by_display_name(user, name, key)? {
        Some(summary) => Ok(summary.set_id),
        None if name == "default" => Ok(history.ensure_default_set_id(user, key)?),
        None => Err(HistoryError::NotFound),
    }
}

pub fn map_resolution_error(err: HistoryError) -> crate::http_error::HttpError {
    match err {
        HistoryError::NotFound => crate::http_error::map_prepare_history_err(
            &chatbot_core::session::PrepareHistoryError::NotFound,
        ),
        HistoryError::InvalidInput(message) => crate::http_error::map_prepare_history_err(
            &chatbot_core::session::PrepareHistoryError::InvalidInput(message),
        ),
        other => crate::chat_utils::history_error_to_http(other),
    }
}

/// Shared model/search destination eligibility for an already-bound chat
/// privacy level. Returns whether XAI native-search fallback stays permitted.
///
/// Both `/chat` and `/regenerate` map violations to identical 403 responses,
/// so this check is shared; their prepare-error handling and leases stay
/// per route.
pub fn check_destination_eligibility(
    level: PrivacyLevel,
    policy: Option<&DestinationPolicy>,
    selected_model: &str,
    provider_type: &str,
    xai_search: bool,
    web_search: bool,
) -> Result<bool, HttpError> {
    let model_level = policy.and_then(|p| p.provider(selected_model)).unwrap_or(PrivacyLevel::NonPrivate);
    if !destination_is_eligible(level, model_level) {
        return Err(api_error_json(StatusCode::FORBIDDEN, serde_json::json!({"error":"privacy_restricted","destination":"model"})));
    }
    let mut allow_native_search_fallback = true;
    if web_search {
        let native = provider_type == "xai" && xai_search;
        let search_level = if native { policy.map(|p| p.xai_native_search).unwrap_or(PrivacyLevel::NonPrivate) } else { policy.map(|p| p.brave_search).unwrap_or(PrivacyLevel::NonPrivate) };
        if !destination_is_eligible(level, search_level) {
            return Err(api_error_json(StatusCode::FORBIDDEN, serde_json::json!({"error":"privacy_restricted","destination":if native {"native_search"} else {"brave_search"}})));
        }
        if provider_type == "xai" && !native {
            let native_level = policy.map(|p| p.xai_native_search).unwrap_or(PrivacyLevel::NonPrivate);
            allow_native_search_fallback = destination_is_eligible(level, native_level);
        }
    }
    Ok(allow_native_search_fallback)
}
