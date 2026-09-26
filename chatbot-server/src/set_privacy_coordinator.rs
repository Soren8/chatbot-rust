use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use chatbot_core::history::SetId;
use chatbot_core::history::{HistoryError, HistoryService};
use chatbot_core::enc_key::EncryptionKey;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

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
        if !history.list_sets(user, key)?.iter().any(|summary| summary.set_id == id) {
            return Err(HistoryError::NotFound);
        }
        return Ok(id);
    }
    let name = set_name.map(str::trim).filter(|name| !name.is_empty()).unwrap_or("default");
    match history.list_sets(user, key)?.into_iter().find(|summary| summary.display_name == name) {
        Some(summary) => Ok(summary.set_id),
        None if name == "default" => Ok(history.ensure_default_set(user, key)?.set_id),
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
