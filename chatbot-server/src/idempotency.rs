//! HTTP transport for transaction-owned operation receipts.
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
};

use axum::{
    body::Body,
    http::{header, HeaderMap, Response, StatusCode},
};
use chatbot_core::operation_receipt::{OperationId, OperationRequest, Receipt};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::http_error::{api_error, HttpError};

pub fn operation_request(
    headers: &HeaderMap,
    route: &str,
    semantic_body: &Value,
) -> Result<Option<OperationRequest>, HttpError> {
    let values: Vec<_> = headers.get_all("idempotency-key").iter().collect();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid_operation_id"));
    }
    let value = values[0]
        .to_str()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_operation_id"))?;
    let id = OperationId::parse(value)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_operation_id"))?;
    Ok(Some(OperationRequest::new(id, route, semantic_body)))
}

pub fn reused() -> HttpError {
    api_error(StatusCode::CONFLICT, "operation_id_reused")
}

pub fn replay(receipt: &Receipt) -> Result<Response<Body>, HttpError> {
    let status = StatusCode::from_u16(receipt.status)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid receipt"))?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(receipt.body.clone()))
        .expect("valid receipt response"))
}

/// Receipts kept per owner in each RAM receipt map; the owner's oldest is
/// evicted beyond this. Clients retry an operation within seconds and keep at
/// most a few in flight (generation admission is serialized per owner, voice
/// turns are sequential), so 64 is far above legitimate use while bounding
/// what one owner (including a guest replaying stale `/chat` 409s) can hold.
pub(crate) const MAX_RECEIPTS_PER_OWNER: usize = 64;
/// Minimum spacing of the sweep that drops expired receipts of idle owners.
const IDLE_OWNER_SWEEP_SECS: u64 = 60;

/// Owner-scoped RAM receipts in insertion order. Each insert prunes that
/// owner's expired receipts and evicts its oldest beyond the cap; idle owners
/// are swept at most once per `IDLE_OWNER_SWEEP_SECS`, so lookups never scan
/// other owners.
pub(crate) struct OwnerReceipts<T> {
    owners: HashMap<String, VecDeque<(Receipt, T)>>,
    next_sweep: u64,
}
impl<T> Default for OwnerReceipts<T> {
    fn default() -> Self {
        Self { owners: HashMap::new(), next_sweep: 0 }
    }
}
impl<T> OwnerReceipts<T> {
    pub(crate) fn get(&self, owner: &str, id: &OperationId, now: u64) -> Option<&(Receipt, T)> {
        self.owners
            .get(owner)?
            .iter()
            .find(|(receipt, _)| &receipt.operation_id == id && !receipt.expired(now))
    }

    pub(crate) fn insert(&mut self, owner: &str, receipt: Receipt, value: T) {
        let now = receipt.created_at;
        if now >= self.next_sweep {
            self.owners.retain(|_, receipts| {
                receipts.retain(|(receipt, _)| !receipt.expired(now));
                !receipts.is_empty()
            });
            self.next_sweep = now + IDLE_OWNER_SWEEP_SECS;
        }
        let receipts = self.owners.entry(owner.to_owned()).or_default();
        receipts.retain(|(old, _)| old.operation_id != receipt.operation_id && !old.expired(now));
        receipts.push_back((receipt, value));
        while receipts.len() > MAX_RECEIPTS_PER_OWNER {
            receipts.pop_front();
        }
    }

    #[cfg(test)]
    pub(crate) fn stored(&self, owner: &str) -> usize {
        self.owners.get(owner).map_or(0, VecDeque::len)
    }
}

/// RAM-only STT transcripts and per-operation admission serialization.
#[derive(Default)]
pub(crate) struct SttReceipts {
    receipts: Mutex<OwnerReceipts<()>>,
    pub(crate) voice_operations: InFlightOperations,
}
impl SttReceipts {
    pub(crate) fn replay(&self, owner: &str, operation: &OperationRequest) -> Result<Option<Response<Body>>, HttpError> {
        use chatbot_core::operation_receipt::{ReceiptClock, SystemReceiptClock};
        let receipts = self.receipts.lock().unwrap_or_else(|e| e.into_inner());
        match receipts.get(owner, &operation.id, SystemReceiptClock.now_secs()) {
            Some((receipt, _)) if !receipt.matches(operation) => Err(reused()),
            Some((receipt, _)) => replay(receipt).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn record(&self, owner: &str, operation: &OperationRequest, status: StatusCode, value: impl serde::Serialize) {
        use chatbot_core::operation_receipt::{ReceiptClock, ReceiptOutcome, SystemReceiptClock};
        let outcome = if status.is_success() { ReceiptOutcome::Applied } else { ReceiptOutcome::Rejected };
        let receipt = Receipt::new(operation, outcome, status.as_u16(), serde_json::to_vec(&value).expect("receipt"), SystemReceiptClock.now_secs());
        self.receipts.lock().unwrap_or_else(|e| e.into_inner()).insert(owner, receipt, ());
    }

    #[cfg(test)]
    fn stored(&self, owner: &str) -> usize {
        self.receipts.lock().unwrap().stored(owner)
    }
}

/// Per-owned-service serialization, including asynchronous connection checks.
/// Durable stores must still arbitrate using their own write transaction.
#[derive(Default)]
pub struct InFlightOperations {
    locks: Mutex<HashMap<(String, String), Weak<AsyncMutex<()>>>>,
}
impl InFlightOperations {
    pub async fn acquire(&self, owner: &str, id: &OperationId) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            locks.retain(|_, value| value.strong_count() > 0);
            let key = (owner.to_owned(), id.as_str().to_owned());
            match locks.get(&key).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    locks.insert(key, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chatbot_core::operation_receipt::OperationId;
    use serde_json::json;

    fn op(i: usize) -> OperationRequest {
        OperationRequest::new(OperationId::parse(&format!("op-{i:016}")).unwrap(), "/stt", &json!({}))
    }

    #[test]
    fn stt_receipts_are_capped_per_owner_without_touching_other_owners() {
        let receipts = SttReceipts::default();
        receipts.record("guest:other", &op(0), StatusCode::OK, json!({"text":"kept"}));
        for i in 0..10_000 {
            receipts.record("guest:flood", &op(i), StatusCode::OK, json!({"text":i}));
        }
        assert!(receipts.stored("guest:flood") <= MAX_RECEIPTS_PER_OWNER);
        assert_eq!(receipts.stored("guest:other"), 1);
        assert!(receipts.replay("guest:other", &op(0)).unwrap().is_some());
        let latest = receipts.replay("guest:flood", &op(9_999)).unwrap().expect("latest replays");
        assert_eq!(latest.status(), StatusCode::OK);
        assert!(receipts.replay("guest:flood", &op(0)).unwrap().is_none(), "oldest was evicted");
    }
}
