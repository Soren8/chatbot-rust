//! HTTP transport for transaction-owned operation receipts.
use std::{
    collections::HashMap,
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

/// RAM-only STT transcripts and per-operation admission serialization.
#[derive(Default)]
pub(crate) struct SttReceipts {
    receipts: Mutex<HashMap<(String, String), Receipt>>,
    pub(crate) voice_operations: InFlightOperations,
}
impl SttReceipts {
    pub(crate) fn replay(&self, owner: &str, operation: &OperationRequest) -> Result<Option<Response<Body>>, HttpError> {
        use chatbot_core::operation_receipt::{ReceiptClock, SystemReceiptClock};
        let mut receipts = self.receipts.lock().unwrap_or_else(|e| e.into_inner());
        let now = SystemReceiptClock.now_secs();
        receipts.retain(|_, receipt| !receipt.expired(now));
        match receipts.get(&(owner.into(), operation.id.as_str().into())) {
            Some(receipt) if !receipt.matches(operation) => Err(reused()),
            Some(receipt) => replay(receipt).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn record(&self, owner: &str, operation: &OperationRequest, status: StatusCode, value: impl serde::Serialize) {
        use chatbot_core::operation_receipt::{ReceiptClock, ReceiptOutcome, SystemReceiptClock};
        let outcome = if status.is_success() { ReceiptOutcome::Applied } else { ReceiptOutcome::Rejected };
        let receipt = Receipt::new(operation, outcome, status.as_u16(), serde_json::to_vec(&value).expect("receipt"), SystemReceiptClock.now_secs());
        self.receipts.lock().unwrap_or_else(|e| e.into_inner())
            .insert((owner.into(), operation.id.as_str().into()), receipt);
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
