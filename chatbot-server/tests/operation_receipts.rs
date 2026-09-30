use chatbot_core::operation_receipt::{
    OperationId, OperationRequest, Receipt, ReceiptClock, ReceiptOutcome, RECEIPT_TTL_SECS,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct Clock(AtomicU64);
impl ReceiptClock for Clock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn operation_ids_are_bounded_url_safe_tokens() {
    assert!(OperationId::parse("a-valid_random-token_123").is_ok());
    for value in ["", "short", "has spaces-in-token", "../../operation"] {
        assert!(OperationId::parse(value).is_err());
    }
    assert!(OperationId::parse(&"x".repeat(129)).is_err());
}

#[test]
fn fingerprint_is_canonical_and_route_bound() {
    let id = OperationId::parse("test-operation-0001").unwrap();
    let first = OperationRequest::new(
        id.clone(),
        "/update_memory",
        &json!({"memory":"private", "expected_version": 1}),
    );
    let reordered = OperationRequest::new(
        id.clone(),
        "/update_memory",
        &json!({"expected_version": 1, "memory":"private"}),
    );
    assert_eq!(first.fingerprint, reordered.fingerprint);
    assert_ne!(
        first.fingerprint,
        OperationRequest::new(
            id.clone(),
            "/reset_chat",
            &json!({"memory":"private", "expected_version": 1})
        )
        .fingerprint
    );
    assert_ne!(
        first.fingerprint,
        OperationRequest::new(
            id,
            "/update_memory",
            &json!({"memory":"changed", "expected_version": 1})
        )
        .fingerprint
    );
}

#[test]
fn rejected_receipt_replays_and_expires_at_twenty_four_hours() {
    let clock = Arc::new(Clock(AtomicU64::new(100)));
    let request = OperationRequest::new(
        OperationId::parse("test-operation-0002").unwrap(),
        "/update_memory",
        &json!({"memory":"text"}),
    );
    let receipt = Receipt::new(
        &request,
        ReceiptOutcome::Rejected,
        409,
        br#"{"error":"version_conflict"}"#.to_vec(),
        clock.now_secs(),
    );
    assert!(!receipt.expired(clock.now_secs()));
    assert!(receipt.matches(&request));
    assert_eq!(receipt.body, br#"{"error":"version_conflict"}"#);
    clock.0.store(100 + RECEIPT_TTL_SECS - 1, Ordering::SeqCst);
    assert!(!receipt.expired(clock.now_secs()));
    clock.0.store(100 + RECEIPT_TTL_SECS, Ordering::SeqCst);
    assert!(receipt.expired(clock.now_secs()));
}
