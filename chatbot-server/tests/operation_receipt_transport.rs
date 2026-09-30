use axum::{
    body::to_bytes,
    http::{HeaderMap, HeaderValue, StatusCode},
};
use chatbot_core::{
    enc_key::EncryptionKey,
    operation_receipt::{OperationId, OperationRequest, Receipt, ReceiptOutcome},
};
use chatbot_server::idempotency::{operation_request, replay, InFlightOperations};
use serde_json::json;
use std::sync::Arc;

#[test]
fn header_transport_is_optional_and_rejects_duplicates() {
    let mut headers = HeaderMap::new();
    assert!(operation_request(&headers, "/create_set", &json!({}))
        .unwrap()
        .is_none());
    headers.insert(
        "idempotency-key",
        HeaderValue::from_static("operation-request-123"),
    );
    assert!(operation_request(&headers, "/create_set", &json!({}))
        .unwrap()
        .is_some());
    headers.append(
        "idempotency-key",
        HeaderValue::from_static("operation-request-456"),
    );
    assert!(operation_request(&headers, "/create_set", &json!({})).is_err());
}

#[test]
fn encrypted_receipts_bind_owner_and_operation() {
    let key = EncryptionKey::from_header_value("test-user-data-key").unwrap();
    let request = OperationRequest::new(
        OperationId::parse("operation-request-123").unwrap(),
        "/fork_set",
        &json!({"pair_index":1}),
    );
    let receipt = Receipt::new(
        &request,
        ReceiptOutcome::Applied,
        200,
        b"sensitive response".to_vec(),
        10,
    );
    let sealed = receipt.seal("alice", &key).unwrap();
    assert!(!sealed
        .windows(receipt.body.len())
        .any(|bytes| bytes == receipt.body));
    assert_eq!(
        Receipt::open("alice", &request.id, &sealed, &key)
            .unwrap()
            .body,
        receipt.body
    );
    assert!(Receipt::open("bob", &request.id, &sealed, &key).is_err());
    assert!(Receipt::open(
        "alice",
        &OperationId::parse("operation-request-456").unwrap(),
        &sealed,
        &key
    )
    .is_err());
}

#[tokio::test]
async fn replay_preserves_status_and_body() {
    let request = OperationRequest::new(
        OperationId::parse("operation-request-123").unwrap(),
        "/delete_set",
        &json!({}),
    );
    let receipt = Receipt::new(
        &request,
        ReceiptOutcome::Rejected,
        409,
        br#"{"error":"version_conflict"}"#.to_vec(),
        10,
    );
    let response = replay(&receipt).unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        receipt.body
    );
}

#[tokio::test]
async fn in_flight_guard_serializes_same_owner_and_id_only() {
    let guards = Arc::new(InFlightOperations::default());
    let id = OperationId::parse("operation-request-123").unwrap();
    let first = guards.acquire("alice", &id).await;
    let second_future = guards.acquire("alice", &id);
    tokio::pin!(second_future);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), &mut second_future)
            .await
            .is_err()
    );
    let other_owner = guards.acquire("bob", &id).await;
    drop(other_owner);
    drop(first);
    let second = second_future.await;
    drop(second);
}
