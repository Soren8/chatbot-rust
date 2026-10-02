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
use std::sync::{Arc, Mutex, OnceLock};
use once_cell::sync::Lazy;
use regex::Regex;
use axum::{body::Body, http::{header, Method, Request}};
use chatbot_server::{build_router, resolve_static_root};
use tower::ServiceExt;

mod common;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).unwrap());

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn stt_rejects_invalid_idempotency_keys_over_http() {
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    let _workspace = common::TestWorkspace::with_openai_provider();
    std::env::set_var("SECRET_KEY", "operation_receipt_transport_secret");
    let app = build_router(resolve_static_root());
    let home = app.clone().oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    let cookie = common::extract_cookie(home.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap());
    let bytes = to_bytes(home.into_body(), 256 * 1024).await.unwrap();
    let csrf = CSRF_META_RE.captures(std::str::from_utf8(&bytes).unwrap()).unwrap()[1].to_owned();
    let keys = vec![String::new(), "short".to_owned(), "a".repeat(129), "invalid/key-value".to_owned()];
    for key in keys {
        let form = "--boundary\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"voice.webm\"\r\nContent-Type: audio/webm\r\n\r\naudio\r\n--boundary--\r\n";
        let response = app.clone().oneshot(Request::builder().method(Method::POST).uri("/stt")
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=boundary")
            .header(header::COOKIE, &cookie).header("X-CSRF-Token", &csrf).header("Idempotency-Key", key)
            .body(Body::from(form)).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), br#"{"error":"invalid_operation_id"}"#);
    }
}


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

#[test]
fn receipt_open_reports_truncated_framing_and_tampered_ciphertext() {
    let key = EncryptionKey::from_header_value("test-user-data-key").unwrap();
    let request = OperationRequest::new(
        OperationId::parse("operation-request-123").unwrap(),
        "/fork_set",
        &json!({"pair_index":1}),
    );
    let receipt = Receipt::new(&request, ReceiptOutcome::Applied, 200, b"body".to_vec(), 10);
    let sealed = receipt.seal("alice", &key).unwrap();

    assert_eq!(
        Receipt::open("alice", &request.id, &sealed[..27], &key).unwrap_err(),
        "receipt framing"
    );
    let mut tampered = sealed;
    tampered[12] ^= 1;
    assert_eq!(
        Receipt::open("alice", &request.id, &tampered, &key).unwrap_err(),
        "receipt decryption"
    );
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
