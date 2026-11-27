use chatbot_core::{
    enc_key::EncryptionKey,
    history::{HistoryError, HistoryService, SetVersion},
    operation_receipt::{OperationId, OperationRequest, ReceiptClock, RECEIPT_TTL_SECS},
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
fn fork_receipts_replay_rejections_reject_reuse_and_expire() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(100)));
    let history =
        HistoryService::open_with_data_dir(root.path().join("history"), root.path(), "prompt")
            .unwrap()
            .with_receipt_clock(clock.clone());
    let key = EncryptionKey::from_header_value("data-key").unwrap();
    let source = history.create_set("alice", "Source", &key).unwrap();
    let version = history
        .append_pair(
            "alice",
            source.set_id,
            source.version,
            "question",
            "answer",
            &key,
        )
        .unwrap();
    let request = OperationRequest::new(
        OperationId::parse("fork-operation-1234").unwrap(),
        "/fork_set",
        &json!({"pair_index":0}),
    );
    let rejected = history
        .fork_operation(
            "alice",
            source.set_id,
            Some(SetVersion(0)),
            0,
            None,
            &key,
            &request,
        )
        .unwrap();
    assert_eq!(rejected.status, 409);
    assert_eq!(
        history
            .fork_operation(
                "alice",
                source.set_id,
                Some(version),
                0,
                None,
                &key,
                &request
            )
            .unwrap()
            .body,
        rejected.body
    );
    let changed = OperationRequest::new(request.id.clone(), "/fork_set", &json!({"pair_index":1}));
    assert!(matches!(
        history.fork_operation(
            "alice",
            source.set_id,
            Some(version),
            0,
            None,
            &key,
            &changed
        ),
        Err(HistoryError::InvalidInput("operation_id_reused"))
    ));
    assert!(history
        .fork_receipt("bob", &request, &key)
        .unwrap()
        .is_none());
    clock.0.store(100 + RECEIPT_TTL_SECS, Ordering::SeqCst);
    let applied = history
        .fork_operation(
            "alice",
            source.set_id,
            Some(version),
            0,
            None,
            &key,
            &request,
        )
        .unwrap();
    assert_eq!(applied.status, 200);
}

#[test]
fn concurrent_forks_with_same_operation_create_one_set() {
    let root = tempfile::tempdir().unwrap();
    let history = Arc::new(
        HistoryService::open_with_data_dir(root.path().join("history"), root.path(), "prompt")
            .unwrap(),
    );
    let key = EncryptionKey::from_header_value("data-key").unwrap();
    let source = history.create_set("alice", "Source", &key).unwrap();
    let version = history
        .append_pair(
            "alice",
            source.set_id,
            source.version,
            "question",
            "answer",
            &key,
        )
        .unwrap();
    let request = OperationRequest::new(
        OperationId::parse("fork-operation-1234").unwrap(),
        "/fork_set",
        &json!({"pair_index":0}),
    );
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let history = history.clone();
            let key = key.clone();
            let request = request.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                history
                    .fork_operation(
                        "alice",
                        source.set_id,
                        Some(version),
                        0,
                        None,
                        &key,
                        &request,
                    )
                    .unwrap()
                    .body
            })
        })
        .collect();
    let bodies: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(
        history
            .list_sets("alice", &key)
            .unwrap()
            .iter()
            .filter(|s| s.display_name.starts_with("Source - branch"))
            .count(),
        1
    );
}
