use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::{HistoryError, HistoryService};

#[test]
fn warm_snapshot_rejects_wrong_key_like_cold_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.redb");
    let correct =
        EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
            .unwrap();
    let wrong =
        EncryptionKey::from_header_value("d3Jvbmcta2V5LW1hdGVyaWFsLTEyMzQ1Njc4OTAxMjM0NTY=")
            .unwrap();
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let created = svc.create_set("alice", "private", &correct).unwrap();
    svc.append_pair(
        "alice",
        created.set_id,
        created.version,
        "secret",
        "answer",
        &correct,
    )
    .unwrap();
    let warm = svc.load_logical("alice", created.set_id, &correct).unwrap();
    assert_eq!(warm.history, vec![("secret".into(), "answer".into())]);

    assert!(
        matches!(
            svc.load_logical("alice", created.set_id, &wrong),
            Err(HistoryError::DecryptFailed)
        ),
        "wrong key must not return a cached plaintext snapshot"
    );
    drop(svc);

    let cold = HistoryService::open_ephemeral(&path).unwrap();
    assert!(
        matches!(
            cold.load_logical("alice", created.set_id, &wrong),
            Err(HistoryError::DecryptFailed)
        ),
        "wrong key must also fail without a cached snapshot"
    );
}
