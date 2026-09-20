//! Owned lazy history for `ChatService::with_storage`.
//!
//! Construction must not touch the filesystem; the first `history()` call
//! opens `{data_root}/history/redb` via `open_with_data_dir`. A blocked root
//! fails that call without freezing the service: repairing the fixture lets
//! the same service retry successfully through `get_or_try_init`.

use std::sync::Arc;

use chatbot_core::history::HistoryError;
use chatbot_core::session::{ChatService, ChatSessionStore};

fn make_lazy(data_root: &std::path::Path) -> ChatService {
    let sessions = Arc::new(ChatSessionStore::new(
        3600,
        "lazy prompt".to_owned(),
    ));
    ChatService::with_storage(
        sessions,
        data_root.to_path_buf(),
        data_root.join("accounts"),
        "lazy-secret".to_owned(),
    )
}

#[test]
fn construction_creates_no_history_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_root = temp.path().join("data");
    let redb_path = data_root.join("history").join("redb");
    let _service = make_lazy(&data_root);
    assert!(
        !redb_path.exists(),
        "with_storage must not open the database at construction"
    );
    assert!(
        !data_root.join("history").exists(),
        "with_storage must not create the history dir at construction"
    );
}

#[test]
fn first_history_opens_expected_root_and_clone_reuses_same_service() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_root = temp.path().join("data");
    let redb_path = data_root.join("history").join("redb");
    let service = make_lazy(&data_root);
    let clone = service.clone();

    let history = service.history().expect("first open succeeds");
    assert_eq!(
        history.db_path(),
        redb_path.as_path(),
        "lazy open must use the explicit data root"
    );
    assert!(
        redb_path.exists(),
        "first history() must create the database file"
    );

    let via_clone = clone.history().expect("clone sees the opened history");
    assert!(
        std::ptr::eq(history, via_clone),
        "clone must reuse the same opened service, not a second open"
    );
    assert_eq!(via_clone.db_path(), redb_path.as_path());
}

#[test]
fn blocked_root_errors_then_same_service_retries_successfully_after_repair() {
    let temp = tempfile::tempdir().expect("tempdir");
    let blocked = temp.path().join("blocked");
    std::fs::write(&blocked, b"regular file where a directory is needed")
        .expect("write blocking fixture");

    let service = make_lazy(&blocked);
    let err = match service.history() {
        Ok(_) => panic!("blocked root must fail"),
        Err(err) => err,
    };
    assert!(
        matches!(err, HistoryError::Internal),
        "blocked open maps to Internal, got: {err:?}"
    );

    std::fs::remove_file(&blocked).expect("remove blocking fixture");
    std::fs::create_dir_all(&blocked).expect("repair data root");
    let history = service
        .history()
        .expect("same service must retry successfully after repair");
    let expected = blocked.join("history").join("redb");
    assert_eq!(history.db_path(), expected.as_path());
    assert!(expected.exists(), "retry must create the database file");

    let clone = service.clone();
    let via_clone = clone.history().expect("clone reuses repaired open");
    assert!(std::ptr::eq(history, via_clone));
}
