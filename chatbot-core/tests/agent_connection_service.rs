// Until the conductor installs the lib.rs export, exercise the production module directly.
mod account_service { pub use chatbot_core::account_service::*; }
mod enc_key { pub use chatbot_core::enc_key::*; }
mod names { pub use chatbot_core::names::*; }
#[path = "../src/agent_connections.rs"]
mod agent_connections;

use agent_connections::{ConnectionError, ConnectionInput, ConnectionPatch, ConnectionService};
use chatbot_core::account_service::AccountService;
use chatbot_core::enc_key::EncryptionKey;
use redb::{Database, ReadableTable, TableDefinition};

fn setup() -> (tempfile::TempDir, AccountService, EncryptionKey, ConnectionService) {
    let tmp = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(tmp.path().join("accounts"), "test-hmac-secret");
    let key = EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==").unwrap();
    let users = accounts.users().unwrap();
    for name in ["alice", "bob"] { users.ensure_key_verifier(name, key.as_bytes()).unwrap(); }
    let service = ConnectionService::open(tmp.path(), accounts.clone()).unwrap();
    (tmp, accounts, key, service)
}

fn input() -> ConnectionInput {
    ConnectionInput { name: "Personal sandbox".into(), base_url: "https://example.test/opencode".into(), username: "opencode".into(), password: "secret-password".into() }
}

#[test]
fn crud_reopen_and_redacted_storage() {
    let (tmp, accounts, key, service) = setup();
    let created = service.create("alice", &key, input()).unwrap();
    assert_eq!(created.revision, 1);
    assert!(created.has_password);
    assert_eq!(service.list("bob", &key).unwrap().len(), 0);
    assert_eq!(service.credentials("bob", &key, created.id).err(), Some(ConnectionError::NotFound));
    let updated = service.update("alice", &key, created.id, 1, ConnectionPatch { name: Some("New name".into()), ..Default::default() }).unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(service.credentials("alice", &key, created.id).unwrap().1.password, "secret-password");
    let path = tmp.path().join("connections/redb");
    drop(service);
    let bytes = std::fs::read(path).unwrap();
    for marker in ["Personal sandbox", "New name", "secret-password", "example.test", "opencode"] {
        assert!(!bytes.windows(marker.len()).any(|window| window == marker.as_bytes()));
    }
    let reopened = ConnectionService::open(tmp.path(), accounts).unwrap();
    assert!(reopened.list("alice", &key).unwrap() == vec![updated]);
    reopened.delete("alice", &key, created.id, 2).unwrap();
    assert!(reopened.list("alice", &key).unwrap().is_empty());
}

#[test]
fn revision_key_validation_and_cache_invalidation() {
    let (_tmp, _accounts, key, service) = setup();
    let created = service.create("alice", &key, input()).unwrap();
    let wrong = EncryptionKey::from_header_value("other-key").unwrap();
    assert_eq!(service.list("alice", &wrong).err(), Some(ConnectionError::InvalidKey));
    assert_eq!(service.update("alice", &key, created.id, 0, ConnectionPatch::default()).err(), Some(ConnectionError::Conflict { current_revision: 1 }));
    service.record_check("alice", &key, created.id, 1, "reachable".into(), Some("1.0".into())).unwrap();
    assert!(service.last_check("alice", &key, created.id).unwrap().is_some());
    let updated = service.update("alice", &key, created.id, 1, ConnectionPatch { password: Some("rotated".into()), ..Default::default() }).unwrap();
    assert_eq!(updated.revision, 2);
    assert!(service.last_check("alice", &key, created.id).unwrap().is_none());
    assert_eq!(service.update("alice", &key, created.id, 2, ConnectionPatch { password: Some(String::new()), ..Default::default() }).err(), Some(ConnectionError::InvalidInput));
    assert_eq!(service.delete("bob", &key, created.id, 2), Err(ConnectionError::NotFound));
}

#[test]
fn input_limits_and_per_user_capacity() {
    let (_tmp, _accounts, key, service) = setup();
    let mut invalid = input(); invalid.username = "bad:name".into();
    assert_eq!(service.create("alice", &key, invalid).err(), Some(ConnectionError::InvalidInput));
    let mut invalid = input(); invalid.password = "a".repeat(4097);
    assert_eq!(service.create("alice", &key, invalid).err(), Some(ConnectionError::InvalidInput));
    let mut invalid = input(); invalid.name = "x".repeat(129);
    assert_eq!(service.create("alice", &key, invalid).err(), Some(ConnectionError::InvalidInput));
    for _ in 0..16 { service.create("alice", &key, input()).unwrap(); }
    assert_eq!(service.create("alice", &key, input()).err(), Some(ConnectionError::LimitReached));
    assert!(service.create("bob", &key, input()).is_ok());
}

#[test]
fn ciphertext_swap_and_unsupported_schema_fail_closed() {
    let (tmp, accounts, key, service) = setup();
    let a = service.create("alice", &key, input()).unwrap();
    let b = service.create("alice", &key, input()).unwrap();
    drop(service);
    let db = Database::create(tmp.path().join("connections/redb")).unwrap();
    let records: TableDefinition<&[u8], &[u8]> = TableDefinition::new("connections");
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(records).unwrap();
        let first = table.get(a.id.as_bytes().as_slice()).unwrap().unwrap().value().to_vec();
        let second = table.get(b.id.as_bytes().as_slice()).unwrap().unwrap().value().to_vec();
        table.insert(a.id.as_bytes().as_slice(), second.as_slice()).unwrap();
        table.insert(b.id.as_bytes().as_slice(), first.as_slice()).unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    let reopened = ConnectionService::open(tmp.path(), accounts.clone()).unwrap();
    assert_eq!(reopened.list("alice", &key).err(), Some(ConnectionError::Corrupt));
    drop(reopened);
    let db = Database::create(tmp.path().join("connections/redb")).unwrap();
    let schema: TableDefinition<&str, u64> = TableDefinition::new("connection_schema");
    let tx = db.begin_write().unwrap();
    tx.open_table(schema).unwrap().insert("schema", 2).unwrap();
    tx.commit().unwrap();
    drop(db);
    assert!(matches!(ConnectionService::open(tmp.path(), accounts), Err(ConnectionError::UnsupportedSchema)));
}

#[test]
fn ciphertext_byte_flip_is_rejected_on_load() {
    let (tmp, accounts, key, service) = setup();
    let created = service.create("alice", &key, input()).unwrap();
    drop(service);

    let db = Database::create(tmp.path().join("connections/redb")).unwrap();
    let records: TableDefinition<&[u8], &[u8]> = TableDefinition::new("connections");
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(records).unwrap();
        let mut value = table.get(created.id.as_bytes().as_slice()).unwrap().unwrap().value().to_vec();
        let owner_len = u16::from_le_bytes([value[0], value[1]]) as usize;
        let ciphertext_start = 2 + owner_len + 8 + 12;
        value[ciphertext_start] ^= 1;
        table.insert(created.id.as_bytes().as_slice(), value.as_slice()).unwrap();
    }
    tx.commit().unwrap();
    drop(db);

    let reopened = ConnectionService::open(tmp.path(), accounts).unwrap();
    assert_eq!(reopened.credentials("alice", &key, created.id).err(), Some(ConnectionError::Corrupt));
    assert_eq!(reopened.list("alice", &key).err(), Some(ConnectionError::Corrupt));
}

#[test]
fn ciphertext_under_another_record_id_is_rejected() {
    let (tmp, accounts, key, service) = setup();
    let a = service.create("alice", &key, input()).unwrap();
    let b = service.create("alice", &key, input()).unwrap();
    drop(service);

    let db = Database::create(tmp.path().join("connections/redb")).unwrap();
    let records: TableDefinition<&[u8], &[u8]> = TableDefinition::new("connections");
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(records).unwrap();
        let a_value = table.get(a.id.as_bytes().as_slice()).unwrap().unwrap().value().to_vec();
        let mut b_value = table.get(b.id.as_bytes().as_slice()).unwrap().unwrap().value().to_vec();
        let a_blob_start = 2 + u16::from_le_bytes([a_value[0], a_value[1]]) as usize + 8;
        let b_blob_start = 2 + u16::from_le_bytes([b_value[0], b_value[1]]) as usize + 8;
        b_value.truncate(b_blob_start);
        b_value.extend_from_slice(&a_value[a_blob_start..]);
        table.insert(b.id.as_bytes().as_slice(), b_value.as_slice()).unwrap();
    }
    tx.commit().unwrap();
    drop(db);

    let reopened = ConnectionService::open(tmp.path(), accounts).unwrap();
    assert_eq!(reopened.credentials("alice", &key, a.id).unwrap().1.password, "secret-password");
    assert_eq!(reopened.credentials("alice", &key, b.id).err(), Some(ConnectionError::Corrupt));
}

#[test]
fn wrong_user_and_wrong_key_cannot_read_connection() {
    let (_tmp, _accounts, key, service) = setup();
    let created = service.create("alice", &key, input()).unwrap();
    let wrong_key = EncryptionKey::from_header_value("other-key").unwrap();

    assert!(service.list("bob", &key).unwrap().is_empty());
    assert_eq!(service.credentials("bob", &key, created.id).err(), Some(ConnectionError::NotFound));
    assert_eq!(service.credentials("alice", &wrong_key, created.id).err(), Some(ConnectionError::InvalidKey));
    assert_eq!(service.list("alice", &wrong_key).err(), Some(ConnectionError::InvalidKey));
}

#[test]
fn valid_key_can_read_connection_after_reopen() {
    let (tmp, accounts, key, service) = setup();
    let created = service.create("alice", &key, input()).unwrap();
    drop(service);

    let reopened = ConnectionService::open(tmp.path(), accounts).unwrap();
    assert!(reopened.list("alice", &key).unwrap() == vec![created.clone()]);
    let (revision, credentials) = reopened.credentials("alice", &key, created.id).unwrap();
    assert_eq!(revision, 1);
    assert_eq!(credentials.base_url, "https://example.test/opencode");
    assert_eq!(credentials.username, "opencode");
    assert_eq!(credentials.password, "secret-password");
}

#[test]
fn endpoint_password_and_label_do_not_appear_in_db_or_errors() {
    let (tmp, _accounts, key, service) = setup();
    let mut secret = input();
    secret.name = "private-label-unique-3948".into();
    secret.base_url = "https://private-url-unique-3948.test/agent".into();
    secret.password = "private-password-unique-3948".into();
    let created = service.create("alice", &key, secret).unwrap();
    let wrong_key = EncryptionKey::from_header_value("other-key").unwrap();
    let errors = [
        service.credentials("alice", &wrong_key, created.id).err().unwrap().to_string(),
        service.credentials("bob", &key, created.id).err().unwrap().to_string(),
        service.update("alice", &key, created.id, 0, ConnectionPatch::default()).err().unwrap().to_string(),
    ];
    drop(service);

    let bytes = std::fs::read(tmp.path().join("connections/redb")).unwrap();
    for marker in ["private-label-unique-3948", "private-url-unique-3948.test", "private-password-unique-3948"] {
        assert!(!bytes.windows(marker.len()).any(|window| window == marker.as_bytes()), "DB contains {marker}");
        for error in &errors {
            assert!(!error.contains(marker), "error contains {marker}: {error}");
        }
    }
}
