use std::sync::{Arc, Barrier};

use chatbot_core::user_store::UserStore;

#[test]
fn simultaneous_first_enrollment_cannot_replace_an_accepted_key() {
    const SECRET: &[u8] = b"first-enrollment-secret";
    for _ in 0..32 {
        let root = tempfile::tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let outcomes = std::thread::scope(|scope| {
            let workers: Vec<_> = [b"first-key".as_slice(), b"second-key".as_slice()]
                .into_iter()
                .map(|key| {
                    let barrier = barrier.clone();
                    let path = root.path();
                    scope.spawn(move || {
                        let store = UserStore::open(path).unwrap();
                        barrier.wait();
                        let accepted = store
                            .ensure_key_verifier_with_secret("alice", key, SECRET)
                            .is_ok();
                        (key, accepted)
                    })
                })
                .collect();
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        let store = UserStore::open(root.path()).unwrap();
        let accepted: Vec<_> = outcomes.iter().filter(|(_, accepted)| *accepted).collect();
        assert!(!accepted.is_empty(), "one enrollment must succeed");
        for (key, _) in accepted {
            assert!(
                store
                    .verify_encryption_key_with_secret("alice", key, SECRET)
                    .unwrap(),
                "successful enrollment must remain valid"
            );
        }
    }
}

#[test]
fn simultaneous_salt_creation_returns_the_persisted_salt_to_every_caller() {
    for _ in 0..64 {
        let root = tempfile::tempdir().unwrap();
        let mut store = UserStore::open(root.path()).unwrap();
        store.create_user("alice", "unused-password-hash").unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let salts = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let barrier = barrier.clone();
                    let path = root.path();
                    scope.spawn(move || {
                        let store = UserStore::open(path).unwrap();
                        barrier.wait();
                        store.get_client_salt("alice").unwrap()
                    })
                })
                .collect();
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            salts[0], salts[1],
            "first login must derive against a single durable salt"
        );
        assert_eq!(salts[0], store.get_client_salt("alice").unwrap());
    }
}
