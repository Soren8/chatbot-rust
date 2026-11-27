//! User-store concurrent read-modify-write behavior.
//!
//! Given independently opened stores sharing one users file, when concurrent
//! account and preference updates run, then every unrelated change survives.

use std::sync::{Arc, Barrier};

use chatbot_core::user_store::{CreateOutcome, UserStore};

const THREADS: usize = 8;
const ROUNDS: usize = 10;

#[test]
fn concurrent_signups_and_preference_updates_do_not_lose_records() {
    let root = tempfile::tempdir().expect("tempdir");
    let password_hash = bcrypt::hash("concurrency-password", 4).expect("hash password");

    for round in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut workers = Vec::with_capacity(THREADS);
        for worker in 0..THREADS {
            let root = root.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            let password_hash = password_hash.clone();
            let username = format!("race_{round}_{worker}");
            workers.push(std::thread::spawn(move || {
                let mut store = UserStore::open(&root).expect("open user store");
                barrier.wait();
                assert!(matches!(
                    store.create_user(&username, &password_hash).expect("create user"),
                    CreateOutcome::Created
                ));
                username
            }));
        }
        let usernames: Vec<String> = workers
            .into_iter()
            .map(|worker| worker.join().expect("signup thread"))
            .collect();

        for username in usernames {
            assert!(
                UserStore::open(root.path())
                    .expect("reopen user store")
                    .validate_user(&username, "concurrency-password")
                    .expect("validate user"),
                "account {username} was lost in round {round}"
            );
        }
    }

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::with_capacity(THREADS);
    for worker in 0..THREADS {
        let root = root.path().to_path_buf();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let username = format!("race_0_{worker}");
            let mut store = UserStore::open(&root).expect("open user store");
            barrier.wait();
            store
                .update_user_preferences(
                    &username,
                    Some(format!("set-{worker}")),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("update preferences");
            username
        }));
    }
    for worker in workers {
        let username = worker.join().expect("preference thread");
        let store = UserStore::open(root.path()).expect("reopen user store");
        let (last_set, ..) = store.user_preferences(&username).expect("read preferences");
        let expected = format!("set-{}", username.rsplit('_').next().unwrap());
        assert_eq!(last_set.as_deref(), Some(expected.as_str()), "preferences lost for {username}");
    }
}
