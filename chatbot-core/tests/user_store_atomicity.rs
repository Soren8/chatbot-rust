use std::{
    env,
    fs,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use chatbot_core::user_store::UserStore;
use serde_json::Value;

/// Guards HOST_DATA_DIR for the test and restores it afterwards.
struct EnvGuard {
    previous: Option<String>,
}

impl EnvGuard {
    fn set_temp(dir: &std::path::Path) -> Self {
        let previous = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", dir);
        Self { previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var("HOST_DATA_DIR", value),
            None => env::remove_var("HOST_DATA_DIR"),
        }
    }
}

/// Concurrent preference saves must never leave a torn users.json behind.
///
/// Every server handler constructs its own UserStore per request, so
/// overlapping POST /update_preferences calls save with no mutual
/// exclusion. Truncating the file in place (File::create + write) lets a
/// second writer (or a crash) land mid-save, producing the
/// `Json(Error("trailing characters", ...))` corruption seen in the field,
/// after which every tier/preference load and update fails.
#[test]
fn concurrent_saves_never_leave_torn_users_json() {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let _env = EnvGuard::set_temp(tmp.path());

    // A large payload widens the torn-write window on non-atomic saves.
    {
        let mut store = UserStore::new().expect("user store");
        for i in 0..200 {
            store
                .create_user(&format!("loaduser{i:04}"), "x")
                .expect("create user");
        }
    }

    let users_path = tmp.path().join("users.json");
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let mut writers = Vec::new();
    for _ in 0..8 {
        let stop = std::sync::Arc::clone(&stop);
        writers.push(std::thread::spawn(move || {
            // One UserStore per save, mirroring one-per-request handlers.
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let user = format!("loaduser{:04}", (n as usize) % 200);
                if let Ok(mut store) = UserStore::new() {
                    let _ = store.update_user_preferences(
                        &user,
                        Some(format!("set{n}")),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                }
                n += 1;
            }
        }));
    }

    // Every observed snapshot must be empty or valid JSON — never torn.
    let mut torn = 0u32;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(&users_path) {
            if contents.trim().is_empty() {
                continue;
            }
            if serde_json::from_str::<Value>(&contents).is_err() {
                torn += 1;
                if torn <= 3 {
                    let tail_start = contents.len().saturating_sub(120);
                    eprintln!(
                        "torn snapshot ({} bytes) tail: {:?}",
                        contents.len(),
                        &contents[tail_start..]
                    );
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for writer in writers {
        writer.join().expect("writer thread");
    }

    assert_eq!(
        torn, 0,
        "concurrent saves left {torn} torn users.json snapshots; saves must be atomic"
    );

    let final_contents = fs::read_to_string(&users_path).expect("users.json readable");
    serde_json::from_str::<Value>(&final_contents).expect("final users.json must parse");

    let leftovers: Vec<_> = fs::read_dir(tmp.path())
        .expect("read data dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(
        leftovers.is_empty(),
        "save temp files left behind: {leftovers:?}"
    );
}
