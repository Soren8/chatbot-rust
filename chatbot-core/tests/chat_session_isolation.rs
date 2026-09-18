//! MOD003: owned chat session state isolation.
//!
//! Two `ChatSessionStore` instances share nothing: guest history, memory,
//! system prompt and the generation lock are all scoped to the owning store,
//! even for the same session ID. The timeout is raw seconds (zero allowed, no
//! 60s HTTP floor) and each store seeds new sessions with its own default
//! prompt. These tests never touch the process-global store or config.

use chatbot_core::session::ChatSessionStore;

#[test]
fn two_stores_isolate_history_memory_and_prompt_for_same_session_id() {
    let store_a = ChatSessionStore::new(3600, "prompt-A".to_string());
    let store_b = ChatSessionStore::new(3600, "prompt-B".to_string());
    let session_id = "guest_mod003_shared_state";

    store_a.update_history(session_id, &[("u-a".to_string(), "a-a".to_string())]);
    store_b.update_history(session_id, &[("u-b".to_string(), "a-b".to_string())]);

    assert_eq!(
        store_a.history(session_id),
        vec![("u-a".to_string(), "a-a".to_string())]
    );
    assert_eq!(
        store_b.history(session_id),
        vec![("u-b".to_string(), "a-b".to_string())]
    );

    // New sessions start at their owning store's default prompt.
    assert_eq!(store_a.system_prompt(session_id), "prompt-A");
    assert_eq!(store_b.system_prompt(session_id), "prompt-B");

    store_a.update_memory(session_id, "memory-A");
    store_b.update_memory(session_id, "memory-B");
    assert_eq!(store_a.memory(session_id), "memory-A");
    assert_eq!(store_b.memory(session_id), "memory-B");

    store_a.update_system_prompt(session_id, "prompt-A2");
    assert_eq!(store_a.system_prompt(session_id), "prompt-A2");
    assert_eq!(
        store_b.system_prompt(session_id),
        "prompt-B",
        "peer store keeps its own prompt"
    );

    // Prompt/memory writes leave the owning history alone.
    assert_eq!(
        store_a.history(session_id),
        vec![("u-a".to_string(), "a-a".to_string())]
    );
    assert_eq!(
        store_b.history(session_id),
        vec![("u-b".to_string(), "a-b".to_string())]
    );
}

#[test]
fn generation_lock_is_store_scoped_for_same_session_id() {
    let store_a = ChatSessionStore::new(3600, "prompt-A".to_string());
    let store_b = ChatSessionStore::new(3600, "prompt-B".to_string());
    let session_id = "guest_mod003_shared_lock";

    assert!(store_a.try_acquire_generation(session_id));
    assert!(
        !store_a.try_acquire_generation(session_id),
        "same store must report busy while held"
    );
    assert!(
        store_b.try_acquire_generation(session_id),
        "peer store has an independent lock"
    );
    assert!(!store_b.try_acquire_generation(session_id));

    store_a.release_generation(session_id);
    assert!(
        store_a.try_acquire_generation(session_id),
        "release frees the owning store only"
    );
    assert!(
        !store_b.try_acquire_generation(session_id),
        "peer still holds its lock"
    );

    store_a.release_generation(session_id);
    store_b.release_generation(session_id);
    assert!(store_a.try_acquire_generation(session_id));
    assert!(store_b.try_acquire_generation(session_id));
    store_a.release_generation(session_id);
    store_b.release_generation(session_id);

    // Releasing an unknown session is a no-op, mirroring the global delegate.
    store_a.release_generation("guest_mod003_never_created");
}

#[test]
fn new_session_initialises_prompt_default_with_empty_memory_and_history() {
    let store = ChatSessionStore::new(3600, "mod003-default".to_string());
    let session_id = "guest_mod003_defaults";

    assert!(store.history(session_id).is_empty());
    assert_eq!(store.memory(session_id), "");
    assert_eq!(
        store.system_prompt(session_id),
        "",
        "unknown sessions report empty, not the default"
    );

    // Memory/prompt setters do not create sessions on their own.
    store.update_memory(session_id, "memory-no-create");
    store.update_system_prompt(session_id, "prompt-no-create");
    assert!(store.history(session_id).is_empty());
    assert_eq!(store.memory(session_id), "");
    assert_eq!(store.system_prompt(session_id), "");

    store.update_history(session_id, &[]);
    assert_eq!(store.system_prompt(session_id), "mod003-default");
    assert_eq!(store.memory(session_id), "");
    assert!(store.history(session_id).is_empty());
}

#[test]
fn raw_zero_timeout_expires_while_peer_retains() {
    let zero = ChatSessionStore::new(0, "z".to_string());
    let long = ChatSessionStore::new(3600, "l".to_string());
    let session_id = "guest_mod003_shared_timeout";

    zero.update_history(session_id, &[("u".to_string(), "a".to_string())]);
    long.update_history(session_id, &[("u".to_string(), "a".to_string())]);

    std::thread::sleep(std::time::Duration::from_millis(5));

    assert_eq!(
        zero.purge_expired(),
        1,
        "raw zero timeout must expire without the 60s HTTP floor"
    );
    assert!(zero.history(session_id).is_empty());
    assert_eq!(long.purge_expired(), 0);
    assert_eq!(
        long.history(session_id),
        vec![("u".to_string(), "a".to_string())]
    );
}
