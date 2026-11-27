//! Server rendering of typed finalize outcomes (MOD-006).
//!
//! Given a typed persistence outcome, when the shared stream renderer runs,
//! then success and no-op outcomes yield no chunks while failures yield the
//! exact historical stream-error strings. Both `/chat` and `/regenerate`
//! persist paths use this single renderer.

use chatbot_core::session::FinalizeOutcome;
use chatbot_server::chat_utils::render_finalize_outcome;

#[test]
fn success_and_noop_outcomes_render_no_chunks() {
    assert!(render_finalize_outcome(&FinalizeOutcome::GuestUpdated).is_empty());
    assert!(render_finalize_outcome(&FinalizeOutcome::DurableCommitted).is_empty());
    assert!(render_finalize_outcome(&FinalizeOutcome::NoSession).is_empty());
}

#[test]
fn key_validation_failed_renders_shared_string() {
    assert_eq!(
        render_finalize_outcome(&FinalizeOutcome::KeyValidationFailed),
        vec!["\n[Error] Failed to save chat history: missing encryption key".to_string()]
    );
}

#[test]
fn conflict_renders_reload_string() {
    assert_eq!(
        render_finalize_outcome(&FinalizeOutcome::Conflict),
        vec!["\n[Error] Chat history conflict — reload the set and retry.".to_string()]
    );
}

#[test]
fn invalid_input_renders_detail() {
    assert_eq!(
        render_finalize_outcome(&FinalizeOutcome::InvalidInput(
            "empty user message".to_string()
        )),
        vec!["\n[Error] Failed to save chat history: empty user message".to_string()]
    );
}

#[test]
fn store_failure_renders_generic_string() {
    assert_eq!(
        render_finalize_outcome(&FinalizeOutcome::StoreFailure),
        vec!["\n[Error] Failed to save chat history".to_string()]
    );
}
