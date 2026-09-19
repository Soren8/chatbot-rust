//! MOD-009-A regression: conversation-bound requests.
//!
//! Behavioral coverage through the REAL owned state
//! (`static/conversation-state.js`) composed as production request adapters
//! use it: initiating set identity plus history-window generation fence every
//! response application. Delayed chat headers/chunks/completion after A->B,
//! replacement-regenerate stale callbacks, memory/system-prompt retry target
//! retention across a switch, valid same-set completion/retry (logged-in and
//! guest), and generation-fenced pagination settlement run in Node against the
//! actual unit — no algorithm copies, no source-spelling pins.

use std::path::Path;
use std::process::Command;

#[test]
fn conversation_requests_bind_initiating_identity_and_generation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/conversation_request_binding_test.js"))
        .arg(root.join("static/conversation-state.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS conversation-request binding: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
