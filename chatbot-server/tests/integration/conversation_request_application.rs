//! MOD-009-A application regression: the actual `static/chat.js` request
//! adapters evaluated in a vm sandbox with the real owners.
//!
//! Each scenario runs the real extracted adapters (chat/regenerate sends,
//! memory saves, pair pre-reads, older-page loads) against deferred
//! fetch/readers with the real tracker, history window, stream decoder and
//! session client; only leaf DOM/render/playback sinks are stubbed. A set
//! switch mid-flight must settle the old ownership without touching the new
//! selection, and a replacement request must stay usable.

use std::path::Path;
use std::process::Command;

#[test]
fn conversation_request_application_fences_stale_responses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/conversation_request_application_test.js"))
        .arg(root.join("static/chat.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/session-client.js"))
        .arg(root.join("static/stream-decoder.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS conversation-request application: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
