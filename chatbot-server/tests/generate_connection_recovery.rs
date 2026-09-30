//! Browser generation transport failures use the shared request adapters.
use std::path::Path;
use std::process::Command;

#[test]
fn generate_connection_recovery() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/generate_connection_recovery_test.js"))
        .arg(root.join("static/chat.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/session-client.js"))
        .arg(root.join("static/stream-decoder.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(run.status.success(), "JS generation recovery: {}", String::from_utf8_lossy(&run.stderr));
}
