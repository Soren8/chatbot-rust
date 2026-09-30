//! Browser generation transport failures use the shared request adapters.
use std::path::Path;
use std::process::Command;

#[test]
fn web_generation_admission_has_no_legacy_transport() {
    let page = include_str!("../../static/chat.js");
    let session = include_str!("../../static/session-client.js");
    for retired in ["fetchWithGenerateRetry", "GenerateConnectionError", "fetch('/chat'", "fetch('/regenerate'", "fetch(\"/chat\"", "fetch(\"/regenerate\""] {
        assert!(!page.contains(retired), "page retains legacy transport: {retired}");
        assert!(!session.contains(retired), "session retains legacy transport: {retired}");
    }
    assert!(page.contains("activitySync.generationResponse(kind, init)"));
    let transport = include_str!("../../static/activity-sync.js");
    assert!(transport.contains("'X-Generation-Mode': 'durable'"));
}

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
