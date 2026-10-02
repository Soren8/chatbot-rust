//! Given browser glue scripts and their Node vm fixture,
//! When the characterization runner executes,
//! Then each browser script's isolated behavior is asserted.

use std::path::Path;
use std::process::Command;

#[test]
fn browser_glue_behavior() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/browser_glue_test.js"))
        .arg(root.join("static/tt.js"))
        .arg(root.join("static/native-bridge.js"))
        .arg(root.join("static/agent-connections.js"))
        .output()
        .expect("test image must provide Node");
    assert!(
        run.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
