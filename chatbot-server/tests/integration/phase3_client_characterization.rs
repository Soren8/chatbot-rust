use std::path::Path;
use std::process::Command;

#[test]
fn login_notice_and_tts_retry_characterization() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/phase3_client_characterization.js"))
        .arg(root.join("static/login.js"))
        .arg(root.join("static/tts-playback.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS login notice / desktop retry behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
