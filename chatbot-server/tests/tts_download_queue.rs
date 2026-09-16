use std::path::Path;
use std::process::Command;

#[test]
fn native_js_lookahead_orders_refills_retries_and_cancels() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/native_tts_queue_test.js"))
        .arg(root.join("static/chat.js"))
        .output().expect("test image must provide the JS behavior-test runtime");
    assert!(run.status.success(), "JS queue behavior: {}", String::from_utf8_lossy(&run.stderr));
}

#[test]
fn native_download_queue_overlaps_bounds_orders_and_cancels_real_tasks() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .arg("-d").arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/audio/TtsDownloadQueue.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/audio/TtsBodyInputStream.java"))
        .arg(root.join("chatbot-server/tests/fixtures/TtsDownloadQueueTest.java"))
        .output().expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java")
        .arg("-cp").arg(output_dir.path()).arg("TtsDownloadQueueTest")
        .output().expect("run native download queue behavior tests");
    assert!(run.status.success(), "native queue behavior: {}", String::from_utf8_lossy(&run.stderr));
}
