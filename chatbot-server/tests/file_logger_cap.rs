use std::path::Path;
use std::process::Command;

/// The real FileLogger with stub Context/Log: logging far past the size cap
/// keeps the on-disk log bounded, the newest line stays in the active file,
/// and concurrent lines keep well-formed timestamps.
#[test]
fn file_logger_rolls_at_cap_and_keeps_timestamps() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let fixtures = root.join("chatbot-server/tests/fixtures/file_logger");
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/FileLogger.java"))
        .arg(fixtures.join("android/content/Context.java"))
        .arg(fixtures.join("android/util/Log.java"))
        .arg(fixtures.join("FileLoggerCapTest.java"))
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("FileLoggerCapTest")
        .output()
        .expect("run FileLogger cap fixture");
    assert!(
        run.status.success(),
        "FileLogger cap: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
