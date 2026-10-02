//! Given real Android utility/session Java sources and a minimal JUnit 4 shim,
//! When compiled with javac and invoked through the shim runner,
//! Then every annotated test method executes in the Rust test suite.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run_junit_class(class_name: &str, source_path: &Path, expected_methods: usize, extra_sources: &[PathBuf]) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let fixtures = root.join("chatbot-server/tests/fixtures");
    let shim = fixtures.join("junit_shim");
    let output_dir = tempfile::tempdir().unwrap();
    let mut sources = vec![
        shim.join("org/junit/Test.java"),
        shim.join("org/junit/Before.java"),
        shim.join("org/junit/Assert.java"),
        shim.join("JUnitShimRunner.java"),
        source_path.to_path_buf(),
    ];
    sources.extend_from_slice(extra_sources);

    let compile = Command::new("javac")
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(output_dir.path())
        .args(&sources)
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation for {class_name}: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("JUnitShimRunner")
        .arg(class_name)
        .output()
        .expect("run JUnit shim runner");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "JUnit run for {class_name} failed:\n{stdout}{stderr}");
    let pass_count = stdout.lines().filter(|line| line.starts_with("PASS ")).count();
    assert_eq!(
        pass_count, expected_methods,
        "JUnit runner executed {pass_count} methods for {class_name}, expected {expected_methods}:\n{stdout}{stderr}"
    );
}

fn count_test_methods(source: &Path) -> usize {
    let contents = fs::read_to_string(source).unwrap();
    contents.matches("@Test").count()
}

#[test]
fn voice_audio_route_junit_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = root.join("android/app/src/test/java/com/chatbot/app/audio/VoiceAudioRouteTest.java");
    let methods = count_test_methods(&source);
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let fixtures = root.join("chatbot-server/tests/fixtures");
    run_junit_class(
        "com.chatbot.app.audio.VoiceAudioRouteTest",
        &source,
        methods,
        &[
            audio.join("VoiceAudioRoute.java"),
            fixtures.join("android/media/AudioManager.java"),
            fixtures.join("android/media/AudioDeviceInfo.java"),
        ],
    );
}

#[test]
fn voice_session_keep_awake_junit_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = root.join("android/app/src/test/java/com/chatbot/app/audio/VoiceSessionKeepAwakeTest.java");
    let methods = count_test_methods(&source);
    run_junit_class(
        "com.chatbot.app.audio.VoiceSessionKeepAwakeTest",
        &source,
        methods,
        &[root.join("android/app/src/main/java/com/chatbot/app/audio/VoiceSessionKeepAwake.java")],
    );
}

#[test]
fn voice_mode_foreground_session_junit_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = root.join("android/app/src/test/java/com/chatbot/app/audio/VoiceModeForegroundSessionTest.java");
    let methods = count_test_methods(&source);
    run_junit_class(
        "com.chatbot.app.audio.VoiceModeForegroundSessionTest",
        &source,
        methods,
        &[root.join("android/app/src/main/java/com/chatbot/app/audio/VoiceModeForegroundSession.java")],
    );
}

#[test]
fn server_url_resolver_junit_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = root.join("android/app/src/test/java/com/chatbot/app/util/ServerUrlResolverTest.java");
    let methods = count_test_methods(&source);
    run_junit_class(
        "com.chatbot.app.util.ServerUrlResolverTest",
        &source,
        methods,
        &[root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java")],
    );
}

#[test]
fn file_logger_junit_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = root.join("android/app/src/test/java/com/chatbot/app/util/FileLoggerTest.java");
    let methods = count_test_methods(&source);
    let fixtures = root.join("chatbot-server/tests/fixtures/file_logger");
    run_junit_class(
        "com.chatbot.app.util.FileLoggerTest",
        &source,
        methods,
        &[
            root.join("android/app/src/main/java/com/chatbot/app/util/FileLogger.java"),
            fixtures.join("android/content/Context.java"),
            fixtures.join("android/util/Log.java"),
        ],
    );
}
