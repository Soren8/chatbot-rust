use std::path::Path;
use std::process::Command;

/// Voice-mode session composition (phone pause/resume, route + keep-awake +
/// foreground, notification stop) is owned by VoiceModeSessionCoordinator.
/// This harness compiles the real coordinator and resource classes with
/// minimal android.media stubs and runs the pure-Java behavior fixture.
#[test]
fn voice_mode_session_coordinator_orders_phone_and_session_teardown() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(audio.join("VoiceAudioRoute.java"))
        .arg(audio.join("VoiceSessionKeepAwake.java"))
        .arg(audio.join("VoiceModeForegroundSession.java"))
        .arg(audio.join("VoiceModeSessionCoordinator.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioManager.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioDeviceInfo.java"))
        .arg(root.join("chatbot-server/tests/fixtures/VoiceModeSessionCoordinatorTest.java"))
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
        .arg("VoiceModeSessionCoordinatorTest")
        .output()
        .expect("run coordinator behavior tests");
    assert!(
        run.status.success(),
        "coordinator behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
