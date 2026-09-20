use std::path::Path;
use std::process::Command;

/// Foreground stop honesty through the REAL production adapter.
///
/// Compiles the real foreground session, service, coordinator and route
/// units with minimal fake platform stubs plus the real behavior fixture.
/// The fixture drives platform throw/fail/already-stopped/success, destroy
/// and stale-stop-vs-newer through the actual service stop path; a pure
/// boolean fake backend would hide the fabricated success.
#[test]
fn foreground_stop_reports_honest_outcome_with_generation_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let fixtures = root.join("chatbot-server/tests/fixtures");
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(audio.join("VoiceModeForegroundSession.java"))
        .arg(audio.join("VoiceModeForegroundService.java"))
        .arg(audio.join("VoiceModeNativeHooks.java"))
        .arg(audio.join("VoiceModeSessionCoordinator.java"))
        .arg(audio.join("VoiceAudioRoute.java"))
        .arg(audio.join("VoiceSessionKeepAwake.java"))
        .arg(fixtures.join("android/content/Context.java"))
        .arg(fixtures.join("android/content/Intent.java"))
        .arg(fixtures.join("android/content/pm/ServiceInfo.java"))
        .arg(fixtures.join("android/app/Service.java"))
        .arg(fixtures.join("android/os/Build.java"))
        .arg(fixtures.join("android/os/Handler.java"))
        .arg(fixtures.join("android/os/Looper.java"))
        .arg(fixtures.join("android/os/IBinder.java"))
        .arg(fixtures.join("android/os/PowerManager.java"))
        .arg(fixtures.join("android/net/ConnectivityManager.java"))
        .arg(fixtures.join("android/net/NetworkRequest.java"))
        .arg(fixtures.join("android/net/NetworkCapabilities.java"))
        .arg(fixtures.join("android/media/AudioManager.java"))
        .arg(fixtures.join("android/media/AudioDeviceInfo.java"))
        .arg(fixtures.join("foreground_stop/FileLogger.java"))
        .arg(fixtures.join("foreground_stop/VoiceModeNotification.java"))
        .arg(fixtures.join("VoiceModeForegroundStopTest.java"))
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
        .arg("VoiceModeForegroundStopTest")
        .output()
        .expect("run foreground stop behavior tests");
    assert!(
        run.status.success(),
        "foreground stop behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
