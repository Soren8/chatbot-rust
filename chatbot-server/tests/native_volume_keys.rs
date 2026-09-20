use std::path::Path;
use std::process::Command;

/// Hardware volume keys must drive the music stream TTS plays on, foreground
/// and background/locked, through the owned voice-mode session.
///
/// Compiles the real route/keep-awake/foreground/volume/coordinator units
/// with minimal android.media stubs and runs the pure-Java behavior fixture.
/// String checks alone cannot prove the keys reach music: the fixture drives
/// the production owner/adapter composition (enter, keys, slider, stale
/// generations, pause/exit/stop/destroy) against fake platform backends.
#[test]
fn voice_volume_keys_drive_music_through_owned_session() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(audio.join("VoiceAudioRoute.java"))
        .arg(audio.join("VoiceSessionKeepAwake.java"))
        .arg(audio.join("VoiceModeForegroundSession.java"))
        .arg(audio.join("VoiceModeVolumeSession.java"))
        .arg(audio.join("VoiceModeSessionCoordinator.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioManager.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioDeviceInfo.java"))
        .arg(root.join("chatbot-server/tests/fixtures/VoiceModeVolumeSessionTest.java"))
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
        .arg("VoiceModeVolumeSessionTest")
        .output()
        .expect("run volume behavior tests");
    assert!(
        run.status.success(),
        "volume behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Exercises the REAL platform adapter: MediaVolumeBackend is extracted
/// verbatim from NativeMicPlugin (never reimplemented) and compiled with fake
/// platform leaves plus the real volume owner. A stale provider object after
/// replacement must not forward, and a setup failure must not leak the
/// constructed session. The owner-level fixture cannot see these adapter
/// defects: the mutable backend rebound the generation per invocation, and a
/// half-constructed session escaped cleanup.
#[test]
fn voice_volume_platform_adapter_isolates_stale_providers_and_cleans_up() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let plugin = std::fs::read_to_string(
        root.join("android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"),
    )
    .unwrap();
    let marker = "private final class MediaVolumeBackend implements VoiceModeVolumeSession.Backend {";
    let start = plugin
        .find(marker)
        .expect("real platform adapter must be present");
    let body = &plugin[start..];
    let mut depth = 0i32;
    let mut end = None;
    for (i, ch) in body.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.expect("balanced adapter class braces");
    let adapter = String::from(
        "import android.content.Context;\nimport android.media.AudioManager;\nimport android.media.VolumeProvider;\nimport android.media.session.MediaSession;\nimport android.media.session.PlaybackState;\nimport com.chatbot.app.audio.VoiceModeVolumeSession;\nimport com.chatbot.app.util.FileLogger;\n\n",
    ) + &body[..end]
        .replacen(
            "private final class MediaVolumeBackend",
            "final class MediaVolumeBackend",
            1,
        )
        .replacen(
            "{",
            "{\n    android.media.AudioManager audioManager;\n    android.content.Context testContext;\n    private static final String TAG = \"VolumeAdapterTest\";\n    android.content.Context getContext() { return testContext; }\n",
            1,
        );
    let output_dir = tempfile::tempdir().unwrap();
    let gen_dir = output_dir.path().join("gen");
    std::fs::create_dir(&gen_dir).unwrap();
    std::fs::write(gen_dir.join("MediaVolumeBackend.java"), adapter).unwrap();
    let leaves = root.join("chatbot-server/tests/fixtures/android_volume_adapter");
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(audio.join("VoiceModeVolumeSession.java"))
        .arg(gen_dir.join("MediaVolumeBackend.java"))
        .arg(leaves.join("android/media/AudioManager.java"))
        .arg(leaves.join("android/media/VolumeProvider.java"))
        .arg(leaves.join("android/media/session/MediaSession.java"))
        .arg(leaves.join("android/media/session/PlaybackState.java"))
        .arg(leaves.join("android/content/Context.java"))
        .arg(leaves.join("com/chatbot/app/util/FileLogger.java"))
        .arg(leaves.join("VolumeAdapterDriver.java"))
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "adapter compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("VolumeAdapterDriver")
        .output()
        .expect("run platform adapter regressions");
    assert!(
        run.status.success(),
        "platform adapter: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
