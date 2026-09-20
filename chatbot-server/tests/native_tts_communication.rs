use std::path::Path;
use std::process::Command;

/// Handheld voice-mode TTS must play through the communication path it
/// captures on (MODE_IN_COMMUNICATION / VOICE_COMMUNICATION), while
/// standalone TTS keeps the media path.
///
/// Adapted from the retired remote-volume harness: the executable
/// owner/policy composition, generation/stale, ordering and no-volume-write
/// regression patterns are preserved against the locally meaningful
/// communication/media policy. Compiles the real
/// route/keep-awake/foreground/coordinator/policy units with minimal
/// android.media stubs and runs the pure-Java behavior fixture. String
/// checks alone cannot prove the playback choice: the fixture drives the
/// production composition (route ownership, voice vs standalone selection,
/// track/focus recreation, pause/exit/stop/destroy) against fake backends
/// and asserts no backend ever writes a stream volume.
#[test]
fn voice_tts_uses_communication_in_voice_mode_and_media_standalone() {
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
        .arg(audio.join("TtsAudioPolicy.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioManager.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioDeviceInfo.java"))
        .arg(root.join("chatbot-server/tests/fixtures/android/media/AudioAttributes.java"))
        .arg(root.join("chatbot-server/tests/fixtures/VoiceTtsCommunicationPolicyTest.java"))
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
        .arg("VoiceTtsCommunicationPolicyTest")
        .output()
        .expect("run TTS communication behavior tests");
    assert!(
        run.status.success(),
        "TTS communication behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The native TTS playback adapter must build matching attributes from
/// actual route ownership: communication without a legacy override in voice
/// mode, media with the music mapping standalone, with track recreation on
/// usage change and no stream writes.
///
/// Exercises the REAL production adapter: `requestAudioFocus` and
/// `ensureTrackPlaying` are extracted verbatim from NativeVoiceTtsPlugin
/// (never reimplemented) and compiled with fake platform leaves plus the
/// real policy. Only the environment queries (route/headset/speaker/context)
/// are injected flags; the attribute/focus/track decisions stay verbatim.
#[test]
fn voice_tts_platform_adapter_builds_matching_attributes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let plugin = std::fs::read_to_string(
        root.join("android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"),
    )
    .unwrap();
    let focus_body = extract_java_method(&plugin, "private void requestAudioFocus(boolean inCommunication)")
        .expect("real requestAudioFocus(boolean) must be present");
    let track_body = extract_java_method(&plugin, "private AudioTrack ensureTrackPlaying(int sampleRate, long generation)")
        .expect("real ensureTrackPlaying must be present");
    assert!(
        focus_body.contains("TtsAudioPolicy.playbackUsage")
            && focus_body.contains("TtsAudioPolicy.shouldRefreshFocus"),
        "extracted focus adapter must select matching usage via the owned policy"
    );
    assert!(
        track_body.contains("TtsAudioPolicy.playbackUsage")
            && track_body.contains("TtsAudioPolicy.shouldRecreateTrack")
            && track_body.contains("TtsAudioPolicy.useLegacyMusicStream")
            && track_body.contains("TtsAudioPolicy.preferBuiltInSpeaker"),
        "extracted track adapter must delegate usage/recreate/legacy/device to the owned policy"
    );
    let focus_decl = focus_body
        .find('{')
        .expect("focus body must open a block");
    let track_decl = track_body
        .find('{')
        .expect("track body must open a block");
    let adapter = String::from(
        "import android.content.Context;\nimport android.media.AudioAttributes;\nimport android.media.AudioDeviceInfo;\nimport android.media.AudioFocusRequest;\nimport android.media.AudioFormat;\nimport android.media.AudioManager;\nimport android.media.AudioTrack;\nimport android.os.Build;\nimport android.util.Log;\nimport com.chatbot.app.audio.TtsAudioPolicy;\nimport java.util.concurrent.atomic.AtomicBoolean;\nimport java.util.concurrent.atomic.AtomicLong;\n\nfinal class TtsAdapterUnderTest {\n    private static final String TAG = \"TtsAdapterTest\";\n    android.content.Context testContext;\n    boolean routeActiveFlag;\n    boolean headsetFlag;\n    boolean speakerPresentFlag = true;\n    boolean notifiedStarted;\n    private volatile AudioTrack audioTrack;\n    private volatile int trackSampleRate = 24000;\n    private volatile int trackUsage = AudioAttributes.USAGE_MEDIA;\n    private volatile int focusUsage = -1;\n    private AudioFocusRequest currentFocusRequest;\n    private final AtomicLong bytesWritten = new AtomicLong(0);\n    private final AtomicBoolean playbackStartedNotified = new AtomicBoolean(false);\n    private android.content.Context getContext() { return testContext; }\n    private boolean isVoiceRouteActive() { return routeActiveFlag; }\n    private boolean hasHeadsetOrBluetoothConnected(AudioManager am) { return headsetFlag; }\n    private AudioDeviceInfo findBuiltInSpeaker() { return speakerPresentFlag ? new AudioDeviceInfo() : null; }\n    private void notifyStarted(long generation) { notifiedStarted = true; }\n    ",
    ) + "void requestAudioFocus(boolean inCommunication) " + &focus_body[focus_decl..]
        + "\n    public AudioTrack ensureTrackPlayingPublic(int sampleRate, long generation) "
        + &track_body[track_decl..]
        + "\n}\n";
    let output_dir = tempfile::tempdir().unwrap();
    let gen_dir = output_dir.path().join("gen");
    std::fs::create_dir(&gen_dir).unwrap();
    std::fs::write(gen_dir.join("TtsAdapterUnderTest.java"), adapter).unwrap();
    let leaves = root.join("chatbot-server/tests/fixtures/android_volume_adapter");
    let fixtures = root.join("chatbot-server/tests/fixtures");
    let audio = root.join("android/app/src/main/java/com/chatbot/app/audio");
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(audio.join("TtsAudioPolicy.java"))
        .arg(gen_dir.join("TtsAdapterUnderTest.java"))
        .arg(leaves.join("android/media/AudioManager.java"))
        .arg(leaves.join("android/media/AudioAttributes.java"))
        .arg(leaves.join("android/media/AudioFocusRequest.java"))
        .arg(leaves.join("android/media/AudioFormat.java"))
        .arg(leaves.join("android/media/AudioTrack.java"))
        .arg(leaves.join("android/media/VolumeProvider.java"))
        .arg(leaves.join("android/media/session/MediaSession.java"))
        .arg(leaves.join("android/media/session/PlaybackState.java"))
        .arg(leaves.join("android/content/Context.java"))
        .arg(leaves.join("android/os/Build.java"))
        .arg(leaves.join("android/util/Log.java"))
        .arg(leaves.join("com/chatbot/app/util/FileLogger.java"))
        .arg(fixtures.join("android/media/AudioDeviceInfo.java"))
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
        .expect("run playback adapter regressions");
    assert!(
        run.status.success(),
        "playback adapter: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

fn extract_java_method<'a>(src: &'a str, marker: &str) -> Option<&'a str> {
    let start = src.find(marker)?;
    let body = &src[start..];
    let open = body.find('{')?;
    let mut depth = 0i32;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[..open + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}
