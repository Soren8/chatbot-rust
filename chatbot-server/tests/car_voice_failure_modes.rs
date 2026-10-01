//! Android Auto voice failure modes: the pure capture/turn/drain decisions in
//! `CarVoicePolicy.java` run under `javac`; `VoiceScreen.java` wiring is pinned
//! by source because the car library has no test stubs.

use std::path::Path;
use std::process::Command;

const VOICE_SCREEN: &str =
    include_str!("../../android/app/src/main/java/com/chatbot/app/car/VoiceScreen.java");

#[test]
fn car_voice_policy_bounds_capture_turns_and_drain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac").arg("-d").arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/car/CarVoicePolicy.java"))
        .arg(root.join("chatbot-server/tests/fixtures/car_voice/CarVoicePolicyTest.java"))
        .output().expect("test image must provide javac");
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java").arg("-cp").arg(output_dir.path()).arg("CarVoicePolicyTest")
        .output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
}

#[test]
fn car_voice_screen_wires_policy_and_releases_threads() {
    assert!(
        VOICE_SCREEN.contains("AudioRecord record = audioRecord;")
            && !VOICE_SCREEN.contains("audioRecord.read("),
        "capture loop must read a local recorder reference, not the field main nulls"
    );
    assert!(
        VOICE_SCREEN.contains("CarVoicePolicy.CaptureReads.STOP")
            && VOICE_SCREEN.contains("CarVoicePolicy.CaptureReads.BACK_OFF")
            && VOICE_SCREEN.contains("logIdle()"),
        "capture loop must stop on read errors and back off with bounded logging"
    );
    assert!(
        VOICE_SCREEN.contains("turns.offer(pcm)") && VOICE_SCREEN.contains("turns.finish()"),
        "utterances during an in-flight turn must go through the single-pending slot"
    );
    assert!(
        VOICE_SCREEN.contains("CarVoicePolicy.drainMs(") && !VOICE_SCREEN.contains("Math.min(durationMs, 30000)"),
        "TTS drain must wait only for audio still buffered"
    );
    assert!(
        VOICE_SCREEN.contains("public void onDestroy(")
            && VOICE_SCREEN.contains("executor.shutdown()")
            && VOICE_SCREEN.contains("captureExecutor.shutdown()"),
        "screen destroy must stop capture and shut down both executors"
    );
}
