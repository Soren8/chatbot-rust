//! Native voice capture consumes Silero probabilities produced on Android's
//! microphone thread. PCM chunks carry audio; only fresh 32 ms model results
//! advance the speech, end-silence, and barge-in gates.

use std::path::Path;
use std::process::Command;

#[test]
fn native_silero_confidence_metadata_contract() {
    let capture = include_str!("../../static/voice-capture.js");
    let chat = include_str!("../../static/chat.js");
    let audio = include_str!("../../static/native-audio.js");
    assert!(chat.contains("window.NativeMic.start(options)"));
    assert!(capture.contains("recorder.start({ vad: true })"));
    assert!(capture.contains("data.vadProbability") && capture.contains("data.vadDurationMs"));
    assert!(capture.contains("durationMs !== 0 && durationMs !== 32"));
    assert!(audio.contains("const SPEECH_START_MS = 120"));
    assert!(audio.contains("const REAL_SPEECH_MS = 600"));
    assert!(audio.contains("const SPEECH_MIN_ACTIVE_MS = 400"));
    assert!(capture.contains("SPEECH_END_SILENCE_MS"));
}

#[test]
fn pcm_amplitude_does_not_classify_native_speech() {
    let capture = include_str!("../../static/voice-capture.js");
    let audio = include_str!("../../static/native-audio.js");
    for obsolete in [
        "function pcm16IsSpeechLike",
        "function pcm16IsVoicedSpeech",
        "function pcm16RealSpeechDetected",
        "pcm16IsSpeechLike:",
        "pcm16RealSpeechDetected:",
    ] {
        assert!(
            !audio.contains(obsolete),
            "obsolete PCM classifier remains: {obsolete}"
        );
        assert!(
            !capture.contains(obsolete),
            "native capture still uses classifier: {obsolete}"
        );
    }
}

#[test]
fn shipped_native_vad_dual_invariant_on_real_capture() {
    run_native_capture_fixture();
}

#[test]
fn cough_and_hey_do_not_barge_in_sustained_noisy_speech_does() {
    run_native_capture_fixture();
}

fn run_native_capture_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_capture_test.js"))
        .arg(root.join("static/voice-capture.js"))
        .arg(root.join("static/native-audio.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS shipped native Silero behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn native_audio_no_longer_exports_waveform_vad() {
    let src = include_str!("../../static/native-audio.js");
    assert!(src.contains("SPEECH_START_MS"));
    assert!(src.contains("REAL_SPEECH_MS"));
    assert!(src.contains("SPEECH_END_SILENCE_MS"));
    assert!(!src.contains("SPEECH_RMS_THRESHOLD"));
    assert!(!src.contains("SPEECH_PERIODICITY_MIN"));
}
