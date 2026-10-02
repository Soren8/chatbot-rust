//! Behavior tests for the shipped native-audio.js implementation (Capacitor STT).

use std::path::Path;
use std::process::Command;

#[test]
fn shipped_native_audio_wav_and_adts_behavior() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/native_audio_wav_test.js"))
        .arg(root.join("static/native-audio.js"))
        .output()
        .expect("test image must provide Node");
    assert!(
        run.status.success(),
        "JS shipped-audio behavior: {}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Every WAV fallback in encodeAudioForStt must be reported with a
/// machine-readable reason; a successful AAC encode must also be logged with
/// sizes so operators can confirm compression actually engages (and spot the
/// plain-HTTP Android case where WebCodecs is unavailable).
#[test]
fn stt_codec_choice_and_fallbacks_are_logged_with_reasons() {
    let js = include_str!("../../static/native-audio.js");
    let start = js
        .find("async function encodeAudioForStt(")
        .expect("encodeAudioForStt must be declared");
    let end = js[start..]
        .find("function PcmSampleBuffer(")
        .map(|i| start + i)
        .unwrap_or(js.len());
    let body = &js[start..end];

    assert!(
        body.contains("sttCodecLog('STT codec: aac"),
        "a successful AAC encode must be logged with sizes (STT codec: aac bytes=... pcmBytes=...)"
    );
    assert!(
        body.contains("reason=no-webcodecs"),
        "missing AudioEncoder/AudioData must log reason=no-webcodecs, not fail silently"
    );
    assert!(
        body.contains("reason=insecure-context"),
        "plain HTTP (Android physical flavor) can never use WebCodecs; the fallback must log reason=insecure-context every utterance"
    );
    assert!(
        body.contains("reason=unsupported-config"),
        "an isConfigSupported rejection must log reason=unsupported-config, not fail silently"
    );
    assert!(
        body.contains("reason=empty-output"),
        "an empty encoder output must log reason=empty-output, not fail silently"
    );
    assert!(
        body.contains("reason=encoder-error"),
        "an encoder exception must log reason=encoder-error in addition to the console.warn"
    );
    assert!(
        js.contains("function sttCodecLog(") && js.contains("nativeLog('VAD'"),
        "codec logs must also reach adb logcat via window.nativeLog, not only the browser console"
    );
}
