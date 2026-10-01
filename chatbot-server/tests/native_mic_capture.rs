//! Behavior of the Android-free NativeMic capture loop (`NativeMicCapture.java`):
//! `getMinBufferSize` bytes become a 16-bit sample read size, a failed
//! `AudioRecord.read` ends capture instead of spinning, and PCM leaves as
//! contiguous little-endian 20 ms frames.

use std::path::Path;
use std::process::Command;

#[test]
fn native_mic_capture_sizes_reads_stops_on_read_errors_and_frames_pcm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicCapture.java"))
        .arg(root.join("chatbot-server/tests/fixtures/native_mic/NativeMicCaptureTest.java"))
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
        .arg("NativeMicCaptureTest")
        .output()
        .expect("run native mic capture behavior tests");
    assert!(
        run.status.success(),
        "native mic capture behavior:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn native_mic_plugin_runs_the_tested_capture_loop() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    assert!(
        plugin.contains("NativeMicCapture.readSamples(bufferSize)")
            && plugin.contains("NativeMicCapture.run("),
        "NativeMicPlugin must size reads and run capture through NativeMicCapture"
    );
    assert!(
        !plugin.contains("new short[bufferSize]"),
        "getMinBufferSize returns bytes; it must not size a short[] read buffer directly"
    );
    let handler = plugin
        .find("private void onCaptureReadError(")
        .map(|start| &plugin[start..])
        .expect("a failed AudioRecord.read must reach onCaptureReadError");
    let handler = &handler[..handler.find("\n    }\n").unwrap()];
    assert!(
        handler.contains("VOICE-ERROR")
            && handler.contains("generation == recordingGeneration.get()")
            && handler.contains("stopRecording()"),
        "a read error must report VOICE-ERROR and release only the recorder it came from"
    );
}
