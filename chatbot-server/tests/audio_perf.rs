use std::path::Path;
use std::process::Command;

fn compile_and_run(sources: &[std::path::PathBuf], main_class: &str, opens: &[&str]) {
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(output_dir.path())
        .args(sources)
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let mut run = Command::new("java");
    for module in opens {
        run.arg("--add-opens").arg(format!("{module}=ALL-UNNAMED"));
    }
    let run = run
        .arg("-cp")
        .arg(output_dir.path())
        .arg(main_class)
        .output()
        .expect("run java fixture");
    assert!(
        run.status.success(),
        "{main_class}: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Each body read schedules a stall watchdog; cancelled watchdogs must leave
/// the scheduler queue instead of lingering for the whole timeout window.
#[test]
fn tts_body_watchdog_queue_stays_bounded_across_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    compile_and_run(
        &[
            root.join("android/app/src/main/java/com/chatbot/app/audio/TtsBodyInputStream.java"),
            root.join("chatbot-server/tests/fixtures/audio_perf/TtsBodyWatchdogQueueTest.java"),
        ],
        "TtsBodyWatchdogQueueTest",
        &["java.base/java.util.concurrent"],
    );
}

/// The real Ogg-Opus decoder, compiled against a deterministic concentus
/// stub: PCM is identical for any chunking (checked against an independent
/// reference at 48 kHz and through the 24 kHz decimator), and parsed pages are
/// consumed so retained staging stays bounded instead of growing with the clip.
#[test]
fn ogg_opus_decoder_consumes_pages_and_keeps_pcm_identical() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let stub = root.join("chatbot-server/tests/fixtures/audio_perf");
    compile_and_run(
        &[
            root.join("android/app/src/main/java/com/chatbot/app/audio/OggOpusStreamDecoder.java"),
            stub.join("io/github/jaredmdobson/concentus/OpusDecoder.java"),
            stub.join("io/github/jaredmdobson/concentus/OpusException.java"),
            stub.join("OggOpusStagingTest.java"),
        ],
        "com.chatbot.app.audio.OggOpusStagingTest",
        &["java.base/java.io"],
    );
}
