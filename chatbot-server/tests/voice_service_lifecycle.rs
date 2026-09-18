//! CPU lifecycle for the owned voice-service settings + inference service.
//!
//! Given explicit startup settings plus injected fakes, when the Python suite
//! under `chatbot-cuda/tests` runs over real FastAPI HTTP, then settings
//! resolution, lifespan ownership (two independent apps, startup failure,
//! health readiness from the same service), TTS/STT routing with error
//! mapping, and WAV tempfile cleanup must hold without torch/GPU imports.
//! The streaming queue/thread contract is preserved verbatim in `service.py`
//! and covered through the stream route; GPU-runtime behavior is unmeasured
//! and no GPU claims are made here.

use std::path::PathBuf;
use std::process::Command;

fn chatbot_cuda_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("chatbot-cuda")
}

#[test]
fn voice_service_cpu_lifecycle_passes() {
    let root = chatbot_cuda_dir();
    assert!(
        root.join("tests").is_dir(),
        "chatbot-cuda/tests must exist at {}",
        root.display()
    );
    assert!(
        root.join("src").join("settings.py").is_file(),
        "chatbot-cuda/src/settings.py must exist at {}",
        root.display()
    );
    assert!(
        root.join("src").join("service.py").is_file(),
        "chatbot-cuda/src/service.py must exist at {}",
        root.display()
    );
    assert!(
        root.join("src").join("main.py").is_file(),
        "chatbot-cuda/src/main.py must exist at {}",
        root.display()
    );
    assert!(
        !root.join("src").join("models.py").exists(),
        "chatbot-cuda/src/models.py must stay removed: main owns settings/service with no import-time globals fallback"
    );

    let output = Command::new("python3")
        .args(["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"])
        .current_dir(&root)
        .output()
        .expect("python3 must be available in the tests image for voice-service CPU tests");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "voice-service CPU lifecycle tests failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        root.display()
    );
    println!("voice-service CPU tests passed:\n{stderr}");
}
