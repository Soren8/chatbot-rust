//! The voice service lives in the standalone chatbot-voice repo, which owns
//! its CPU lifecycle suite. This workspace only talks to it (or any other
//! OpenAI-compatible audio provider) through the `tts:`/`stt:` config blocks,
//! so no voice-service sources may creep back in here.

use std::path::PathBuf;

#[test]
fn voice_service_sources_live_outside_this_repo() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    assert!(
        !root.join("chatbot-cuda").join("src").exists(),
        "chatbot-cuda moved to the chatbot-voice repo"
    );
}
