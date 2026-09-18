//! Contract for `static/voice-text.js`: pure voice text shared by the
//! desktop and native voice paths (sentence splitting/termination, TTS
//! normalization, late-fragment joining, amend-vs-new-turn decision,
//! caret-offset sentence lookup). Chat keeps thin adapters over the shared
//! unit and owns only the amend-window literal, passed explicitly. No
//! threshold or queue behavior changes.

use std::path::Path;
use std::process::Command;

#[test]
fn voice_text_projects_turn_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_text_boundary_test.js"))
        .arg(root.join("static/voice-text.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS voice-text behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn voice_text_js_parses() {
    let source = include_str!("../../static/voice-text.js");
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/voice-text.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared voice-text unit before
/// the application script so the browser global exists when voice turns and
/// sentence clicks resolve. Chat delegates its voice-text helpers to the
/// shared unit instead of owning a second implementation.
#[test]
fn chat_page_wires_shared_voice_text_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/voice-text.js")
        .expect("chat page must load the shared voice-text unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "voice-text.js must load before chat.js so ChatVoiceText exists"
    );

    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "ChatVoiceText.joinVoiceUtterances",
        "ChatVoiceText.shouldAmendLastVoiceTurn",
        "ChatVoiceText.sentenceIndexAtOffset",
        "ChatVoiceText.sentenceEndsWithTerminator",
        "ChatVoiceText.splitSentences",
        "ChatVoiceText.sanitizeForTTS",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat.js must delegate voice text to the shared unit; missing: {marker}"
        );
    }
}

/// Threshold contract: the amend window stays a chat-owned literal because
/// `voice_mode_reliability.rs` parses `const VOICE_AMEND_WINDOW_MS = <int>`;
/// the adapter passes it explicitly and the shared unit takes it as a plain
/// parameter, so desktop and native keep one policy value.
#[test]
fn amend_window_stays_chat_owned_explicit_param() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("const VOICE_AMEND_WINDOW_MS = 2000"),
        "the amend window must stay a chat-owned 2000 ms literal"
    );
    assert!(
        chat_js.contains("}, VOICE_AMEND_WINDOW_MS);"),
        "the amend adapter must pass the owned window explicitly"
    );
    let unit = include_str!("../../static/voice-text.js");
    assert!(
        unit.contains("amendWindowMs"),
        "the shared unit must take the window as an explicit parameter"
    );
    assert!(
        !unit.contains("VOICE_AMEND_WINDOW_MS"),
        "the shared unit must not own the threshold"
    );
}
