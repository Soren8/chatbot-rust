//! Contract for `static/voice-events.js`: ONE central idempotence gate for
//! native voice-mode transitions (MOD012 phase 1 follow-up).
//!
//! Phone pause/resume and notification stop reach the page twice (owned
//! Capacitor listener plus the evalJs fallback) carrying one monotonic
//! coordinator transition ID. The shared unit owns the gate: only strictly
//! newer IDs apply, so duplicate deliveries collapse and a reordered stale
//! event cannot invalidate a newer session. `static/chat.js` keeps thin
//! handler adapters that claim through the gate first.

use std::path::Path;
use std::process::Command;

fn chat_js() -> &'static str {
    include_str!("../../static/chat.js")
}

#[test]
fn voice_events_gate_collapses_duplicates_and_stale_delivery() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_events_test.js"))
        .arg(root.join("static/voice-events.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS voice-events behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn voice_events_js_parses() {
    let source = include_str!("../../static/voice-events.js");
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/voice-events.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared events unit before the
/// application script, and chat.js claims every native transition through it.
#[test]
fn chat_page_wires_voice_events_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/voice-events.js")
        .expect("chat page must load the shared voice-events unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "voice-events.js must load before chat.js so ChatVoiceEvents exists"
    );

    let src = chat_js();
    for marker in [
        "ChatVoiceEvents.createTransitionGate",
        "voiceTransitionGate.claim(",
    ] {
        assert!(
            src.contains(marker),
            "chat.js must claim native transitions through the shared gate; missing: {marker}"
        );
    }
}
