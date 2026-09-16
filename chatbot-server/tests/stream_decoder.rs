//! Contract for `static/stream-decoder.js`: incremental decoding and
//! whole-text projection for the chat wire protocol. Chat strips console
//! detail and flushes at EOF; regenerate does not. TTS text selection and
//! thinking-toggle labels stay in the callers.

use std::path::Path;
use std::process::Command;

#[test]
fn stream_decoder_projects_wire_behavior() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/stream_decoder_test.js"))
        .arg(root.join("static/stream-decoder.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS stream-decoder behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn stream_decoder_js_parses() {
    let source = include_str!("../../static/stream-decoder.js");
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/stream-decoder.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared decoder before the
/// application script so the browser global exists when streaming starts.
/// History keeps its top-level projection entry point for paging callers.
#[test]
fn chat_page_wires_shared_decoder_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let decoder = html
        .find("/static/stream-decoder.js")
        .expect("chat page must load the shared stream decoder");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        decoder < app,
        "stream-decoder.js must load before chat.js so ChatStreamDecoder exists"
    );

    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "ChatStreamDecoder.decodeComplete",
        "ChatStreamDecoder.pushChunk",
        "ChatStreamDecoder.flushRemainder",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat.js must delegate streaming protocol to the shared decoder; missing: {marker}"
        );
    }
    assert_eq!(
        chat_js.matches("function formatAiMessage(text)").count(),
        1,
        "history paging still calls one top-level formatAiMessage"
    );
}
