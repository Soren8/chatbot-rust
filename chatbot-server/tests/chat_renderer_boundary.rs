//! Contract for `static/chat-renderer.js`: cohesive owned message rendering
//! (escaping, image allowlists, user/system/error/AI chrome, markdown and
//! history projection) behind explicit sanitizer/markdown/highlighter
//! dependencies. `static/chat.js` keeps DOM/event composition (mount, scroll,
//! message assembly, lightbox open/close) and thin adapters over the unit.

use std::path::Path;
use std::process::Command;

#[test]
fn chat_renderer_projects_untrusted_text_as_text() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/chat_renderer_test.js"))
        .arg(root.join("static/chat-renderer.js"))
        .arg(root.join("static/stream-decoder.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS renderer behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn chat_renderer_js_parses() {
    let source = include_str!("../../static/chat-renderer.js");
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/chat-renderer.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Image sinks accept only `URL.createObjectURL` results, so DOM/message text
/// can never become a script URL (CodeQL js/xss-through-dom). `chat.js` also
/// records sanitized sources in a WeakMap instead of reading `src` back.
#[test]
fn image_src_is_only_assigned_object_urls() {
    let renderer = include_str!("../../static/chat-renderer.js");
    let chat = include_str!("../../static/chat.js");
    for (name, source) in [("chat-renderer.js", renderer), ("chat.js", chat)] {
        let mut rest = source;
        let mut found = 0;
        while let Some(at) = rest.find("setAttribute('src',") {
            let tail = &rest[at + "setAttribute('src',".len()..];
            assert!(
                tail.starts_with(" objectUrl)"),
                "{name} assigns an image src from something other than an object URL: {}",
                tail.chars().take(40).collect::<String>()
            );
            found += 1;
            rest = &tail[1..];
        }
        assert!(found > 0, "{name} must assign image src at least once");
    }
    assert!(
        !chat.contains("getAttribute('src')"),
        "chat.js must not read image src back from the DOM; use the imageSources WeakMap"
    );
    assert!(
        !chat.contains(".attr('src'"),
        "chat.js must route image sources through loadHistoryImage, not jQuery .attr('src', ...)"
    );
}

/// Ownership: builders and the markdown/history projection live in the shared
/// unit behind named deps (never a generic getter bag); chat keeps thin
/// adapters so existing call sites are unchanged.
#[test]
fn chat_renderer_owns_chrome_behind_explicit_deps() {
    let unit = include_str!("../../static/chat-renderer.js");
    assert!(
        unit.contains("createChatRenderer") && unit.contains("createTrustedHtml"),
        "renderer deps must be explicit (trusted-HTML wrapper); got no generic bag"
    );
    assert!(
        !unit.contains("deps.get(")
            && !unit.contains("getDependency")
            && !unit.contains("getAdapter"),
        "renderer must not take a generic getter bag"
    );
    for owned in [
        "function buildUserMessageSpan(",
        "function buildAiErrorChildren(",
        "function buildAiHistoryChildren(",
        "function buildAiStreamChildren(",
        "function buildAiRegenerateContainer(",
        "function sanitizeLightboxSrc(",
        "function renderMarkdown(",
        "function formatAiMessage(",
    ] {
        assert!(
            unit.contains(owned),
            "renderer must own the cohesive builder; missing: {owned}"
        );
    }
    assert!(
        !unit.contains("window.") && !unit.contains("document."),
        "the shared unit must not touch window/document; DOM arrives via explicit deps"
    );

    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "ChatRenderer.createChatRenderer",
        "chatRenderer.buildUserMessageSpan",
        "chatRenderer.buildAiErrorChildren",
        "chatRenderer.buildAiHistoryChildren",
        "chatRenderer.buildAiStreamChildren",
        "chatRenderer.sanitizeLightboxSrc",
        "chatRenderer.renderMarkdown",
        "chatRenderer.formatAiMessage",
        "chatRenderer.configureMarked",
        "function buildAiErrorChildren(",
        "function renderMarkdown(",
        "function formatAiMessage(",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat must delegate owned rendering through thin adapters; missing: {marker}"
        );
    }
}
