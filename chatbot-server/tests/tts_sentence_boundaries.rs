//! Streaming TTS sentence boundaries and retry-exhaustion fail-stop.
//!
//! The terminator check holds extendable trailing fragments (colon, digit
//! period, all-caps initialism, known abbreviations/honorifics) while
//! generation continues so both discover loops speak each sentence once, and
//! desktop ignores a chunk that only appends punctuation/closers to an
//! already-queued sentence. Exhausted retries end the session with a visible
//! chat error instead of advancing to later sentences.

use std::path::Path;
use std::process::Command;

#[test]
fn streaming_boundaries_speak_once_on_both_real_queues() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/tts_sentence_boundary_test.js"))
        .arg(root.join("static/tts-playback.js"))
        .arg(root.join("static/voice-text.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS sentence-boundary behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn retry_exhaustion_ends_the_session_with_a_visible_error() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/tts_exhaustion_test.js"))
        .arg(root.join("static/tts-playback.js"))
        .arg(root.join("static/voice-text.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS exhaustion behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The terminator doubles as the streaming stability check: extendable
/// endings wait for their continuation while ordinary endings stream at once.
/// Owned discover loops live in static/tts-playback.js; chat keeps thin DOM
/// adapters delegating to them.
#[test]
fn streaming_terminator_holds_extendable_endings() {
    let chat_js = include_str!("../../static/chat.js");
    let playback_js = include_str!("../../static/tts-playback.js");
    assert!(
        !playback_js.contains("trailingTtsFragmentIsStable"),
        "no separate stability helper; the existing terminator carries the invariant"
    );
    assert!(
        !chat_js.contains("trailingTtsFragmentIsStable"),
        "no separate stability helper in chat either"
    );
    let voice_text_js = include_str!("../../static/voice-text.js");
    let term = function_body(voice_text_js, "sentenceEndsWithTerminator")
        .expect("sentenceEndsWithTerminator must be declared in the shared voice-text unit");
    for marker in [
        ":\\s*[\"'",
        "[0-9]\\.\\s*[\"'",
        "[A-Z]{2,4}\\.\\s*[\"'",
        "e\\.g|i\\.e|vs|etc|approx",
        "Mr|Mrs|Ms|Dr|Prof",
        "etcetera\\.",
    ] {
        assert!(
            term.contains(marker),
            "terminator must hold the extendable ending; missing: {marker}; got: {term}"
        );
    }
    let desktop = function_body(playback_js, "discoverAbsolute")
        .expect("owned desktop queue must contain discoverAbsolute");
    assert!(
        desktop.contains("!terminator(s.text) && isGenerating()"),
        "desktop discoverAbsolute gates the trailing fragment on the injected terminator; got: {desktop}"
    );
    assert!(
        desktop.contains("consumedLen > s.start"),
        "desktop must ignore a punctuation/closer-only extension of a queued sentence; got: {desktop}"
    );
    assert!(
        !desktop.contains("s.start < consumedLen"),
        "desktop must not blanket-skip by start offset (that drops shrunken sentences); got: {desktop}"
    );
    let native = function_body(playback_js, "discoverSentences")
        .expect("owned native queue must contain discoverSentences");
    assert!(
        native.contains("!terminator(part.text) && isGenerating()"),
        "native discoverSentences gates the trailing fragment on the injected terminator; got: {native}"
    );
    // The terminator itself stays owned by the shared voice-text unit (proven
    // above); both queues take it as an explicit dep that chat feeds from it.
    assert!(
        playback_js.contains("var terminator = deps.terminator;"),
        "the owned queues must take the terminator as an explicit dep, not a global"
    );
    assert!(
        chat_js.contains("terminator: function (text) { return sentenceEndsWithTerminator(text); }"),
        "chat must feed the owned queues the shared voice-text terminator"
    );
    for marker in [
        "ChatTtsPlayback.playMessageBodyTts",
        "ChatTtsPlayback.playNativeVoiceModeTts",
        "function playMessageBodyTts(",
        "function playNativeVoiceModeTts(",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat must keep thin DOM adapters delegating to the owned queues; missing: {marker}"
        );
    }
    assert!(
        !function_body(chat_js, "discoverAbsolute").is_some(),
        "discoverAbsolute lives in the owned unit, not as a parallel chat binding"
    );
}

/// Packaging contract: the chat page loads the owned renderer/playback units
/// before the application script, and chat.js delegates owned state to them.
#[test]
fn chat_page_wires_renderer_and_playback_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let renderer = html
        .find("/static/chat-renderer.js")
        .expect("chat page must load the owned renderer unit");
    let playback = html
        .find("/static/tts-playback.js")
        .expect("chat page must load the owned playback unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        renderer < app && playback < app,
        "renderer and playback must load before chat.js so ChatRenderer/ChatTtsPlayback exist"
    );
    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "ChatRenderer.createChatRenderer",
        "chatRenderer.buildAiErrorChildren",
        "chatRenderer.renderMarkdown",
        "chatRenderer.formatAiMessage",
        "ChatTtsPlayback.createDesktopClipPipeline",
        "ChatTtsPlayback.playFixedSentenceList",
        "ChatTtsPlayback.playMessageBodyTts",
        "ChatTtsPlayback.playNativeVoiceModeTts",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat.js must delegate owned rendering/playback to the shared units; missing: {marker}"
        );
    }
    let playback_js = include_str!("../../static/tts-playback.js");
    assert!(
        !playback_js.contains("window.") && !playback_js.contains("document."),
        "the owned playback unit must not touch window/document; DOM arrives via explicit callbacks"
    );
    let renderer_js = include_str!("../../static/chat-renderer.js");
    assert!(
        renderer_js.contains("createChatRenderer") && renderer_js.contains("createTrustedHtml"),
        "renderer must expose explicit sanitizer/markdown/highlighter deps, not a generic bag"
    );
    assert!(
        !renderer_js.contains("window.") || renderer_js.contains("window.location adapter"),
        "renderer must not touch window except via injected location docs"
    );
}

/// Exhaustion terminates with the existing chat error bubble plus telemetry.
/// No path advances to later sentences; the desktop pump never kills the
/// session on a transient failure (existing invariant, still enforced).
/// Owned pumps live in static/tts-playback.js; chat keeps thin adapters.
#[test]
fn exhaustion_terminates_without_advancing() {
    let playback_js = include_str!("../../static/tts-playback.js");
    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (fixed list)')",
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (desktop)')",
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (native)')",
        "appendMessage('Voice output failed. Try again.', 'error-message')",
    ] {
        assert!(
            playback_js.contains(marker),
            "exhaustion must surface via existing mechanisms in the owned unit; missing: {marker}"
        );
    }
    assert!(
        !playback_js.contains("skipping after retries"),
        "exhaustion must not skip ahead; the old skip language must be gone"
    );
    let fixed = function_body(playback_js, "playFixedSentenceList")
        .expect("owned fixed list must be declared");
    assert!(
        fixed.contains("onComplete(button)"),
        "fixed list must end the session via the explicit completion callback; got: {fixed}"
    );
    let body = function_body(playback_js, "playMessageBodyTts")
        .expect("owned desktop queue must be declared");
    let pump_start = body
        .find("function pump(")
        .expect("owned desktop queue must contain a sentence pump");
    let pump = &body[pump_start..];
    assert!(
        !pump.contains("stopCurrentDesktopTts"),
        "a transient sentence failure must not kill the whole desktop session"
    );
    assert!(
        pump.contains("onComplete(button)"),
        "exhausted desktop retries must end the session via onComplete; got: {pump}"
    );
    let native = function_body(playback_js, "playNativeVoiceModeTts")
        .expect("owned native queue must be declared");
    let catch_start = native
        .find("}).catch(function (err) {")
        .expect("native queue must handle exhaustion");
    let tail = &native[catch_start..catch_start + 900.min(native.len() - catch_start)];
    assert!(
        tail.contains("finishNative(generation, button)"),
        "exhausted native retries must end the session via the explicit finish callback; got: {tail}"
    );
    assert!(
        !tail.contains("releaseSlot(job)"),
        "exhaustion must not release the slot and advance; got: {tail}"
    );
    for marker in [
        "ChatTtsPlayback.playFixedSentenceList",
        "ChatTtsPlayback.playMessageBodyTts",
        "ChatTtsPlayback.playNativeVoiceModeTts",
        "function playFixedSentenceList(",
        "function playMessageBodyTts(",
    ] {
        assert!(
            chat_js.contains(marker),
            "chat must delegate owned exhaustion paths; missing: {marker}"
        );
    }
}

fn function_body<'a>(src: &'a str, fn_name: &str) -> Option<&'a str> {
    let header = format!("function {fn_name}(");
    let start = src.find(&header)?;
    let body = &src[start..];
    let open = body.find('{')?;
    let mut depth = 0i32;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}
