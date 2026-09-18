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
        .arg(root.join("static/chat.js"))
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
        .arg(root.join("static/chat.js"))
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
#[test]
fn streaming_terminator_holds_extendable_endings() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        !chat_js.contains("trailingTtsFragmentIsStable"),
        "no separate stability helper; the existing terminator carries the invariant"
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
    let desktop = function_body(chat_js, "discoverAbsolute")
        .expect("playMessageBodyTts must contain discoverAbsolute");
    assert!(
        desktop.contains("sentenceEndsWithTerminator"),
        "desktop discoverAbsolute gates the trailing fragment on the terminator; got: {desktop}"
    );
    assert!(
        desktop.contains("consumedLen > s.start"),
        "desktop must ignore a punctuation/closer-only extension of a queued sentence; got: {desktop}"
    );
    assert!(
        !desktop.contains("s.start < consumedLen"),
        "desktop must not blanket-skip by start offset (that drops shrunken sentences); got: {desktop}"
    );
    let native = function_body(chat_js, "discoverSentences")
        .expect("playNativeVoiceModeTts must contain discoverSentences");
    assert!(
        native.contains("sentenceEndsWithTerminator"),
        "native discoverSentences gates the trailing fragment on the terminator; got: {native}"
    );
}

/// Exhaustion terminates with the existing chat error bubble plus telemetry.
/// No path advances to later sentences; the desktop pump never kills the
/// session on a transient failure (existing invariant, still enforced).
#[test]
fn exhaustion_terminates_without_advancing() {
    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (fixed list)')",
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (desktop)')",
        "reportVoice('VOICE-ERROR', 'TTS sentence failed (native)')",
        "appendMessage('Voice output failed. Try again.', 'error-message')",
    ] {
        assert!(
            chat_js.contains(marker),
            "exhaustion must surface via existing mechanisms; missing: {marker}"
        );
    }
    assert!(
        !chat_js.contains("skipping after retries"),
        "exhaustion must not skip ahead; the old skip language must be gone"
    );
    let fixed = function_body(chat_js, "playFixedSentenceList")
        .expect("playFixedSentenceList must be declared");
    assert!(
        fixed.contains("completeDesktopTtsPlayback(button)"),
        "fixed list must end the session; got: {fixed}"
    );
    let body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    let pump_start = body
        .find("function pump(")
        .expect("playMessageBodyTts must contain a sentence pump");
    let pump = &body[pump_start..];
    assert!(
        !pump.contains("stopCurrentDesktopTts"),
        "a transient sentence failure must not kill the whole desktop session"
    );
    assert!(
        pump.contains("completeDesktopTtsPlayback(button)"),
        "exhausted desktop retries must end the session; got: {pump}"
    );
    let native = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    let catch_start = native
        .find("}).catch(function (err) {")
        .expect("native queue must handle exhaustion");
    let tail = &native[catch_start..catch_start + 900.min(native.len() - catch_start)];
    assert!(
        tail.contains("finishNativeVoiceTts(generation, button)"),
        "exhausted native retries must end the session; got: {tail}"
    );
    assert!(
        !tail.contains("releaseSlot(job)"),
        "exhaustion must not release the slot and advance; got: {tail}"
    );
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
