//! Characterization for the MOD-009 playback-source follow-up.
//!
//! Pins actual queue/render behavior for the shared explicit per-message
//! playback source: streaming vs historical text parity on both real
//! queues, thinking/placeholder/error silence, trailing-hold while
//! generating, sentence-click exact strings, per-message (non-stalling)
//! progress, and the stop-suffix exclusion. Behavior scenarios run on the
//! real owned units (tts-playback, voice-text, conversation-state,
//! voice-lifecycle, playback-source) with leaf I/O stubbed; source-string
//! pins record the event-fed chat/queue wiring these behaviors arrive
//! through (no progress inference from buttons or rendered text).

use std::path::Path;
use std::process::Command;

fn run_scenario(scenario: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/playback_source_characterization_test.js"))
        .arg(root.join("static/tts-playback.js"))
        .arg(root.join("static/voice-text.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .arg(root.join("static/playback-source.js"))
        .arg(scenario)
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS playback characterization ({scenario}): {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn playback_streaming_and_historical_speak_same_text() {
    run_scenario("parity");
}

#[test]
fn playback_thinking_removed_and_placeholders_silent() {
    run_scenario("thinking");
}

#[test]
fn playback_trailing_fragment_held_while_generating() {
    run_scenario("hold");
}

#[test]
fn playback_sentence_click_list_exact_strings() {
    run_scenario("fixed");
}

#[test]
fn playback_finished_message_completes_while_tracker_generates() {
    run_scenario("historical");
}

#[test]
fn playback_stop_suffix_not_spoken() {
    run_scenario("stop");
}

/// Regression: retargeting a finished (historical) source to a replacement
/// sequence must atomically restart it — bound sequence, cleared text,
/// unfinished, single notify — so a fresh autoplay queue neither completes
/// before chunks arrive nor enqueues the stale answer, on both real queues.
#[test]
fn playback_retarget_restarts_finished_source_without_stale_text() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/playback_source_retarget_test.js"))
        .arg(root.join("static/tts-playback.js"))
        .arg(root.join("static/voice-text.js"))
        .arg(root.join("static/conversation-state.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .arg(root.join("static/playback-source.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS playback retarget regression: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Text wiring: the shared per-message source projects speakable text
/// (data-original with think stripping, visible fallback, shared sanitizing,
/// Thinking.../Error guards); chat publishes the strings its render sites
/// already own, never reading them back from the DOM.
#[test]
fn playback_text_projection_wiring() {
    let unit = include_str!("../../static/playback-source.js");
    let project =
        function_body(unit, "projectSpeakableText").expect("projectSpeakableText body");
    assert!(
        project.contains("<think>") && project.contains("fallbackVisible"),
        "projection prefers the original with think stripping plus a visible fallback; got: {project}"
    );
    assert!(
        project.contains("sanitize(")
            && project.contains("Thinking...")
            && project.contains("\\[Error\\]"),
        "projection sanitizes through the injected normalizer with placeholder/error guards; got: {project}"
    );
    assert!(
        !unit.contains("window.") && !unit.contains("document."),
        "the shared source takes text as explicit inputs, never DOM"
    );
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("function combinedAiOriginal("),
        "chat must publish the canonical wire shape it also renders"
    );
    assert!(
        chat_js.contains("function publishMessagePlaybackText("),
        "chat must publish text at its producing/updating sites"
    );
}

/// Progress wiring: terminal finished flag plus the bound request-tracker
/// sequence gate the tracker, so settled messages never stall on generation
/// elsewhere and live ones follow their own request. Queues read only the
/// source and wake on its subscribe plus the observer backstop; no adapter
/// or helper infers progress from buttons or rendered text.
#[test]
fn playback_progress_and_observation_wiring() {
    let unit = include_str!("../../static/playback-source.js");
    let source = function_body(unit, "createMessageSource").expect("createMessageSource body");
    assert!(
        source.contains("finished")
            && source.contains("boundSeq")
            && source.contains("retarget"),
        "progress is an explicit finished flag plus a migratable sequence binding; got: {source}"
    );
    assert!(
        source.contains("isTrackerGenerating") && source.contains("isTrackerLive"),
        "generation still comes from the owned request tracker; got: {source}"
    );
    let chat_js = include_str!("../../static/chat.js");
    for marker in [
        "function bindMessagePlaybackSource(",
        "function finishMessagePlayback(",
        "lookupMessagePlaybackSource(",
        "liveStreamPlaybackSource",
        "MutationObserver",
    ] {
        assert!(
            chat_js.contains(marker),
            "event-fed sources with a wake-only observer backstop; missing: {marker}"
        );
    }
    // No progress inference from rendered state in the integration seam.
    for entry in [
        "playMessageBodyTts",
        "playNativeVoiceModeTts",
        "bindMessagePlaybackSource",
        "publishMessagePlaybackText",
        "finishMessagePlayback",
    ] {
        let body =
            function_body(chat_js, entry).unwrap_or_else(|| panic!("{entry} must be declared"));
        for dom_progress in ["regenerate-button", "Thinking...", "is-generating"] {
            assert!(
                !body.contains(dom_progress),
                "{entry} must not infer progress from rendered state; found: {dom_progress}"
            );
        }
    }
    let playback_js = include_str!("../../static/tts-playback.js");
    assert!(
        playback_js.contains("function discoverAbsolute(")
            && playback_js.contains("function discoverSentences("),
        "both owned queues discover sentences from the supplied source"
    );
    assert!(
        playback_js.contains("deps.source") && playback_js.contains("source.subscribe"),
        "the owned queues take the explicit source and wake on it"
    );
    assert!(
        !playback_js.contains("window.") && !playback_js.contains("document."),
        "the owned queues take text/progress as explicit callbacks, never DOM"
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
