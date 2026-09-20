//! Contract for `static/playback-source.js`: shared explicit per-message
//! playback source (MOD-009 follow-up).
//!
//! The unit owns answer-text projection (data-original with think stripping,
//! visible fallback, shared voice-text sanitizing, Thinking.../Error guards)
//! and per-message progress (bound request-tracker sequence plus an explicit
//! finished flag) behind explicit deps. `static/chat.js` binds one source
//! per AI message at creation, publishes text at stream appends, and settles
//! it at done/cancel/failure sites; both owned TTS queues read only the
//! source and wake on its subscribe plus the observer backstop. Sentence
//! splitting, retry bounds/backoffs and the clip pipeline stay where they
//! were.

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/playback-source.js")
}

fn chat_js() -> &'static str {
    include_str!("../../static/chat.js")
}

fn playback_js() -> &'static str {
    include_str!("../../static/tts-playback.js")
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

fn function_contains(src: &str, fn_name: &str, needle: &str) -> bool {
    function_body(src, fn_name).is_some_and(|body| body.contains(needle))
}

#[test]
fn playback_source_projects_text_and_progress() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/playback_source_unit_test.js"))
        .arg(root.join("static/playback-source.js"))
        .arg(root.join("static/voice-text.js"))
        .arg(root.join("static/conversation-state.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS playback-source behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn playback_source_js_parses() {
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, unit_js(), source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/playback-source.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared source unit after the
/// voice-text normalizer and before the playback queues plus app script.
#[test]
fn chat_page_wires_playback_source_before_queues_and_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let voice_text = html
        .find("/static/voice-text.js")
        .expect("chat page must load the shared voice-text unit");
    let unit = html
        .find("/static/playback-source.js")
        .expect("chat page must load the shared playback-source unit");
    let playback = html
        .find("/static/tts-playback.js")
        .expect("chat page must load the owned playback unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        voice_text < unit && unit < playback && playback < app,
        "playback-source must load after voice-text and before tts-playback/chat.js"
    );
}

/// Ownership: projection plus event-fed progress live in the shared unit
/// behind explicit deps (never a generic getter bag, never DOM, never
/// button/last-AI/placeholder inference).
#[test]
fn playback_source_owns_projection_behind_explicit_deps() {
    let unit = unit_js();
    assert!(
        unit.contains("ChatPlaybackSource") && unit.contains("createMessageSource"),
        "UMD factory must expose ChatPlaybackSource.createMessageSource"
    );
    assert!(
        unit.contains("function projectSpeakableText("),
        "the unit must own the speakable-text projection"
    );
    for dep in [
        "deps.sanitize",
        "isTrackerGenerating",
        "isTrackerLive",
        "boundSeq",
    ] {
        assert!(
            unit.contains(dep),
            "source deps must be explicit callbacks/values; missing: {dep}"
        );
    }
    assert!(
        !unit.contains("deps.get(")
            && !unit.contains("getDependency")
            && !unit.contains("getAdapter"),
        "the source must not take a generic getter bag"
    );
    assert!(
        !unit.contains("window.") && !unit.contains("document."),
        "the shared source must not touch window/document"
    );
    for owned in ["publish", "finish", "retarget", "subscribe", "boundSeq"] {
        assert!(
            unit.contains(owned),
            "the source must own explicit event-fed text/progress; missing: {owned}"
        );
    }
    // Atomic restart: one retarget call rebinds the sequence, replaces the
    // text, clears the terminal flag, and notifies exactly once, so no
    // subscriber ever observes stale text on the new sequence.
    let retarget = function_body(unit, "retarget").expect("retarget body");
    assert!(
        retarget.contains("finished = false"),
        "retarget must clear the terminal flag; got: {retarget}"
    );
    assert!(
        retarget.match_indices("notify()").count() == 1,
        "retarget must notify exactly once after all state is set; got: {retarget}"
    );
    for removed in [
        "setState(",
        "streamingTarget",
        "refreshMessagePlaybackSource",
        "regenerate-button",
        ".prop(",
        "querySelector",
        "function getMessageTtsText(",
    ] {
        assert!(
            !unit.contains(removed),
            "no DOM-derived progress inference may remain in the unit; found: {removed}"
        );
    }
}

/// Integration mapping: every message-producing, updating, and settling site
/// in chat.js feeds the per-message source; progress never comes from
/// buttons or rendered text.
#[test]
fn chat_feeds_source_at_all_message_transition_sites() {
    let src = chat_js();
    // Registry + helpers.
    for marker in [
        "messagePlaybackSources",
        "function bindMessagePlaybackSource(",
        "function retargetMessagePlaybackSource(",
        "function lookupMessagePlaybackSource(",
        "function publishMessagePlaybackText(",
        "function finishMessagePlayback(",
        "function combinedAiOriginal(",
    ] {
        assert!(
            src.contains(marker),
            "chat must associate explicit sources with message hosts; missing: {marker}"
        );
    }
    // Creation binds: settled history seed, regeneration retarget, new stream.
    assert!(
        src.contains("bindMessagePlaybackSource($aiMsg[0],"),
        "history must seed each message source from the known message data"
    );
    assert!(
        src.contains("retargetMessagePlaybackSource($target[0], seq)"),
        "regeneration must migrate the bubble source to the replacement sequence"
    );
    assert!(
        src.contains("bindMessagePlaybackSource($targetElement[0],"),
        "a new stream must bind its bubble before text or autoplay arrives"
    );
    // Text publishes at every stream append in both generation paths.
    let publishes = src.match_indices("publishMessagePlaybackText($target").count()
        + src.match_indices("publishMessagePlaybackText($targetElement,").count();
    assert!(
        publishes >= 4,
        "both visible and thinking appends in both paths must publish; found {publishes}"
    );
    // Terminal settles: both done handlers, both read-error catches, both
    // abort/error catches, the voice-interrupt gate, and failed turns.
    let finishes = src.match_indices("finishMessagePlayback($").count();
    assert!(
        finishes >= 7,
        "done/cancel/failure sites must settle the source; found {finishes}"
    );
    assert!(
        function_contains(src, "paintFailedAiTurn", "buildAiErrorChildren")
            && src.contains("bindMessagePlaybackSource(failedHost,"),
        "failed turns must settle the bound source or bind a finished empty one"
    );
    assert!(
        src.contains("liveStreamPlaybackSource.finish()"),
        "history replace must finish the live stream source for its detached bubble"
    );
    // Adapters resolve the bound source by host and never synthesize
    // text/progress from the DOM.
    assert!(
        function_contains(src, "playMessageBodyTts", "lookupMessagePlaybackSource("),
        "the desktop adapter must look up the bound source"
    );
    assert!(
        function_contains(src, "playNativeVoiceModeTts", "lookupMessagePlaybackSource("),
        "the native adapter must look up the bound source"
    );
    for entry in [
        "playMessageBodyTts",
        "playNativeVoiceModeTts",
        "bindMessagePlaybackSource",
        "retargetMessagePlaybackSource",
        "lookupMessagePlaybackSource",
        "publishMessagePlaybackText",
        "finishMessagePlayback",
    ] {
        let body =
            function_body(src, entry).unwrap_or_else(|| panic!("{entry} must be declared"));
        for dom_progress in [
            "regenerate-button",
            "Thinking...",
            "is-generating",
            "chatRequests.isGenerating",
        ] {
            // The tracker read lives only in the source factory deps above;
            // these functions must not consult it or any rendered progress.
            assert!(
                !body.contains(dom_progress),
                "{entry} must not infer progress from rendered state; found: {dom_progress}"
            );
        }
    }
    // Removed: the DOM-recapturing refresh pipeline and its projection twin.
    for removed in [
        "function refreshMessagePlaybackSource(",
        "function readMessageFallbackText(",
        "function getMessageTtsText(",
        "function createMessagePlaybackSource(",
    ] {
        assert!(
            !src.contains(removed),
            "the DOM-recapture pipeline must be gone; found: {removed}"
        );
    }
}

/// Queues read answer text/progress only from the source and wake on its
/// subscribe plus the observer backstop. Poll intervals, retry
/// bounds/backoffs, terminator gating and the fixed-list exact-string path
/// are unchanged (no retuning, no retry changes).
#[test]
fn queues_consume_explicit_source_with_unchanged_bounds() {
    let playback = playback_js();
    for marker in [
        "deps.source",
        "source.subscribe",
        "source.getText()",
        "source.isGenerating()",
    ] {
        assert!(
            playback.contains(marker),
            "owned queues must consume the explicit source; missing: {marker}"
        );
    }
    assert!(
        !playback.contains("deps.getText")
            && !playback.contains("deps.isGenerating")
            && !playback.contains("refreshSource"),
        "queues must not take DOM-inferring text/progress callbacks or a refresh pipe"
    );
    for bound in [
        "MAX_TTS_SENTENCE_RETRIES",
        "MAX_TTS_CLIP_ATTEMPTS",
        "TTS_CLIP_RETRY_BACKOFF_MS",
        "MAX_NATIVE_TTS_LOOKAHEAD",
    ] {
        assert!(
            playback.contains(bound),
            "retry/lookahead bounds stay owned by the playback unit; missing: {bound}"
        );
    }
    assert!(
        playback.contains("}, 60);") && playback.contains("}, 80);"),
        "desktop (60 ms) and native (80 ms) poll fallbacks stay as they were"
    );
    let desktop = function_body(playback, "discoverAbsolute")
        .expect("owned desktop queue must contain discoverAbsolute");
    assert!(
        desktop.contains("!terminator(s.text) && isGenerating()"),
        "desktop discover still gates the trailing fragment on the terminator; got: {desktop}"
    );
    let native = function_body(playback, "discoverSentences")
        .expect("owned native queue must contain discoverSentences");
    assert!(
        native.contains("!terminator(part.text) && isGenerating()"),
        "native discover still gates the trailing fragment on the terminator; got: {native}"
    );
    let fixed = function_body(playback, "playFixedSentenceList")
        .expect("owned fixed list must be declared");
    assert!(
        !fixed.contains("source"),
        "sentence-click keeps its exact-string list path off the source; got: {fixed}"
    );
    assert!(
        !playback.contains("window.") && !playback.contains("document."),
        "the owned queues must not touch window/document"
    );
}

/// Native early exits stay before any message association: bridge-missing
/// fallback and the current-button toggle return before the context (now the
/// source lookup point) initializes.
#[test]
fn native_early_exits_preserved_before_context() {
    let playback = playback_js();
    let native = function_body(playback, "playNativeVoiceModeTts")
        .expect("owned playNativeVoiceModeTts must be declared");
    let bridge = native
        .find("if (!bridge)")
        .expect("bridge-missing fallback");
    let toggle = native
        .find("voiceLifecycle.isCurrentButton(button)")
        .expect("current-button toggle");
    let context = native
        .find("deps.initMessageContext()")
        .expect("message context init");
    assert!(
        bridge < toggle && toggle < context,
        "fallback and toggle must precede context init"
    );
    let init_tail = &native[context..];
    assert!(
        init_tail.contains("deps.source"),
        "the context init point must publish the explicit source"
    );
    let src = chat_js();
    let adapter = function_body(src, "playNativeVoiceModeTts").expect("native adapter");
    assert!(
        adapter.contains("initMessageContext")
            && adapter.contains("lookupMessagePlaybackSource("),
        "the native adapter looks the source up at the original association point; got: {adapter}"
    );
}
