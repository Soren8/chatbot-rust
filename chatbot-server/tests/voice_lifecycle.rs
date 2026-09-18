//! Contract for `static/voice-lifecycle.js`: SINGLE owned browser voice
//! lifecycle (MOD009 phase 1).
//!
//! The shared unit owns currentAudio/currentButton, desktop
//! session/audio/abort/preloads/blob, TTS sessionActive/playing,
//! bargeFrames, listen cooldown and native-generation stale guards, plus the
//! completion/stopping transitions. `static/chat.js` keeps one owner plus
//! thin browser entry adapters and all DOM/VAD/queue rendering; pumps delegate
//! every lifecycle mutation to the owner. No duplicate mutable authority.

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/voice-lifecycle.js")
}

fn chat_js() -> &'static str {
    include_str!("../../static/chat.js")
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
fn voice_lifecycle_projects_owned_transitions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_lifecycle_test.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS voice-lifecycle behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn voice_lifecycle_js_parses() {
    let source = unit_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/voice-lifecycle.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared lifecycle unit before
/// the application script, and chat.js delegates owned state to it.
#[test]
fn chat_page_wires_voice_lifecycle_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/voice-lifecycle.js")
        .expect("chat page must load the shared voice-lifecycle unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "voice-lifecycle.js must load before chat.js so ChatVoiceLifecycle exists"
    );

    let src = chat_js();
    for marker in [
        "ChatVoiceLifecycle.createVoiceLifecycle",
        "ChatVoiceLifecycle.TTS_LISTEN_COOLDOWN_MS",
        "ChatVoiceLifecycle.BARGE_IN_FRAMES_DESKTOP",
        "ChatVoiceLifecycle.BARGE_IN_SPEECH_PROB",
        "voiceLifecycle.isTtsActive()",
        "voiceLifecycle.isLiveDesktop(",
        "voiceLifecycle.completeDesktopPlayback(",
        "voiceLifecycle.stopDesktopPlayback(",
        "voiceLifecycle.beginDesktopPlayback(",
        "voiceLifecycle.beginNativePlayback(",
        "voiceLifecycle.isLiveNativeGeneration(",
        "voiceLifecycle.finishNativePlayback(",
        "voiceLifecycle.invalidateNativeSession(",
        "voiceLifecycle.stopAllPlayback(",
        "voiceLifecycle.noteFrameProcessed(",
        "voiceLifecycle.hasActiveVoiceSession(",
        "voiceLifecycle.resetBargeFrames(",
        "voiceLifecycle.isInCooldown(",
        "voiceLifecycle.getCurrentButton()",
        "voiceLifecycle.isCurrentButton(",
    ] {
        assert!(
            src.contains(marker),
            "chat.js must delegate owned voice lifecycle to the shared unit; missing: {marker}"
        );
    }
    // Browser entry adapters keep their names; pumps stay in chat.js.
    for entry in [
        "function stopCurrentDesktopTts(",
        "function completeDesktopTtsPlayback(",
        "function desktopTtsIsLive(",
        "function isVoiceTtsActive(",
        "function stopAllTtsPlayback(",
        "function finishNativeVoiceTts(",
        "function invalidateNativeVoiceTts(",
        "function onVoiceModeTtsStarted(",
        "function onVoiceModeTtsEnded(",
        "function playNativeVoiceModeTts(",
        "function playMessageBodyTts(",
        "function playFixedSentenceList(",
        "function playOneTtsUtterance(",
        "window.playTTS",
    ] {
        assert!(
            src.contains(entry),
            "browser entry adapter must keep its name; missing: {entry}"
        );
    }
}

/// Single authority: lifecycle mutations live in the shared unit, never as
/// parallel_top-level bindings in chat.js. STT upload ownership stays outside
/// (voiceSttAbortController remains top-level for top-level playTTS).
#[test]
fn voice_lifecycle_single_authority_no_parallel_mutation() {
    let src = chat_js();
    for duplicate in [
        "let CURRENT_AUDIO",
        "let CURRENT_AUDIO_BUTTON",
        "let desktopTtsSession",
        "let desktopTtsAudio",
        "let desktopTtsAbort",
        "let desktopTtsPreloadCache",
        "let desktopTtsCurrentBlobUrl",
        "let voiceModeTtsSessionActive",
        "let voiceModeTtsPlaying",
        "let bargeInFrames",
        "let voiceModeListenCooldownUntil",
        "let nativeVoiceTtsGeneration",
        "CURRENT_AUDIO =",
        "CURRENT_AUDIO_BUTTON =",
        "desktopTtsSession +=",
        "desktopTtsSession =",
        "voiceModeTtsSessionActive =",
        "voiceModeTtsPlaying =",
        "bargeInFrames++",
        "bargeInFrames =",
        "voiceModeListenCooldownUntil =",
        "nativeVoiceTtsGeneration +=",
    ] {
        assert!(
            !src.contains(duplicate),
            "single authority lives in the shared unit; chat.js must not keep {duplicate}"
        );
    }
    // STT upload controller is not TTS lifecycle; top-level playTTS still aborts it.
    assert!(
        src.contains("let voiceSttAbortController"),
        "STT upload abort stays top-level so top-level playTTS can read it"
    );
    assert!(
        function_contains(src, "playTTS", "voiceSttAbortController"),
        "playTTS must keep aborting in-flight STT for barge-in"
    );
    assert!(
        function_contains(src, "playTTS", "beginDesktopPlayback"),
        "playTTS begin must delegate the owned desktop transition"
    );
}

/// Threshold contract: 400 ms cooldown and the desktop frame gate live in the
/// owner. Chat keeps read-only aliases; the frame gate delegates per frame.
#[test]
fn voice_lifecycle_thresholds_stay_owned_with_chat_aliases() {
    let unit = unit_js();
    assert!(
        unit.contains("TTS_LISTEN_COOLDOWN_MS = 400"),
        "cooldown stays 400 ms in the owner"
    );
    assert!(
        unit.contains("BARGE_IN_FRAMES_DESKTOP = 4"),
        "barge-in needs 4 high-confidence frames in the owner"
    );
    assert!(
        unit.contains("BARGE_IN_SPEECH_PROB = 0.85"),
        "barge-in speech prob stays 0.85 in the owner"
    );
    let gate = function_body(unit, "noteFrameProcessed").expect("noteFrameProcessed");
    assert!(
        gate.contains("BARGE_IN_SPEECH_PROB") && gate.contains("BARGE_IN_FRAMES_DESKTOP"),
        "the owned frame gate carries the threshold; got: {gate}"
    );
    let src = chat_js();
    for alias in [
        "const TTS_LISTEN_COOLDOWN_MS = ChatVoiceLifecycle.TTS_LISTEN_COOLDOWN_MS",
        "const BARGE_IN_FRAMES_DESKTOP = ChatVoiceLifecycle.BARGE_IN_FRAMES_DESKTOP",
        "const BARGE_IN_SPEECH_PROB = ChatVoiceLifecycle.BARGE_IN_SPEECH_PROB",
    ] {
        assert!(
            src.contains(alias),
            "chat keeps a read-only threshold alias; missing: {alias}"
        );
    }
    assert!(
        function_contains(src, "createVAD", "noteFrameProcessed"),
        "desktop Silero frames delegate to the owned gate"
    );
}

/// Completion/stopping/native-generation stale guards are owned transitions.
#[test]
fn voice_lifecycle_completion_stopping_and_stale_guards_are_owned() {
    let unit = unit_js();
    let finish = function_body(unit, "finishNativePlayback").expect("finishNativePlayback");
    assert!(
        finish.contains("generation !== nativeGeneration")
            && finish.contains("return false")
            && finish.contains("return true"),
        "stale native generations never touch the replacement; got: {finish}"
    );
    let live_desktop = function_body(unit, "isLiveDesktop").expect("isLiveDesktop");
    assert!(
        live_desktop.contains("sessionId === desktopSession")
            && live_desktop.contains("currentAudio.sessionId === sessionId"),
        "desktop liveness is exact session equality; got: {live_desktop}"
    );
    let stop_desktop = function_body(unit, "stopDesktopPlayback").expect("stopDesktopPlayback");
    assert!(
        stop_desktop.contains("desktopSession +=")
            && stop_desktop.contains("currentAudio = null"),
        "desktop stop bumps so prior async chains go stale; got: {stop_desktop}"
    );
    let stop_all = function_body(unit, "stopAllPlayback").expect("stopAllPlayback");
    assert!(
        stop_all.contains("preserveListen")
            && stop_all.contains("stopDesktopPlayback()"),
        "stop-all preserves listen vs arming cooldown and funnels desktop stop; got: {stop_all}"
    );
    let begin = function_body(unit, "beginDesktopPlayback").expect("beginDesktopPlayback");
    assert!(
        begin.contains("abortStt")
            && begin.contains("bargeFrames = 0")
            && begin.contains("sessionActive = true"),
        "desktop begin runs STT abort between the barge reset and sessionActive; got: {begin}"
    );
    assert!(
        finish.contains("onEnded") && finish.contains("cleanup"),
        "native finish runs onEnded then cleanup in owned order; got: {finish}"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "_maybeBargeIn", "hasActiveVoiceSession")
            && function_contains(src, "_onNativePcm", "hasActiveVoiceSession")
            && function_contains(src, "submitVoiceUtterance", "hasActiveVoiceSession"),
        "barge-in and utterance routing use the flags-only session, not currentAudio"
    );
    assert!(
        function_contains(src, "finishNativeVoiceTts", "onEnded")
            && function_contains(src, "finishNativeVoiceTts", "cleanup"),
        "native finish adapter must pass owned onEnded/cleanup order"
    );
    assert!(
        function_contains(src, "finishNativeVoiceTts", "finishNativePlayback"),
        "native finish adapter must delegate the owned stale-guarded transition"
    );
    assert!(
        function_contains(src, "stopAllTtsPlayback", "stopAllPlayback"),
        "stop-all adapter must delegate to the owner"
    );
    assert!(
        function_contains(src, "handleBargeIn", "VOICE_AMEND_WINDOW_MS")
            && function_contains(src, "handleBargeIn", "interruptVoiceReplyForNewTurn"),
        "barge-in after the amend window must interrupt immediately"
    );
}

/// Flags-only session excludes plain click-to-play; lifecycle errors
/// propagate instead of being swallowed.
#[test]
fn voice_lifecycle_flags_only_session_and_propagating_errors() {
    let unit = unit_js();
    let flags = function_body(unit, "hasActiveVoiceSession").expect("hasActiveVoiceSession");
    assert!(
        flags.contains("sessionActive") && flags.contains("playing"),
        "flags-only session tracks sessionActive/playing; got: {flags}"
    );
    assert!(
        !flags.contains("currentAudio"),
        "plain currentAudio must not count as a voice session; got: {flags}"
    );
    for swallowed in [
        "try { syncSendButtonFn();",
        "try { resetPlayButtonFn(",
        "try { clearMessageUiFn();",
        "try { return !!isVoiceModeActiveFn();",
        "try { desktopAudio = createAudioFn();",
        "try { desktopAbort = createAbortFn();",
    ] {
        assert!(
            !unit.contains(swallowed),
            "lifecycle must propagate instead of swallowing; found: {swallowed}"
        );
    }
}

/// The unit touches no window/document: DOM/audio/clock/native arrive as
/// explicit callbacks from chat.js.
#[test]
fn voice_lifecycle_unit_has_explicit_callbacks_no_dom_access() {
    let unit = unit_js();
    assert!(
        unit.contains("ChatVoiceLifecycle") && unit.contains("createVoiceLifecycle"),
        "UMD factory must expose ChatVoiceLifecycle.createVoiceLifecycle"
    );
    for dep in [
        "deps.now",
        "createAudio",
        "createAbortController",
        "revokeUrl",
        "resetPlayButton",
        "clearMessageUi",
        "syncSendButton",
        "isVoiceModeActive",
        "stopNativePlayback",
    ] {
        assert!(
            unit.contains(dep),
            "lifecycle deps must be explicit callbacks; missing: {dep}"
        );
    }
    // The clock literal lives at the delegate call site: chat.js passes
    // `now:` into createVoiceLifecycle while the owner reads `deps.now`.
    assert!(
        chat_js().contains("now: function () { return Date.now(); },"),
        "chat.js must pass the explicit clock callback into the owner"
    );
    assert!(
        !unit.contains("window.") && !unit.contains("document."),
        "the shared unit must not touch window/document"
    );
}
