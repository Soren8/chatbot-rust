//! Contract for `static/voice-capture.js`: single owned browser voice
//! capture (native PCM utterance VAD + desktop Silero factory) behind
//! explicit native-audio/lifecycle/clock/error/log/recorder hooks.
//! `static/chat.js` keeps platform composition (bridge pointer, stop
//! rendezvous, permission helper, voice-mode session UI) and thin adapters.
//! Thresholds live in `static/native-audio.js` and the Silero config;
//! the unit redefines none. Phase gates stay split: record at speech-like
//! start, barge in only on confirmed real speech.

use std::path::Path;
use std::process::Command;

fn capture_js() -> &'static str {
    include_str!("../../static/voice-capture.js")
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
fn voice_capture_projects_owned_dual_gates() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_capture_test.js"))
        .arg(root.join("static/voice-capture.js"))
        .arg(root.join("static/native-audio.js"))
        .arg(root.join("static/voice-lifecycle.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS shipped-VAD dual behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn voice_capture_js_parses() {
    let source = capture_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/voice-capture.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared capture unit before
/// the application script, and chat.js delegates owned state to it.
#[test]
fn chat_page_wires_voice_capture_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/voice-capture.js")
        .expect("chat page must load the shared voice-capture unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "voice-capture.js must load before chat.js so ChatVoiceCapture exists"
    );

    let src = chat_js();
    for marker in [
        "ChatVoiceCapture.NativeMicUtteranceVAD",
        "ChatVoiceCapture.createVAD",
        "function createNativeVadHost(",
        "function createDesktopVadHost(",
        "function createVAD(",
        "function ensureNativeMicPermission(",
    ] {
        assert!(
            src.contains(marker),
            "chat.js must delegate owned voice capture to the shared unit; missing: {marker}"
        );
    }
    assert!(
        src.find("NativeMicUtteranceVAD.prototype.start").is_none(),
        "the utterance state machine lives in the shared unit, never as a parallel chat binding"
    );
}

/// Single authority: capture lifecycle lives in the shared unit behind
/// explicit hooks. Thresholds stay in native-audio.js / the Silero config.
#[test]
fn voice_capture_single_authority_behind_explicit_hooks() {
    let unit = capture_js();
    assert!(
        unit.contains("ChatVoiceCapture") && unit.contains("NativeMicUtteranceVAD"),
        "UMD factory must expose ChatVoiceCapture.NativeMicUtteranceVAD"
    );
    for dep in [
        "nativeAudio",
        "voiceLifecycle",
        "isVoiceModeActive",
        "onBargeIn",
        "onUtteranceEnd",
        "recorder",
        "registry",
        "ensurePermission",
        "isCurrent",
        "getStopPromise",
        "setStopPromise",
    ] {
        assert!(
            unit.contains(dep),
            "capture deps must be explicit hooks; missing: {dep}"
        );
    }
    assert!(
        !unit.contains("window.") && !unit.contains("document."),
        "the shared unit must not touch window/document"
    );
    for redefined in [
        "SPEECH_START_FRAMES =",
        "SPEECH_RMS_THRESHOLD =",
        "REAL_SPEECH_MS =",
    ] {
        assert!(
            !unit.contains(redefined),
            "thresholds live in native-audio.js; the unit must use them, never redefine {redefined}"
        );
    }
    let desktop = function_body(unit, "createVAD").expect("createVAD");
    assert!(
        desktop.contains("positiveSpeechThreshold: 0.7")
            && desktop.contains("negativeSpeechThreshold: 0.4")
            && desktop.contains("redemptionMs: 1500")
            && desktop.contains("minSpeechMs: 400")
            && desktop.contains("preSpeechPadFrames: 16"),
        "desktop Silero config stays exactly as shipped; got: {desktop}"
    );
}

/// Phase gates stay split exactly as shipped: speech-like starts recording
/// (voicing excluded), barge-in needs confirmed real speech on the
/// flags-only session, and completion never barges in.
#[test]
fn voice_capture_gates_stay_split_on_the_flags_only_session() {
    let unit = capture_js();
    assert!(
        function_contains(unit, "_maybeStartUtterance", "pcm16IsSpeechLike")
            && !function_contains(unit, "_maybeStartUtterance", "pcm16IsVoicedSpeech")
            && !function_contains(unit, "_maybeStartUtterance", "pcm16RealSpeechDetected"),
        "recording start is speech-like only (coughs may record; they must not barge in)"
    );
    assert!(
        !function_contains(unit, "_beginUtterance", "onBargeIn"),
        "do not barge in at utterance start (that is onSpeechStart / cough-prone)"
    );
    assert!(
        function_contains(unit, "_maybeBargeIn", "onBargeIn")
            && function_contains(unit, "_maybeBargeIn", "pcm16RealSpeechDetected")
            && function_contains(unit, "_maybeBargeIn", "hasActiveVoiceSession")
            && function_contains(unit, "_accumulateUtterance", "_maybeBargeIn")
            && function_contains(unit, "_beginUtterance", "_maybeBargeIn"),
        "barge-in at real-speech confirm on the flags-only session, checked as audio accumulates"
    );
    assert!(
        !function_contains(unit, "_endUtterance", "onBargeIn"),
        "do not wait for the utterance to finish before stopping TTS"
    );
    assert!(
        function_contains(unit, "_onNativePcm", "_maybeStartUtterance")
            && function_contains(unit, "_onNativePcm", "hasActiveVoiceSession"),
        "speech start during a TTS session uses the utterance start gate on the owned flags-only session"
    );
    assert!(
        function_contains(unit, "createVAD", "onSpeechRealStart")
            && function_contains(unit, "createVAD", "noteFrameProcessed"),
        "desktop Silero must barge in on confirmed / high-confidence speech, not the first suspected frame"
    );
}

/// Stale-bridge discipline is owned: stop checks registry ownership before
/// touching the recorder, and a replacement waits for an in-flight stop.
#[test]
fn voice_capture_stale_stop_never_touches_a_newer_recorder() {
    let unit = capture_js();
    let stop_start = unit
        .find("NativeMicUtteranceVAD.prototype.stop")
        .expect("NativeMicUtteranceVAD.stop must be declared");
    let stop_body = &unit[stop_start..];
    let stop_end = stop_body
        .find("NativeMicUtteranceVAD.prototype.reinitialize")
        .unwrap_or(stop_body.len());
    let stop_body = &stop_body[..stop_end];
    let owner_check = stop_body
        .find("registry.isCurrent(this)")
        .expect("native VAD stop must check registry ownership");
    let recorder_stop = stop_body
        .find("recorder.stop()")
        .expect("native VAD stop must stop the recorder");
    assert!(
        owner_check < recorder_stop,
        "a stale bridge must not stop the recorder owned by a newer bridge"
    );
    assert!(
        stop_body.contains("getStopPromise")
            && stop_body.contains("setStopPromise"),
        "a replacement bridge must wait for an in-flight native stop to finish"
    );

    let start = unit
        .find("NativeMicUtteranceVAD.prototype.start")
        .expect("NativeMicUtteranceVAD.start must be declared");
    let start_body = &unit[start..];
    let start_end = start_body
        .find("NativeMicUtteranceVAD.prototype.stop")
        .unwrap_or(start_body.len());
    assert!(
        start_body[..start_end].contains("recorder.ensurePermission"),
        "native VAD start must wait for microphone permission before recorder start"
    );
}

/// Lifecycle errors propagate; the owner never swallows them. The frame
/// state machine must not wrap lifecycle callbacks, and the desktop factory
/// must not guard construction: failures surface exactly as the inline code
/// threw, so field logs keep the true cause.
#[test]
fn voice_capture_errors_propagate_exactly() {
    let unit = capture_js();
    let factory = function_body(unit, "createVAD").expect("createVAD");
    assert!(
        !factory.contains("try {") && !factory.contains("catch"),
        "desktop factory must not swallow construction failures; got: {factory}"
    );
    for swallowed in [
        "try { host.report(",
        "try { host.log(",
        "try { host.onBargeIn(",
        "try { host.onUtteranceEnd(",
    ] {
        assert!(
            !unit.contains(swallowed),
            "capture must propagate instead of swallowing; found: {swallowed}"
        );
    }
}
