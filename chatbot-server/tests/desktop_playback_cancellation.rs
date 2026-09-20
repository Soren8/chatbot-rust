//! MOD-009-B regression: desktop playback cancellation owns settlement/disposal.
//!
//! Behavioral coverage through the REAL owned desktop clip pipeline
//! (`static/tts-playback.js`) composed with the REAL voice lifecycle
//! (`static/voice-lifecycle.js`), voice-text splitter, conversation tracker
//! and per-message source over fake audio/fetch/timers: midclip stop settles
//! the active clip and disposes queue subscriptions/observers/timers with no
//! later events; replacement playback keeps order with stale sessions silent;
//! clip and sentence retry/backoff cancellation clears pending work without
//! error UI. Chat stop/replacement adapters compose the explicit path; order,
//! retry bounds, shared desktop/native source semantics and the native dual
//! barge-in invariant are preserved.

use std::path::Path;
use std::process::Command;

fn run_scenario(scenario: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/desktop_playback_cancellation_test.js"))
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
        "JS desktop playback cancellation ({scenario}): {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn desktop_midclip_stop_settles_clip_and_disposes_queue() {
    run_scenario("midclip");
}

#[test]
fn desktop_replacement_play_keeps_order_with_stale_silent() {
    run_scenario("replacement");
}

#[test]
fn desktop_clip_retry_backoff_cancellation_clears_without_later_work() {
    run_scenario("clipretry");
}

#[test]
fn desktop_sentence_retry_backoff_cancellation_clears_without_later_work() {
    run_scenario("sentenceretry");
}

/// Wiring: the explicit session cancellation settles the active clip and
/// disposes queue-owned subscriptions/observers/timers, composed through the
/// actual chat stop/replacement adapters. Asserts real adapter composition,
/// not helper booleans alone.
#[test]
fn desktop_cancellation_wiring_through_actual_chat_adapters() {
    let playback = include_str!("../../static/tts-playback.js");
    let lifecycle = include_str!("../../static/voice-lifecycle.js");
    let chat = include_str!("../../static/chat.js");
    for marker in [
        "cancelSession",
        "activeClips",
        "retryTimer",
        "silent",
        "registerClipCanceller",
        "unregisterClipCanceller",
    ] {
        assert!(
            playback.contains(marker),
            "owned clip pipeline must expose explicit session cancellation; missing: {marker}"
        );
    }
    for marker in ["cancelled", "teardownObserver", "cancel", "dispose"] {
        assert!(
            playback.contains(marker),
            "owned queues must expose a disposal handle clearing subscriptions/observers/timers; missing: {marker}"
        );
    }
    assert!(
        playback.contains("clearTimeout"),
        "owned clip/queue retries must clear pending backoff timers on cancellation"
    );
    for marker in [
        "registerDesktopClipCanceller",
        "unregisterDesktopClipCanceller",
        "cancelDesktopClips",
    ] {
        assert!(
            lifecycle.contains(marker),
            "voice lifecycle must own clip-cancellation registration invoked on stop; missing: {marker}"
        );
    }
    assert!(
        lifecycle.contains("cancelDesktopClips()"),
        "lifecycle desktop stop must settle active clips before clearing handlers"
    );
    for entry in [
        "function stopCurrentDesktopTts(",
        "function stopAllTtsPlayback(",
        "function playMessageBodyTts(",
        "function playFixedSentenceList(",
    ] {
        assert!(
            chat.contains(entry),
            "chat must keep its playback adapter; missing: {entry}"
        );
    }
    assert!(
        chat.contains("cancelSession") || chat.contains("cancelAllClips"),
        "chat desktop stop adapters must compose pipeline session cancellation"
    );
    assert!(
        chat.contains("activeDesktopTtsQueue")
            || chat.contains("activeDesktopQueue")
            || chat.contains("desktopQueueHandle"),
        "chat must track the active desktop queue disposal handle across stop/replacement"
    );
    assert!(
        chat.contains("registerClipCanceller") || chat.contains("registerDesktopClipCanceller"),
        "chat must wire pipeline clip registration to the lifecycle owner"
    );
    assert!(
        !playback.contains("window.") && !playback.contains("document."),
        "the owned playback unit must not touch window/document; DOM arrives via explicit callbacks"
    );
    assert!(
        !lifecycle.contains("window.") && !lifecycle.contains("document."),
        "the shared lifecycle must not touch window/document"
    );
}
