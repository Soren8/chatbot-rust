//! MOD-009-B review proof: the real chat adapters own disposal.
//!
//! Bounded source slices of `static/chat.js` run in Node vm with the real
//! lifecycle, clip pipeline, voice-text, tracker and playback source over
//! fake audio/fetch/timers/DOM. Stops go through the real
//! stopCurrentDesktopTts and stopAllTtsPlayback; direct stops go through the
//! real lifecycle owner, which must immediately dispose queue timers,
//! observers and subscriptions on every stop path.

use std::path::Path;
use std::process::Command;

fn run_scenario(scenario: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/desktop_playback_cancellation_vm_test.js"))
        .arg(root.join("static/chat.js"))
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
        "JS desktop playback vm cancellation ({scenario}): {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn desktop_vm_stop_current_settles_resolved_clip_without_later_work() {
    run_scenario("stop-current");
}

#[test]
fn desktop_vm_stop_all_settles_resolved_clip_without_later_work() {
    run_scenario("stop-all");
}

#[test]
fn desktop_vm_fixed_list_retry_clears_without_later_work() {
    run_scenario("fixed-retry");
}

#[test]
fn desktop_vm_immediate_replacement_keeps_order_with_stale_silent() {
    run_scenario("immediate-replacement");
}

#[test]
fn desktop_vm_direct_lifecycle_stop_clears_retry_backoff_immediately() {
    run_scenario("direct-stop-retry");
}

#[test]
fn desktop_vm_direct_lifecycle_stop_clears_idle_poll_immediately() {
    run_scenario("direct-stop-poll");
}

/// Wiring: queues register disposers in the single lifecycle-owned registry
/// and chat composes stops through required single calls, not fallback chains.
#[test]
fn desktop_vm_cancellation_wiring_is_single_owned_and_required() {
    let playback = include_str!("../../static/tts-playback.js");
    let chat = include_str!("../../static/chat.js");
    for marker in [
        "registerClipCanceller(queueEntry)",
        "unregisterClipCanceller(queueEntry)",
    ] {
        assert!(
            playback.contains(marker),
            "owned queues must register disposers in the lifecycle-owned registry; missing: {marker}"
        );
    }
    for marker in [
        "var clearTimeoutFn = deps.clearTimeout;",
        "var registerClipCanceller = deps.registerClipCanceller;",
        "var unregisterClipCanceller = deps.unregisterClipCanceller;",
    ] {
        assert!(
            playback.contains(marker),
            "owned clip pipeline must take required cancellation deps; missing: {marker}"
        );
    }
    let register_wirings = chat
        .matches("registerClipCanceller: function (entry)")
        .count();
    assert!(
        register_wirings >= 3,
        "chat must wire pipeline plus both desktop queues to the lifecycle owner; found {register_wirings}"
    );
    let unregister_wirings = chat
        .matches("unregisterClipCanceller: function (entry)")
        .count();
    assert!(
        unregister_wirings >= 3,
        "chat must wire pipeline plus both desktop queue unregistration; found {unregister_wirings}"
    );
    for marker in [
        "if (handle) handle.cancel();",
        "desktopTtsClip.cancelSession(sessionId);",
    ] {
        assert!(
            chat.contains(marker),
            "chat stops must compose required single cancellation calls; missing: {marker}"
        );
    }
    assert!(
        !chat.contains("cancelAllClips"),
        "chat must not keep fallback clip-cancellation chains"
    );
}
