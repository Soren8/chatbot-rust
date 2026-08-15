//! Voice mode must recover without a driver reading errors or tapping again.

#[test]
fn native_mic_start_reuses_or_restarts_instead_of_rejecting_already_recording() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    assert!(
        !plugin.contains("Already recording"),
        "NativeMic.start must not reject when Capacitor reload leaves the plugin recording"
    );
    assert!(
        plugin.contains("isRecording"),
        "start() should still track an active AudioRecord session"
    );
}

#[test]
fn voice_mode_survives_capacitor_reload_without_a_second_tap() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("chatbotVoiceModeWanted"),
        "voice mode on/off must persist across location.reload() (Capacitor reload-ui)"
    );
    assert!(
        chat_js.contains("recoverNativeVoice") || chat_js.contains("_recoverNativeVoice"),
        "page load must stop leftover NativeMic/NativeVoiceTts before re-entering voice mode"
    );
    assert!(
        chat_js.contains("pagehide") || chat_js.contains("reload-ui"),
        "reload path should release native capture before the WebView document is replaced"
    );
}

#[test]
fn late_voice_utterance_amends_last_user_turn_instead_of_sending_a_new_one() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("function joinVoiceUtterances"),
        "late STT fragments must join onto the previous user text"
    );
    assert!(
        chat_js.contains("function shouldAmendLastVoiceTurn"),
        "in-flight generation or TTS must amend the last turn, not open a new /chat"
    );
    assert!(
        chat_js.contains("submitVoiceUtterance") || chat_js.contains("queueVoiceContinuation"),
        "handleSpeechEnd must route through an amend/resend helper"
    );
    assert!(
        chat_js.contains("abortChatRequestQuietly") || chat_js.contains("chatRequestSeq"),
        "aborted /chat must not clobber the replacement request or paint [Stopped]/error"
    );
    assert!(
        chat_js.contains("fetchWithGenerateRetry") || chat_js.contains("status === 429"),
        "amend must retry the generate lock instead of showing the 429 to the driver"
    );
}

/// A /chat or /regenerate HTTP failure must stay retryable and deletable.
/// Ghost pairs were never saved; delete must not 409 content-mismatch.
#[test]
fn failed_turn_keeps_regenerate_and_local_delete() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("function buildAiErrorChildren")
            && chat_js.contains("buildAiRegenerateContainer(true)"),
        "failed AI chrome must include an enabled regenerate button"
    );
    assert!(
        chat_js.contains("data-local-only"),
        "unsaved failed turns must be marked so delete does not hit the server"
    );
    assert!(
        chat_js.contains("reuseLastUser") && chat_js.contains("data-local-only"),
        "retry of a local-only turn must resend /chat, not /regenerate"
    );
}
