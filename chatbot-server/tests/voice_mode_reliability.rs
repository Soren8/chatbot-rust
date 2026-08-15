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

/// Handheld voice mode must use the VoIP/speakerphone capture path.
/// VOICE_RECOGNITION + USAGE_MEDIA plays loud on the media speaker but keeps
/// the close-talk mic, so the user has to speak into the phone.
#[test]
fn handheld_voice_mode_uses_speakerphone_communication_path() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let route = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceAudioRoute.java"
    );
    let chat_js = include_str!("../../static/chat.js");
    let manifest = include_str!("../../android/app/src/main/AndroidManifest.xml");

    assert!(
        plugin.contains("VOICE_COMMUNICATION"),
        "AudioRecord must use VOICE_COMMUNICATION (VoIP/speakerphone mic + AEC)"
    );
    assert!(
        !plugin.contains("VOICE_RECOGNITION"),
        "VOICE_RECOGNITION is the close-talk recognizer path; do not use it for voice mode"
    );
    assert!(
        plugin.contains("enterVoiceRoute") && plugin.contains("exitVoiceRoute"),
        "speakerphone routing must be a session-held NativeMic plugin API"
    );
    assert!(
        route.contains("MODE_IN_COMMUNICATION"),
        "voice-mode session must enter MODE_IN_COMMUNICATION"
    );
    assert!(
        route.contains("setCommunicationDeviceToSpeaker")
            && plugin.contains("getAvailableCommunicationDevices"),
        "API 31+ must route to TYPE_BUILTIN_SPEAKER via setCommunicationDevice"
    );
    assert!(
        tts.contains("USAGE_VOICE_COMMUNICATION"),
        "TTS must play as USAGE_VOICE_COMMUNICATION so hardware AEC has a reference"
    );
    assert!(
        chat_js.contains("enterVoiceRoute") && chat_js.contains("exitVoiceRoute"),
        "JS must hold speakerphone routing for the whole voice-mode session"
    );
    assert!(
        !chat_js.contains("exitVoiceRoute")
            || !function_contains(chat_js, "stopVoicePlaybackOnly", "exitVoiceRoute"),
        "barge-in must not drop speakerphone routing"
    );
    assert!(
        manifest.contains("MODIFY_AUDIO_SETTINGS"),
        "setMode/setSpeakerphoneOn require MODIFY_AUDIO_SETTINGS"
    );
}

/// Far-field speech is much quieter than close-talk. 1400 RMS required the
/// mouth on the phone; speakerphone VAD must accept table-distance speech.
#[test]
fn native_vad_rms_threshold_accepts_speakerphone_distance() {
    let native_audio = include_str!("../../static/native-audio.js");
    let threshold = parse_js_int_const(native_audio, "SPEECH_RMS_THRESHOLD")
        .expect("SPEECH_RMS_THRESHOLD must be declared in native-audio.js");
    assert!(
        (300..=800).contains(&threshold),
        "SPEECH_RMS_THRESHOLD={threshold} is not a speakerphone-distance gate"
    );
}

fn parse_js_int_const(src: &str, name: &str) -> Option<i32> {
    let needle = format!("const {name} = ");
    let start = src.find(&needle)? + needle.len();
    let rest = src[start..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn function_contains(src: &str, fn_name: &str, needle: &str) -> bool {
    let header = format!("function {fn_name}(");
    let Some(start) = src.find(&header) else {
        return false;
    };
    let body = &src[start..];
    let Some(open) = body.find('{') else {
        return false;
    };
    let mut depth = 0i32;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return body[open..=open + i].contains(needle);
                }
            }
            _ => {}
        }
    }
    false
}
