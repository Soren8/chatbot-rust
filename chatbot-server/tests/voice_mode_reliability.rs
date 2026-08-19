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
        "a quick follow-up must amend the last turn, not open a new /chat"
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

/// Amend is only for a false end-of-speech or a quick add-on. After 1–2s,
/// barge-in must stop generation/TTS and send a new user turn.
#[test]
fn voice_amend_only_within_two_seconds_of_last_speech_end() {
    let chat_js = include_str!("../../static/chat.js");
    let window_ms = parse_js_int_const(chat_js, "VOICE_AMEND_WINDOW_MS")
        .expect("VOICE_AMEND_WINDOW_MS must be declared in chat.js");
    assert!(
        (1000..=2000).contains(&window_ms),
        "VOICE_AMEND_WINDOW_MS={window_ms} must be 1–2 seconds"
    );
    assert!(
        function_contains(chat_js, "shouldAmendLastVoiceTurn", "lastSpeechEndedAt")
            && function_contains(chat_js, "shouldAmendLastVoiceTurn", "utteranceStartedAt")
            && function_contains(chat_js, "shouldAmendLastVoiceTurn", "VOICE_AMEND_WINDOW_MS"),
        "amend must require the new utterance to start within the window of the last speech end"
    );
    assert!(
        function_contains(chat_js, "shouldAmendLastVoiceTurn", "generating")
            && function_contains(chat_js, "shouldAmendLastVoiceTurn", "ttsActive"),
        "outside an in-flight reply there is nothing to amend"
    );
    assert!(
        function_contains(chat_js, "submitVoiceUtterance", "interruptVoiceReplyForNewTurn")
            && function_contains(chat_js, "submitVoiceUtterance", "sendMessage"),
        "speech after the window must stop the current reply and send a new /chat"
    );
    assert!(
        function_contains(chat_js, "interruptVoiceReplyForNewTurn", "[Stopped]")
            && function_contains(chat_js, "interruptVoiceReplyForNewTurn", "stopAllTtsPlayback"),
        "a new voice turn must halt TTS and finalize the interrupted AI bubble"
    );
    assert!(
        function_contains(chat_js, "handleBargeIn", "VOICE_AMEND_WINDOW_MS")
            && function_contains(chat_js, "handleBargeIn", "interruptVoiceReplyForNewTurn"),
        "barge-in after the window must stop generation immediately, not wait for STT"
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

/// Handheld voice mode is JS-driven. Auto screen sleep pauses the Activity /
/// WebView, so VAD, STT, and TTS stop. Hold FLAG_KEEP_SCREEN_ON for the
/// session (and a JS screen wake lock on HTTPS) instead of requiring a
/// background microphone service.
#[test]
fn voice_mode_holds_screen_awake_for_the_session() {
    let keep = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceSessionKeepAwake.java"
    );
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let tests = include_str!(
        "../../android/app/src/test/java/com/chatbot/app/audio/VoiceSessionKeepAwakeTest.java"
    );
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        keep.contains("setKeepScreenOn") && plugin.contains("FLAG_KEEP_SCREEN_ON"),
        "voice session must hold FLAG_KEEP_SCREEN_ON so auto screen sleep cannot kill VAD"
    );
    assert!(
        plugin.contains("voiceSessionKeepAwake.enter")
            && plugin.contains("voiceSessionKeepAwake.exit")
            && plugin.contains("enterVoiceRoute")
            && plugin.contains("exitVoiceRoute"),
        "keep-awake must follow the voice-mode session, not TTS start/stop"
    );
    assert!(
        tests.contains("enterKeepsScreenOnOnce")
            && tests.contains("secondEnterDoesNotRetouchScreen"),
        "unit test must lock idempotent keep-awake enter/exit"
    );
    assert!(
        chat_js.contains("acquireVoiceScreenWakeLock")
            && chat_js.contains("releaseVoiceScreenWakeLock")
            && chat_js.contains("navigator.wakeLock"),
        "HTTPS / browser voice mode must request a Screen Wake Lock"
    );
    assert!(
        function_contains(chat_js, "startVoiceMode", "acquireVoiceScreenWakeLock")
            && function_contains(chat_js, "stopVoiceMode", "releaseVoiceScreenWakeLock"),
        "JS wake lock must be acquired for the voice-mode session and released on stop"
    );
    assert!(
        !function_contains(chat_js, "stopVoicePlaybackOnly", "releaseVoiceScreenWakeLock")
            && !function_contains(chat_js, "stopVoicePlaybackOnly", "exitVoiceRoute"),
        "barge-in must not drop keep-awake or speakerphone routing"
    );
}

/// Voice Mode must not yank playback off a connected Bluetooth headset.
#[test]
fn voice_mode_leaves_bluetooth_route_alone() {
    let route = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceAudioRoute.java"
    );
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let tests = include_str!(
        "../../android/app/src/test/java/com/chatbot/app/audio/VoiceAudioRouteTest.java"
    );

    assert!(
        route.contains("hasBluetoothAudio")
            && route.contains("backend.hasBluetoothAudio()"),
        "enter() must refuse speakerphone routing when Bluetooth audio is connected"
    );
    assert!(
        route.contains("TYPE_BLUETOOTH_A2DP")
            && route.contains("TYPE_BLUETOOTH_SCO")
            && route.contains("TYPE_BLE_HEADSET"),
        "Bluetooth detection must include A2DP, SCO, and BLE headsets"
    );
    assert!(
        plugin.contains("hasBluetoothAudio")
            && plugin.contains("GET_DEVICES_OUTPUTS")
            && plugin.contains("isBluetoothA2dpOn"),
        "NativeMic must inspect current Bluetooth outputs before enterVoiceRoute"
    );
    assert!(
        tests.contains("enterDoesNotChangeRouteWhenBluetoothAudioConnected"),
        "unit test must lock the Bluetooth no-op path"
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

/// Voice transcripts append a user bubble then send /chat. Checking
/// isAtBottom() after insert unpins (bubble > 30px) and leaves the new text
/// off-screen. Stick must be sampled before insert, and scrollTop must pin.
#[test]
fn voice_send_scrolls_chat_to_bottom() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("function shouldStickChatToBottom"),
        "chat follow-state must be shared by mount and stream"
    );
    assert!(
        function_contains(chat_js, "mountChatMessage", "shouldStickChatToBottom"),
        "mountChatMessage must sample stick-to-bottom before inserting the bubble"
    );
    assert!(
        function_contains(chat_js, "scrollToBottom", "scrollTop = container.scrollHeight"),
        "scrollToBottom must assign scrollTop (WebView-safe pin)"
    );
    assert!(
        function_contains(chat_js, "submitVoiceUtterance", "scrollToBottom")
            && function_contains(chat_js, "applyVoiceAmendToUserMessage", "scrollToBottom"),
        "voice send and amend must pin the chat to the new text"
    );
}

/// TTS must stop when real speech is first detected (utterance start), not
/// after the user finishes talking. Energy-only bursts (cough, clap, hiss)
/// must not count as speech. SPEECH_START_FRAMES of speech-like frames is
/// the gate; SPEECH_MIN_ACTIVE_MS is only for sending to STT.
#[test]
fn native_tts_barge_in_on_initial_speech() {
    let chat_js = include_str!("../../static/chat.js");
    let native_audio = include_str!("../../static/native-audio.js");

    assert!(
        !chat_js.contains("BARGE_IN_CONFIRM_MS") && !native_audio.contains("BARGE_IN_CONFIRM_MS"),
        "barge-in must not wait for SPEECH_MIN_ACTIVE_MS / BARGE_IN_CONFIRM_MS"
    );
    assert!(
        !chat_js.contains("BARGE_IN_RMS_THRESHOLD") && !chat_js.contains("BARGE_IN_RMS_FRAMES"),
        "TTS barge-in must not trip on a short RMS energy burst"
    );
    assert!(
        native_audio.contains("function pcm16IsSpeechLike")
            && native_audio.contains("SPEECH_ZCR_MIN")
            && native_audio.contains("SPEECH_ZCR_MAX")
            && native_audio.contains("SPEECH_CREST_MAX"),
        "native VAD must classify speech vs cough/noise, not energy alone"
    );
    assert!(
        function_contains(chat_js, "_maybeStartUtterance", "pcm16IsSpeechLike"),
        "utterance start (and barge-in) must require speech-like frames"
    );
    assert!(
        function_contains(chat_js, "_beginUtterance", "handleBargeIn"),
        "native barge-in must fire at utterance start, immediately on detection"
    );
    assert!(
        !function_contains(chat_js, "_accumulateUtterance", "handleBargeIn"),
        "do not wait for the utterance to finish accumulating before stopping TTS"
    );
    assert!(
        function_contains(chat_js, "_onNativePcm", "_maybeStartUtterance")
            && function_contains(chat_js, "_onNativePcm", "voiceModeTtsSessionActive"),
        "speech start during a TTS session must use the utterance start gate"
    );
    assert!(
        function_contains(chat_js, "createVAD", "onSpeechRealStart")
            && function_contains_near(chat_js, "onSpeechRealStart", "handleBargeIn")
            && function_contains(chat_js, "createVAD", "BARGE_IN_SPEECH_PROB"),
        "desktop Silero must barge in on confirmed / high-confidence speech, not the first suspected frame"
    );
    assert!(
        !chat_js.contains("if (CURRENT_AUDIO) handleBargeIn()"),
        "first-frame onSpeechStart is cough-prone; do not barge in there"
    );
    assert!(
        function_contains(chat_js, "createVAD", "minSpeechMs")
            && !function_contains(chat_js, "createVAD", "minSpeechFrames")
            && !function_contains(chat_js, "createVAD", "redemptionFrames"),
        "bundled Silero v5 reads minSpeechMs / redemptionMs, not the old frame counts"
    );
    let start_frames = parse_js_int_const(native_audio, "SPEECH_START_FRAMES")
        .expect("SPEECH_START_FRAMES must be declared in native-audio.js");
    assert!(
        (3..=8).contains(&start_frames),
        "SPEECH_START_FRAMES={start_frames} should be a short initial-speech gate"
    );
    let min_speech_ms = parse_js_int_const(native_audio, "SPEECH_MIN_ACTIVE_MS")
        .expect("SPEECH_MIN_ACTIVE_MS must be declared in native-audio.js");
    assert!(
        min_speech_ms >= 300,
        "SPEECH_MIN_ACTIVE_MS={min_speech_ms} is too short to reject noise bursts at STT"
    );
}

/// Desktop and mobile share one TTS stop. The play icon, message click, Stop
/// button, barge-in, and disabling voice mode must all halt playback — not
/// only bump the desktop HTMLAudio session.
#[test]
fn voice_mode_gui_stop_halts_tts_on_desktop_and_mobile() {
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        chat_js.contains("function stopAllTtsPlayback"),
        "one shared TTS stop for voice-mode HTML audio and NativeVoiceTts"
    );
    assert!(
        function_contains(chat_js, "handleStopClick", "stopAllTtsPlayback"),
        "Send/Stop must halt TTS, not only abort /chat"
    );
    assert!(
        function_contains(chat_js, "stopVoiceMode", "stopAllTtsPlayback"),
        "disabling voice mode must halt TTS (desktop audioEl and native)"
    );
    assert!(
        function_contains(chat_js, "handleBargeIn", "stopAllTtsPlayback"),
        "barge-in must use the same stop as the GUI"
    );
    assert!(
        function_contains(chat_js, "playTTS", "stopAllTtsPlayback"),
        "play/stop icon must not call stopCurrentDesktopTts alone (leaves voice audio playing)"
    );
    assert!(
        chat_js.contains("stopAllTtsPlayback")
            && chat_js.contains("Click to stop speech")
            && function_contains_near(chat_js, "CURRENT_AUDIO_BUTTON === playBtn", "stopAllTtsPlayback"),
        "clicking the speaking message must use the shared stop"
    );
    assert!(
        function_contains(chat_js, "stopAllTtsPlayback", "NativeVoiceTts")
            && function_contains(chat_js, "stopAllTtsPlayback", "stopCurrentDesktopTts"),
        "shared stop must kill both native AudioTrack and desktop HTMLAudio"
    );
    assert!(
        chat_js.contains("function playMessageTts")
            && function_contains(chat_js, "playMessageTts", "playTTSVoiceMode"),
        "voice-mode play/autoplay must use the voice TTS path on desktop and mobile"
    );
}

fn function_contains_near(src: &str, anchor: &str, needle: &str) -> bool {
    let Some(idx) = src.find(anchor) else {
        return false;
    };
    let start = idx.saturating_sub(200);
    let end = (idx + anchor.len() + 400).min(src.len());
    src[start..end].contains(needle)
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
