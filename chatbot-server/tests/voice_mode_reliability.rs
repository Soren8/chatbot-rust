//! Voice mode must recover without a driver reading errors or tapping again.

/// First launch after storage/permission reset: push-to-talk showed the
/// RECORD_AUDIO dialog, but voice mode called NativeMic.start() without
/// requesting and Capacitor @CapacitorPlugin never delivered
/// handleRequestPermissionsResult. One tap of voice mode must prompt and
/// continue after grant.
#[test]
fn voice_mode_requests_microphone_permission_like_push_to_talk() {
    let chat_js = include_str!("../../static/chat.js");
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );

    assert!(
        function_contains(chat_js, "ensureNativeMicPermission", "requestPermission")
            && function_contains(chat_js, "ensureNativeMicPermission", "Microphone permission denied"),
        "shared helper must call NativeMic.requestPermission and fail closed on deny"
    );
    assert!(
        function_contains(chat_js, "startVoiceMode", "ensureNativeMicPermission"),
        "tapping voice mode must request the microphone, not only NativeMic.start"
    );
    let vad_start = chat_js
        .find("NativeMicUtteranceVAD.prototype.start")
        .expect("NativeMicUtteranceVAD.prototype.start");
    let vad_start_body = &chat_js[vad_start..];
    let vad_start_end = vad_start_body.find("NativeMicUtteranceVAD.prototype.stop")
        .unwrap_or(vad_start_body.len());
    assert!(
        vad_start_body[..vad_start_end].contains("ensureNativeMicPermission"),
        "native VAD start must wait for microphone permission before NativeMic.start"
    );
    assert!(
        function_contains(chat_js, "startVoiceMode", "permissionDenied")
            && function_contains(chat_js, "startVoiceMode", "Microphone access denied"),
        "permission denial must not be retried and must be shown to the user"
    );

    assert!(
        plugin.contains("requestPermissionForAlias")
            && plugin.contains("@PermissionCallback")
            && plugin.contains("RECORD_AUDIO")
            && plugin.contains("startAfterPermission"),
        "NativeMic must use Capacitor permission callbacks; @CapacitorPlugin does not invoke handleRequestPermissionsResult"
    );
    assert!(
        !plugin.contains("handleRequestPermissionsResult")
            && !plugin.contains("ActivityCompat.requestPermissions"),
        "do not use the dead ActivityCompat + handleRequestPermissionsResult path"
    );
    assert!(
        plugin.contains("if (!hasMicPermission())")
            && plugin.contains("startAfterPermission"),
        "NativeMic.start must prompt when RECORD_AUDIO is missing, not only reject"
    );
}

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
fn native_mic_restart_stops_the_owned_recorder_before_joining() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let stop_body = java_method_body(plugin, "private void stopRecording()")
        .expect("NativeMic.stopRecording() must be declared");
    let stop_recorder = stop_body
        .find("recording.stop()")
        .expect("stop must interrupt the recorder read");
    let join_thread = stop_body
        .find("worker.join")
        .expect("stop must wait for the recording thread");
    assert!(
        stop_recorder < join_thread,
        "AudioRecord.stop() must happen before join so a blocked read cannot outlive a restart"
    );
    assert!(
        plugin.contains("final AudioRecord recording")
            && plugin.contains("recording.read(")
            && plugin.contains("audioRecord == recording"),
        "the capture worker must own one recorder instance and never read a replacement session"
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
        function_contains(chat_js, "flushVoiceContinuation", "performRegeneration")
            && function_contains(chat_js, "flushVoiceContinuation", "liveUserPairIndex"),
        "joined speech must regenerate the live pair index (server accepts index == history.len())"
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
        tts.contains("USAGE_MEDIA")
            && !native_tts_uses_voice_communication_playback(tts),
        "CallStyle microphone FGS swallows USAGE_VOICE_COMMUNICATION playback; TTS must use USAGE_MEDIA like HTML Audio"
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
        tts.contains("requestAudioFocus")
            && tts.contains("STREAM_MUSIC")
            && plugin.contains("reclaimAudioFocus")
            && plugin.contains("AUDIOFOCUS_LOSS"),
        "voice-mode TTS must reclaim media focus and unmute STREAM_MUSIC before play"
    );
    assert!(
        manifest.contains("MODIFY_AUDIO_SETTINGS"),
        "setMode/setSpeakerphoneOn require MODIFY_AUDIO_SETTINGS"
    );
}

/// Auto screen sleep still pauses the Activity / WebView. Hold
/// FLAG_KEEP_SCREEN_ON for the session (and a JS screen wake lock on HTTPS).
/// Power-button lock is a separate path: microphone foreground service.
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

/// Power-button lock backgrounds the Activity. Voice mode must keep the
/// microphone + JS loop alive with a microphone FGS, periodically re-resume
/// the WebView (Chromium freezes a hidden renderer after a few minutes), and
/// expose a lock-screen Stop that does not require unlocking (broadcast, not
/// an Activity).
#[test]
fn voice_mode_survives_screen_off_with_lock_screen_stop() {
    let session = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeForegroundSession.java"
    );
    let notification = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeNotification.java"
    );
    let service = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeForegroundService.java"
    );
    let receiver = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeStopReceiver.java"
    );
    let tests = include_str!(
        "../../android/app/src/test/java/com/chatbot/app/audio/VoiceModeForegroundSessionTest.java"
    );
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let hooks = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeNativeHooks.java"
    );
    let activity = include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
    let manifest = include_str!("../../android/app/src/main/AndroidManifest.xml");
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        manifest.contains("FOREGROUND_SERVICE_MICROPHONE")
            && manifest.contains("VoiceModeForegroundService")
            && manifest.contains("foregroundServiceType=\"microphone\"")
            && !manifest.contains("mediaPlayback")
            && manifest.contains("VoiceModeStopReceiver")
            && manifest.contains("android:exported=\"false\""),
        "manifest must declare an unexported microphone FGS and Stop receiver"
    );
    assert!(
        manifest.contains("POST_NOTIFICATIONS"),
        "Android 13+ hides FGS notices from the shade and keyguard without POST_NOTIFICATIONS"
    );
    assert!(
        !manifest.contains("mediaPlayback")
            && !service.contains("FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK")
            && !service.contains("MediaSession")
            && !notification.contains("setMediaSession"),
        "fake MediaSession is stolen into the media player and dropped on GrapheneOS/AOSP without real USAGE_MEDIA"
    );
    assert!(
        notification.contains("CallStyle")
            && notification.contains("forOngoingCall")
            && notification.contains("CATEGORY_CALL")
            && notification.contains("voice_mode_call"),
        "lock-screen bar is CallStyle hangup (Stop), not the media player"
    );
    assert!(
        plugin.contains("POST_NOTIFICATIONS")
            && plugin.contains("requestPermissionForAlias")
            && plugin.contains("TIRAMISU"),
        "enterVoiceRoute must prompt POST_NOTIFICATIONS on API 33+ before posting the FGS notice"
    );

    assert!(
        session.contains("startForeground")
            && session.contains("stopForeground")
            && plugin.contains("VoiceModeForegroundSession.get()")
            && plugin.contains("voiceForeground.enter")
            && plugin.contains("voiceForeground.exit")
            && plugin.contains("enterVoiceRoute")
            && plugin.contains("exitVoiceRoute"),
        "FGS must follow the voice-mode session, not TTS start/stop"
    );
    assert!(
        tests.contains("enterStartsForegroundOnce")
            && tests.contains("secondEnterDoesNotRestartService"),
        "unit test must lock idempotent FGS enter/exit"
    );

    assert!(
        service.contains("PARTIAL_WAKE_LOCK")
            && service.contains("startForeground")
            && service.contains("FOREGROUND_SERVICE_TYPE_MICROPHONE"),
        "FGS must hold a CPU wake lock and start as microphone type"
    );
    assert!(
        notification.contains("VISIBILITY_PUBLIC")
            && notification.contains("setOngoing(true)")
            && notification.contains("ACTION_STOP")
            && notification.contains("IMPORTANCE_HIGH")
            && notification.contains("voice_mode_call")
            && notification.contains("getBroadcast")
            && !notification.contains("getActivity"),
        "lock-screen Stop must be a public HIGH ongoing notice with a broadcast action"
    );
    assert!(
        receiver.contains("requestStop") || receiver.contains("stopFromNotification"),
        "Stop receiver must tear down voice mode without unlocking"
    );
    assert!(
        plugin.contains("stopFromNotification")
            && plugin.contains("voiceModeStopRequested")
            && plugin.contains("stopVoiceMode"),
        "notification Stop must ask JS to stopVoiceMode and tear down native audio"
    );
    assert!(
        plugin.contains("recordingGeneration")
            && plugin.contains("generation != recordingGeneration.get()"),
        "queued native PCM from before notification Stop must be discarded"
    );
    assert!(
        chat_js.contains("!self.isRecording || !window.voiceModeActive")
            && chat_js.contains("voiceModeSessionGeneration"),
        "queued PCM and in-flight STT must not create input after notification Stop"
    );

    assert!(
        activity.contains("keepVoiceWebViewRunning")
            && activity.contains("resumeTimers")
            && activity.contains("RENDERER_PRIORITY_IMPORTANT")
            && activity.contains("onPause")
            && activity.contains("VoiceModeForegroundSession.get().isActive()"),
        "screen-off must keep the WebView JS loop running while the FGS is held"
    );
    assert!(
        activity.contains("dispatchWindowVisibilityChanged")
            && activity.contains("View.VISIBLE"),
        "voice mode must disable hidden-WebView throttling after the Activity backgrounds"
    );
    assert!(
        activity.contains("CapConfig.loadDefault")
            && activity.contains("setUseLegacyBridge(true)"),
        "Capacitor must use its legacy bridge because Vanadium throttles WebMessage callbacks in background"
    );
    let pause_body = java_method_body(activity, "public void onPause()")
        .expect("MainActivity.onPause() must be declared");
    let super_pause = pause_body
        .find("super.onPause()")
        .expect("onPause must preserve the normal Activity lifecycle");
    let keep_after_pause = pause_body
        .find("keepVoiceWebViewRunning()")
        .expect("onPause must refresh the active voice-mode WebView");
    assert!(
        super_pause < keep_after_pause,
        "voice mode must preserve BridgeActivity.onPause lifecycle ordering"
    );
    assert!(
        service.contains("postDelayed")
            && service.contains("keepWebViewAlive")
            && hooks.contains("keepWebViewAlive")
            && plugin.contains("setKeepAliveHandler")
            && (activity.contains("getBridge().eval") || plugin.contains("getBridge().eval")),
        "FGS must periodically re-resume the WebView; one-shot onPause freezes after a few minutes"
    );
    assert!(
        manifest.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")
            && plugin.contains("isIgnoringBatteryOptimizations")
            && plugin.contains("ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"),
        "GrapheneOS/AOSP Doze still sleeps Optimized apps after a couple of minutes; prompt Unrestricted"
    );
    assert!(
        service.contains("requestNetwork")
            && service.contains("NET_CAPABILITY_INTERNET")
            && activity.contains("webView.onResume()")
            && activity.contains("webView.resumeTimers()")
            && !activity.contains("getBridge().onResume()")
            && !activity.contains("fireStatusChange(true)"),
        "hold a network request and resume only the WebView without re-entering Capacitor lifecycle"
    );

    assert!(
        chat_js.contains("window.stopVoiceMode")
            && chat_js.contains("voiceModeStopRequested")
            && function_contains(chat_js, "stopVoiceMode", "exitVoiceRoute"),
        "JS must expose stopVoiceMode and honor the native lock-screen Stop event"
    );
    assert!(
        !function_contains(chat_js, "stopVoicePlaybackOnly", "exitVoiceRoute"),
        "barge-in must not drop the screen-off FGS"
    );
}

/// An answered GSM/IMS call takes MODE_IN_CALL. Voice mode must yield the
/// mic, TTS, and communication route for the call, then resume after.
#[test]
fn voice_mode_pauses_during_phone_call() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        plugin.contains("MODE_IN_CALL")
            && plugin.contains("pauseForPhoneCall")
            && plugin.contains("resumeAfterPhoneCall")
            && plugin.contains("addOnModeChangedListener"),
        "native must watch MODE_IN_CALL and yield the voice-mode session"
    );
    assert!(
        plugin.contains("NativeVoiceTtsPlugin.stopIfPresent")
            && plugin.contains("stopRecording")
            && plugin.contains("voiceAudioRoute.exit"),
        "a phone call must stop TTS, release the mic, and drop MODE_IN_COMMUNICATION"
    );
    assert!(
        chat_js.contains("pauseVoiceModeForPhoneCall")
            && chat_js.contains("resumeVoiceModeAfterPhoneCall")
            && function_contains(chat_js, "pauseVoiceModeForPhoneCall", "stopAllTtsPlayback")
            && !function_contains(chat_js, "pauseVoiceModeForPhoneCall", "persistVoiceModeWanted(false)")
            && function_contains(chat_js, "resumeVoiceModeAfterPhoneCall", "startVoiceMode"),
        "JS must pause the VAD loop without turning voice mode off, then restart after the call"
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

/// A pin queued by one stream chunk must not undo a later upward user scroll.
/// Voice mode follows the same rule as ordinary chat scrolling.
#[test]
fn sticky_scrollback_yields_to_upward_user_scroll() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        function_contains(chat_js, "scrollToBottom", "chatScrollGeneration")
            && function_contains(chat_js, "scrollToBottom", "generation !== chatScrollGeneration"),
        "deferred bottom pins must be cancelled by a later user scroll"
    );
    assert!(
        chat_js.contains("this.scrollTop < lastChatScrollTop"),
        "the chat scroll handler must record upward user scrolls"
    );
    assert!(
        function_contains(chat_js, "shouldStickChatToBottom", "return isAtBottom()")
            && !function_contains(chat_js, "shouldStickChatToBottom", "window.voiceModeActive) return true"),
        "voice mode must respect the same sticky scrollback state"
    );
}

/// Record from speech-like start (Silero onSpeechStart). Stop TTS only when
/// real speech is confirmed (onSpeechRealStart / REAL_SPEECH_MS), immediately
/// at that point — not on cough/"hey", not when the utterance ends.
/// SPEECH_MIN_ACTIVE_MS is only for sending to STT. Desktop Silero is unchanged.
#[test]
fn native_tts_barge_in_on_initial_speech() {
    let chat_js = include_str!("../../static/chat.js");
    let native_audio = include_str!("../../static/native-audio.js");

    assert!(
        !chat_js.contains("BARGE_IN_CONFIRM_MS") && !native_audio.contains("BARGE_IN_CONFIRM_MS"),
        "use REAL_SPEECH_MS (Silero minSpeechMs analog), not BARGE_IN_CONFIRM_MS"
    );
    assert!(
        !chat_js.contains("BARGE_IN_RMS_THRESHOLD") && !chat_js.contains("BARGE_IN_RMS_FRAMES"),
        "TTS barge-in must not trip on a short RMS energy burst"
    );
    assert!(
        native_audio.contains("function pcm16IsSpeechLike")
            && native_audio.contains("function pcm16IsVoicedSpeech")
            && native_audio.contains("function pcm16RealSpeechDetected")
            && native_audio.contains("REAL_SPEECH_MS")
            && native_audio.contains("SPEECH_PERIODICITY_MIN"),
        "native VAD must separate recording-start from real-speech barge-in"
    );
    assert!(
        function_contains(chat_js, "_maybeStartUtterance", "pcm16IsSpeechLike")
            && !function_contains(chat_js, "_maybeStartUtterance", "pcm16IsVoicedSpeech")
            && !function_contains(chat_js, "_maybeStartUtterance", "pcm16RealSpeechDetected"),
        "recording start is speech-like only (coughs may record; they must not barge in)"
    );
    assert!(
        !function_contains(chat_js, "_beginUtterance", "handleBargeIn"),
        "do not barge in at utterance start (that is onSpeechStart / cough-prone)"
    );
    assert!(
        function_contains(chat_js, "_maybeBargeIn", "handleBargeIn")
            && function_contains(chat_js, "_maybeBargeIn", "pcm16RealSpeechDetected")
            && function_contains(chat_js, "_accumulateUtterance", "_maybeBargeIn")
            && function_contains(chat_js, "_beginUtterance", "_maybeBargeIn"),
        "barge-in at real-speech confirm, checked as audio accumulates, not at end-of-speech"
    );
    assert!(
        !function_contains(chat_js, "_endUtterance", "handleBargeIn"),
        "do not wait for the utterance to finish before stopping TTS"
    );
    let real_ms = parse_js_int_const(native_audio, "REAL_SPEECH_MS")
        .expect("REAL_SPEECH_MS must be declared in native-audio.js");
    assert!(
        (500..=700).contains(&real_ms),
        "REAL_SPEECH_MS={real_ms} should be ~1.5× desktop minSpeechMs (400)"
    );
    assert!(
        chat_js.contains("minSpeechMs: 400") || chat_js.contains("minSpeechMs:400"),
        "desktop Silero minSpeechMs stays 400; native duration is the looser energy gate"
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
    let dual = include_str!("native_vad_speech_like.rs");
    assert!(
        dual.contains("fn cough_and_hey_do_not_barge_in_sustained_noisy_speech_does"),
        "keep the paired cough+speech barge-in test; one-sided tests caused the VAD oscillation"
    );
}

/// Short mid-sentence pauses must not end the utterance (that forces a lossy
/// STT split + join). Leading audio of the next fragment must still be kept.
#[test]
fn native_vad_keeps_leading_audio_and_longer_end_silence() {
    let chat_js = include_str!("../../static/chat.js");
    let native_audio = include_str!("../../static/native-audio.js");

    let end_ms = parse_js_int_const(native_audio, "SPEECH_END_SILENCE_MS")
        .expect("SPEECH_END_SILENCE_MS must be declared in native-audio.js");
    assert!(
        (1200..=1800).contains(&end_ms),
        "SPEECH_END_SILENCE_MS={end_ms} should ignore short pauses (~1.2–1.8s)"
    );
    assert!(
        chat_js.contains("redemptionMs: 1500") || chat_js.contains("redemptionMs:1500"),
        "desktop Silero end-silence must match the native hangover"
    );

    let preroll = parse_js_int_const(native_audio, "SPEECH_PREROLL_SAMPLES")
        .expect("SPEECH_PREROLL_SAMPLES must be declared in native-audio.js");
    assert!(
        preroll >= 4800,
        "SPEECH_PREROLL_SAMPLES={preroll} must cover ~300ms so unvoiced onsets reach STT"
    );

    assert!(
        function_contains(chat_js, "_maybeStartUtterance", "startGateChunks")
            && function_contains(chat_js, "_beginUtterance", "startChunks"),
        "speech-like start-gate frames must be kept for the utterance"
    );
    assert!(
        function_contains(chat_js, "_beginUtterance", "startChunks")
            && !chat_js.contains("utterance begin (during TTS, no pre-roll)"),
        "TTS barge-in must keep start-gate audio, not start the utterance empty"
    );
    assert!(
        !function_contains(chat_js, "_maybeStartUtterance", "vadSttInProgress")
            && !function_contains(chat_js, "_beginUtterance", "vadSttInProgress"),
        "STT in flight must not drop the start of the next utterance"
    );
    assert!(
        function_contains(chat_js, "handleSpeechEnd", "hasCompletedSpeechCapture"),
        "do not send an in-progress follow-up utterance to STT"
    );
}

/// Android voice-mode TTS must use the native AudioTrack path. HTML Audio is
/// tied to the hidden WebView and stops when Android backgrounds the Activity.
/// Desktop voice mode continues to use the shared playTTS path.
#[test]
fn android_voice_mode_tts_uses_native_playback_and_desktop_keeps_html_audio() {
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        function_contains(chat_js, "playTTSVoiceMode", "nativeVoiceTtsAvailable")
            && function_contains(chat_js, "playTTSVoiceMode", "playNativeVoiceModeTts")
            && function_contains(chat_js, "playTTSVoiceMode", "playTTS"),
        "Android voice mode must select native playback and retain the desktop fallback"
    );
    assert!(
        function_contains(chat_js, "playNativeVoiceModeTts", "NativeVoiceTts.beginSession")
            && function_contains(chat_js, "playNativeVoiceModeTts", "NativeVoiceTts.enqueue")
            && function_contains(chat_js, "playNativeVoiceModeTts", "markEndOfQueue"),
        "native voice mode must keep one ordered native session for all sentences"
    );
    assert!(
        function_contains(
            chat_js,
            "playNativeVoiceModeTts",
            "nativeVoiceTtsStopPromise"
        ),
        "a new native TTS session must await teardown of the previous worker"
    );
    assert!(
        function_contains(chat_js, "playTTS", "playMessageBodyTts")
            && function_contains(chat_js, "playOneTtsUtterance", "getDesktopTtsAudio"),
        "desktop playTTS must remain on the shared HTMLAudioElement"
    );
    assert!(
        function_contains(chat_js, "playNativeVoiceModeTts", "fetchVoiceRetry")
            && function_contains(chat_js, "playNativeVoiceModeTts", "console.error"),
        "a failed native sentence fetch must be logged and let later sentences continue"
    );
    assert!(
        !function_contains(chat_js, "playTTSVoiceMode", "primeDesktopTtsAudioFromGesture"),
        "Android voice mode must not depend on HTML autoplay priming"
    );
}

/// Native TTS streams PCM, but reliability comes first on spotty links:
/// preroll before the first sample, retry a failed GET, and do not kill
/// the whole session when one sentence drops.
#[test]
fn native_voice_tts_streams_wav_instead_of_buffering_the_clip() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    assert!(
        tts.contains("streamWavToTrack")
            && tts.contains("getInputStream")
            && tts.contains("writePcmBlocking")
            && tts.contains("PREROLL_MS")
            && tts.contains("playUrlToTrackOnce")
            && tts.contains("playbackGeneration")
            && tts.contains("isGenerationActive")
            && tts.contains("hasIncompleteData"),
        "native TTS must stream with a preroll jitter buffer and reject stale/truncated clips"
    );
    assert!(
        !tts.contains("downloadUrl")
            && !tts.contains("readAllBytes")
            && !tts.contains("downloaded fully")
            && !tts.contains("playing what we have"),
        "do not buffer the whole WAV before AudioTrack write"
    );
}

#[test]
fn voice_http_retries_stt_and_tts_on_spotty_links() {
    let chat_js = include_str!("../../static/chat.js");
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    assert!(
        chat_js.contains("function fetchVoiceRetry")
            && function_contains(chat_js, "handleSpeechEnd", "fetchVoiceRetry")
            && function_contains(chat_js, "playOneTtsUtterance", "fetchVoiceRetry"),
        "STT and TTS fetches must retry transient failures on desktop and mobile"
    );
    assert!(
        tts.contains("playUrlToTrackOnce")
            && !function_contains_approx_worker_kills_session(tts),
        "one dropped TTS clip must not abort the rest of the queue"
    );
    assert!(
        tts.contains("activeConnection") && tts.contains("activeConnection.disconnect()"),
        "stopping voice mode must interrupt an in-flight native TTS HTTP read"
    );
    assert!(
        chat_js.contains("voiceTtsAbortController")
            && function_contains(chat_js, "playNativeVoiceModeTts", "signal: ttsSignal"),
        "stopping native TTS must abort an in-flight token request instead of leaking a token"
    );
}

fn function_contains_approx_worker_kills_session(tts: &str) -> bool {
    function_contains(tts, "workerLoop", "stopPlaybackInternal(false)")
        && function_contains(tts, "workerLoop", "notifyError")
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
    assert!(
        function_contains(chat_js, "playMessageTts", "playTTSVoiceMode(button, options)"),
        "voice-mode play must forward sentence options; dropping them plays the whole response"
    );
    assert!(
        function_contains(chat_js, "playTTSVoiceMode", "playTTS")
            && function_contains(chat_js, "playTTS", "options.sentences"),
        "voice-mode TTS must honor a clicked sentence list via playTTS"
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

fn java_method_body<'a>(src: &'a str, signature: &str) -> Option<&'a str> {
    let start = src.find(signature)?;
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

fn native_tts_uses_voice_communication_playback(tts: &str) -> bool {
    tts.contains("setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)")
}
