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
fn native_vad_stop_does_not_stop_a_newer_bridge() {
    let chat_js = include_str!("../../static/chat.js");
    let stop_start = chat_js
        .find("NativeMicUtteranceVAD.prototype.stop")
        .expect("NativeMicUtteranceVAD.stop must be declared");
    let stop_body = &chat_js[stop_start..];
    let stop_end = stop_body
        .find("NativeMicUtteranceVAD.prototype.reinitialize")
        .unwrap_or(stop_body.len());
    let stop_body = &stop_body[..stop_end];
    let owner_check = stop_body
        .find("nativeMicBridge === this")
        .expect("native VAD stop must check bridge ownership");
    let native_stop = stop_body
        .find("window.NativeMic.stop()")
        .expect("native VAD stop must stop the recorder");
    assert!(
        owner_check < native_stop,
        "a stale bridge must not stop the recorder owned by a newer bridge"
    );
    assert!(
        stop_body.contains("nativeMicStopPromise")
            && stop_body.contains("nativeMicStopPromise === stopPromise"),
        "a replacement bridge must wait for an in-flight native stop to finish"
    );
}

#[test]
fn voice_mode_survives_capacitor_reload_without_a_second_tap() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        chat_js.contains("persistVoiceModeWanted") && chat_js.contains("voiceModeWanted"),
        "voice mode on/off must persist across location.reload() (Capacitor reload-ui)"
    );
    assert!(
        chat_js.contains("voice_mode") && chat_js.contains("/update_preferences"),
        "voice mode persistence must be server-side (per-account), consistent with web search"
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

/// Voice-mode STT uploads must stay at or under 500 kbps on the wire,
/// compressed or not: the AAC leg is clamped to STT_WIRE_BITRATE_CAP_BPS and
/// the WAV fallback is NATIVE_MIC_SAMPLE_RATE * 16-bit mono. A quality bump
/// that breaks the budget would stall uploads on spotty links.
#[test]
fn stt_upload_wire_bitrate_stays_at_or_under_500kbps() {
    let native_audio = include_str!("../../static/native-audio.js");
    let cap = parse_js_int_const(native_audio, "STT_WIRE_BITRATE_CAP_BPS")
        .expect("STT_WIRE_BITRATE_CAP_BPS must be declared in native-audio.js");
    assert!(
        cap <= 500_000,
        "STT_WIRE_BITRATE_CAP_BPS={cap} exceeds the 500 kbps voice-mode budget"
    );
    let aac = parse_js_int_const(native_audio, "STT_AAC_BITRATE_BPS")
        .expect("STT_AAC_BITRATE_BPS must be declared in native-audio.js");
    assert!(
        aac <= cap,
        "STT_AAC_BITRATE_BPS={aac} exceeds the declared wire cap {cap}"
    );
    assert!(
        function_contains(
            native_audio,
            "encodeAudioForStt",
            "Math.min(STT_AAC_BITRATE_BPS, STT_WIRE_BITRATE_CAP_BPS)"
        ),
        "encodeAudioForStt must clamp the AAC bitrate to the wire cap"
    );
    let rate = parse_js_int_const(native_audio, "NATIVE_MIC_SAMPLE_RATE")
        .expect("NATIVE_MIC_SAMPLE_RATE must be declared in native-audio.js");
    assert!(
        rate * 16 <= cap,
        "WAV fallback at {rate} Hz mono 16-bit is over the {cap} bps wire cap"
    );
}

/// STT upload failures must be visible in the chat, not a silent green
/// button: over a slow link the multipart upload can stall and fail while
/// voice mode looks alive. User-initiated stops abort the same fetch and
/// must stay silent.
#[test]
fn stt_upload_failure_is_visible_unless_user_stopped() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        function_contains(chat_js, "handleSpeechEnd", "appendMessage")
            && function_contains(chat_js, "handleSpeechEnd", "Voice input failed"),
        "handleSpeechEnd must surface STT failures in the chat"
    );
    assert!(
        function_contains(chat_js, "handleSpeechEnd", "sttSignal.aborted"),
        "user-initiated stops abort the upload and must not report a failure"
    );
}

/// STT codec engagement must be visible server-side: field logs showed WAV
/// uploads with no explanation because sttCodecLog only reached console and
/// logcat. The fallback reason (or AAC success) must ride reportVoice.
#[test]
fn stt_codec_reason_reaches_server_logs() {
    let chat_js = include_str!("../../static/chat.js");
    let native_audio = include_str!("../../static/native-audio.js");
    assert!(
        chat_js.contains("window.reportVoice = reportVoice"),
        "chat.js must expose reportVoice for the earlier-loaded native-audio.js"
    );
    assert!(
        function_contains(native_audio, "sttCodecLog", "globalThis.reportVoice"),
        "sttCodecLog must forward codec decisions to the server via reportVoice"
    );
}

/// The device — not our assumptions — decides the STT codec: AAC encoding
/// rides the hardware MediaCodec path and varies by device/WebView (stock
/// Chrome vs GrapheneOS Vanadium diverge here), while opus is Chromium's
/// built-in software encoder. The client must probe candidates at runtime,
/// log the full support matrix to the server, and use the first encoder the
/// device accepts; opus packets need an Ogg container for ffmpeg.
#[test]
fn stt_encoder_probe_uses_first_device_supported_codec() {
    let native_audio = include_str!("../../static/native-audio.js");
    assert!(
        native_audio.contains("mp4a.40.2") && native_audio.contains("codec: 'opus'"),
        "STT encoder candidates must include both AAC and opus"
    );
    assert!(
        function_contains(native_audio, "encodeAudioForStt", "probeSttEncoders"),
        "encodeAudioForStt must probe device encoder support instead of assuming AAC"
    );
    // The probe reports the per-device matrix via sttCodecLog (console +
    // logcat + server); asserted structurally below, not by log text.
    let cap = parse_js_int_const(native_audio, "STT_WIRE_BITRATE_CAP_BPS")
        .expect("STT_WIRE_BITRATE_CAP_BPS must be declared in native-audio.js");
    let opus = parse_js_int_const(native_audio, "STT_OPUS_BITRATE_BPS")
        .expect("STT_OPUS_BITRATE_BPS must be declared in native-audio.js");
    assert!(
        opus <= cap,
        "STT_OPUS_BITRATE_BPS={opus} exceeds the declared wire cap {cap}"
    );
    assert!(
        function_contains(
            native_audio,
            "encodeAudioForStt",
            "Math.min(STT_OPUS_BITRATE_BPS, STT_WIRE_BITRATE_CAP_BPS)"
        ),
        "encodeAudioForStt must clamp the opus bitrate to the wire cap"
    );
    assert!(
        native_audio.contains("OpusHead") && native_audio.contains("OggS"),
        "opus packets must be muxed into an Ogg container the server can demux"
    );
    assert!(
        native_audio.contains("recording.opus"),
        "the opus leg must upload under its own filename so the server marks it compressed"
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

#[test]
fn native_tts_checks_liveness_before_starting_a_replaced_session() {
    let chat_js = include_str!("../../static/chat.js");
    let ensure_session = function_body(chat_js, "ensureSession")
        .expect("native TTS ensureSession must be declared");
    let liveness_check = ensure_session
        .find("if (!live()) return null;")
        .expect("native TTS startup must stop when its generation is stale");
    let begin_session = ensure_session
        .find("NativeVoiceTts.beginSession")
        .expect("native TTS must begin a native session");
    assert!(
        liveness_check < begin_session,
        "a stale promise must not call beginSession after playback was stopped"
    );
}

#[test]
fn voice_mode_retry_honors_an_explicit_stop() {
    let chat_js = include_str!("../../static/chat.js");
    let start_body = function_body(chat_js, "startVoiceMode")
        .expect("startVoiceMode must be declared");
    let retry_timer = start_body
        .find("setTimeout(function () {")
        .expect("failed voice-mode starts must schedule a retry");
    let retry_body = &start_body[retry_timer..];
    let generation_check = retry_body
        .find("sessionGeneration !== voiceModeSessionGeneration")
        .expect("retry must check the current voice-mode generation");
    let retry_start = retry_body
        .find("startVoiceMode(attempt + 1)")
        .expect("retry must start voice mode again");
    assert!(
        generation_check < retry_start,
        "an explicit stop must invalidate a delayed voice-mode retry"
    );
    assert!(
        retry_body[..retry_start].contains("!voiceModeWanted()"),
        "retry must not restore voice mode after the user turns it off"
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

/// /tts_stream serves Ogg-Opus by default; the native AudioTrack sink takes
/// raw PCM, so the plugin must sniff the content type and decode Opus clips
/// through the streaming decoder (same truncate-rejects-clip contract as WAV).
#[test]
fn native_voice_tts_decodes_opus_clips() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let opus = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/OggOpusStreamDecoder.java"
    );
    assert!(
        tts.contains("streamOpusToClip") && tts.contains("getContentType"),
        "opus clips must be routed to the opus decoder by content type"
    );
    assert!(
        tts.contains("sawOpusHead") && tts.contains("hasIncompleteData"),
        "truncated opus clips must be rejected like truncated WAV clips"
    );
    assert!(
        opus.contains("concentus")
            && opus.contains("OggS")
            && opus.contains("OpusHead")
            && opus.contains("takePcm"),
        "the opus decoder must demux Ogg, decode via concentus, and stream PCM"
    );
    assert!(
        opus.contains("io.github.jaredmdobson.concentus"),
        "the decoder must import the published concentus package matching \
         the io.github.jaredmdobson:concentus Gradle coordinates (org.concentus \
         does not exist in that artifact and breaks the Android build)"
    );
}

/// Desktop `playTTS` is invoked from the ready block but is itself top-level,
/// and it aborts the in-flight Voice Mode STT upload for barge-in. That
/// controller and the barge-in counter must be top-level bindings: a `let`
/// inside the ready closure is invisible to `playTTS`, which threw
/// ReferenceError before every desktop voice-mode play and made TTS silent.
#[test]
fn desktop_play_tts_shared_voice_state_is_top_level() {
    let chat_js = include_str!("../../static/chat.js");
    let ready_at = chat_js
        .find("$(document).ready(function()")
        .expect("chat.js must keep the main ready block");
    let (top_level, _ready_block) = chat_js.split_at(ready_at);
    for name in ["voiceSttAbortController", "bargeInFrames"] {
        let decl_prefix = format!("let {name} ");
        let indented_prefix = format!("  let {name} ");
        assert!(
            top_level.lines().any(|line| line.starts_with(&decl_prefix)),
            "{name} must be declared at top level so top-level playTTS can read it"
        );
        assert!(
            !chat_js.lines().any(|line| line.starts_with(&indented_prefix)),
            "{name} must not be redeclared inside the ready block (ReferenceError in playTTS)"
        );
    }
    assert!(
        function_contains(chat_js, "playTTS", "voiceSttAbortController")
            && function_contains(chat_js, "playTTS", "bargeInFrames"),
        "playTTS must keep aborting in-flight STT and resetting barge-in state"
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
            && function_contains(chat_js, "handleSpeechEnd", "postVoiceSttXhr")
            && function_contains(chat_js, "playOneTtsUtterance", "fetchVoiceRetry"),
        "STT uploads must use the progress-reporting XHR helper (uplink metrics) and TTS fetches must retry transient failures on desktop and mobile"
    );
    let stt_post =
        function_body(chat_js, "postVoiceSttXhr").expect("postVoiceSttXhr must be declared");
    assert!(
        stt_post.contains("xhr.upload.onprogress") && stt_post.contains("upMs"),
        "the STT XHR helper must time the true uplink from progress events"
    );
    assert!(
        stt_post.contains("xhr.timeout = 60000")
            && stt_post.contains("isRetryableVoiceStatus")
            && stt_post.contains("Session expired")
            && stt_post.contains("AbortError"),
        "the STT XHR helper must preserve the retry contract: 60s stall timeout, retried server errors, re-login on 401, abort passthrough on user stop"
    );
    assert!(
        function_contains(chat_js, "handleSpeechEnd", "STT net:"),
        "each STT upload must log its measured uplink bytes/ms/kbps"
    );
    assert!(
        tts.contains("playUrlToTrackOnce")
            && !function_contains_approx_worker_kills_session(tts),
        "one dropped TTS clip must not abort the rest of the queue"
    );
    assert!(
        tts.contains("activeConnection")
            && tts.contains("connectionLock")
            && tts.contains("connection.disconnect()"),
        "stopping voice mode must interrupt an in-flight native TTS HTTP read"
    );
    assert!(
        chat_js.contains("voiceTtsAbortController")
            && function_contains(chat_js, "playNativeVoiceModeTts", "signal: ttsSignal"),
        "stopping native TTS must abort an in-flight token request instead of leaking a token"
    );
    assert!(
        chat_js.contains("function cancelNativeTtsToken")
            && function_contains(chat_js, "playNativeVoiceModeTts", "cancelNativeTtsToken"),
        "a token returned just before stop must be explicitly released"
    );
    assert!(
        function_contains(chat_js, "playNativeVoiceModeTts", "X-TTS-Token")
            && function_contains(chat_js, "playNativeVoiceModeTts", "responseToken"),
        "native TTS must cancel a token even if abort prevents JSON body parsing"
    );
    let native_tts_start = java_method_body(tts, "private AudioClip playUrlToTrackOnce(")
        .expect("NativeVoiceTts.playUrlToTrackOnce must be declared");
    let active_connection = native_tts_start
        .find("activeConnections.add(conn)")
        .expect("native TTS must publish its active connection");
    let generation_check = native_tts_start[active_connection..]
        .find("if (!isGenerationActive(generation))")
        .map(|offset| active_connection + offset)
        .expect("native TTS must re-check generation after publishing the connection");
    let response_code = native_tts_start
        .find("conn.getResponseCode()")
        .expect("native TTS must open the HTTP response");
    assert!(
        active_connection < generation_check && generation_check < response_code,
        "stop must be able to cancel a connection created just before a session replacement"
    );
}

/// A spotty link must not turn sentences into silent gaps. The sentence pump
/// used to requeue only HTTP 429; a failed token fetch (network error, stall
/// timeout, 5xx) dropped the sentence for good and later sentences kept
/// playing — the reported "TTS sentences kept getting skipped".
#[test]
fn native_voice_tts_requeues_sentences_on_transient_failures() {
    let chat_js = include_str!("../../static/chat.js");
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    let pump = function_body(native_tts, "requestToken")
        .expect("native TTS must retry each token without blocking other token requests");

    assert!(
        pump.contains("isRetryableVoiceStatus"),
        "the native sentence pump must reuse the shared retryable-status helper"
    );
    assert!(
        !pump.contains("\\(429\\)"),
        "requeue must not be 429-only; network errors and 5xx must also requeue the sentence"
    );
    let retries = parse_js_int_const(chat_js, "MAX_TTS_SENTENCE_RETRIES")
        .expect("MAX_TTS_SENTENCE_RETRIES must be declared in chat.js");
    assert!(
        (2..=5).contains(&retries),
        "sentence requeue must be bounded (MAX_TTS_SENTENCE_RETRIES={retries}) so a dead link cannot churn forever"
    );
    assert!(
        pump.contains("await sleepMs"),
        "a retried sentence must wait out its backoff"
    );
    assert!(
        pump.contains("Session expired"),
        "a 401 redirect must not be requeued"
    );
}

/// The desktop HTML-audio sentence pump used to treat any sentence failure as
/// session-fatal (`stopCurrentDesktopTts`), so one dropped clip GET, failed
/// token fetch, or late `play()` rejection ended speech at the last good
/// sentence — the reported "desktop TTS stops after the first sentence".
/// The native pump already requeues transient failures; the desktop pump must
/// do the same (bounded), plus a bounded same-token clip retry (the server
/// retains a generated WAV for MAX_TTS_REPLAYS replays and re-arms a failed
/// generation), while an autoplay-blocked play() stays fatal.
#[test]
fn desktop_tts_requeues_sentences_on_transient_failures() {
    let chat_js = include_str!("../../static/chat.js");
    let body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    let pump_start = body
        .find("function pump(")
        .expect("playMessageBodyTts must contain a sentence pump");
    let pump = &body[pump_start..];

    assert!(
        !pump.contains("stopCurrentDesktopTts"),
        "a transient sentence failure must not kill the whole desktop session"
    );
    assert!(
        pump.contains("queue.unshift("),
        "a failed desktop sentence must be requeued, not dropped"
    );
    assert!(
        pump.contains("MAX_TTS_SENTENCE_RETRIES"),
        "desktop sentence requeue must be bounded like the native pump"
    );
    assert!(
        pump.contains("retryScheduled"),
        "a requeued desktop sentence must wait out its backoff; stream callbacks must not re-post it immediately"
    );

    let utterance = function_body(chat_js, "playOneTtsUtterance")
        .expect("playOneTtsUtterance must be declared");
    assert!(
        utterance.contains("MAX_TTS_CLIP_ATTEMPTS"),
        "a failed clip GET must retry the same token before failing the sentence"
    );
    assert!(
        utterance.contains("NotAllowedError"),
        "an autoplay-blocked play() must stay fatal; only transport failures may retry"
    );
    let attempts = parse_js_int_const(chat_js, "MAX_TTS_CLIP_ATTEMPTS")
        .expect("MAX_TTS_CLIP_ATTEMPTS must be declared in chat.js");
    assert!(
        (2..=3).contains(&attempts),
        "clip GET retries must be bounded (MAX_TTS_CLIP_ATTEMPTS={attempts}) within the server replay budget"
    );
    assert!(
        chat_js.contains("TTS_CLIP_RETRY_BACKOFF_MS"),
        "clip GET retries must back off so a brief blip does not exhaust the budget"
    );
}

/// Discovery must survive sanitize shrink of already-consumed text. A markdown
/// emphasis/inline-code pair that opens before a sentence boundary and closes
/// later (e.g. "**Key point. More detail.**") leaves literal markers while
/// streaming; the boundary sentence is enqueued including them, then the pair
/// completes and sanitizeForTTS strips the markers, shifting every later
/// sentence left of the recorded offset. The desktop discoverAbsolute used to
/// skip any sentence whose start drifted below the consumed offset
/// (`s.start < consumedLen`) — the sentence holding the closer, often the last
/// one, was never enqueued (the reported "sometimes the last TTS sentence
/// still doesn't play", desktop-only: the native pump tracks a consumed
/// prefix length and cannot skip). Discovery must be end-based: enqueue
/// anything with `s.end > consumedLen`; ends only ever move left when sanitize
/// shrinks completed text, so the end guard alone prevents replaying a
/// sentence.
#[test]
fn desktop_tts_discovery_survives_sanitize_shrink_of_consumed_prefix() {
    let chat_js = include_str!("../../static/chat.js");
    let body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    let discover_start = body
        .find("function discoverAbsolute(")
        .expect("playMessageBodyTts must contain discoverAbsolute");
    let discover = function_body(&body[discover_start..], "discoverAbsolute")
        .expect("discoverAbsolute must be a complete function");

    assert!(
        !discover.contains("s.start < consumedLen"),
        "discoverAbsolute must not skip a sentence whose start drifted below the consumed offset; that permanently drops the last sentence when a markdown pair closes after the boundary was consumed; got: {discover}"
    );
    assert!(
        discover.contains("s.end <= consumedLen"),
        "discovery must stay replay-guarded by the consumed end boundary; got: {discover}"
    );
    assert!(
        discover.contains("consumedLen = s.end"),
        "discovery must still advance the consumed boundary on enqueue so nothing replays; got: {discover}"
    );
}

/// fetchVoiceRetry's own 60s stall timeout and a user stop both surface as
/// AbortError. A stalled spotty-link request must retry; a user stop must not.
#[test]
fn voice_http_retry_retries_stalled_requests_not_user_aborts() {
    let chat_js = include_str!("../../static/chat.js");
    let retry =
        function_body(chat_js, "fetchVoiceRetry").expect("fetchVoiceRetry must be declared");
    assert!(
        retry.contains("userAborted"),
        "the retry loop must distinguish its own stall timeout from a user abort"
    );
    assert!(
        retry.contains("err.name === 'AbortError' && userAborted"),
        "only a user abort may rethrow AbortError without retrying"
    );
    assert!(
        !retry.contains("(err.name === 'AbortError' || err.message === 'Session expired')"),
        "the old catch conflated the stall timeout with a user stop and never retried stalls"
    );
}

/// The native worker retries a failed clip GET, but back-to-back retries on a
/// blipping link (cell handoff, tunnel reconnect) all die together and the
/// sentence is lost while later clips keep playing.
#[test]
fn native_tts_clip_retries_wait_out_the_blip() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let body = java_method_body(tts, "private AudioClip playUrlToTrack(String urlStr")
        .expect("playUrlToTrack must be declared");
    assert!(
        body.contains("CLIP_RETRY_BACKOFF_MS"),
        "clip GET retries must back off so a brief connectivity blip does not exhaust all attempts"
    );
    let sleep = body.find("Thread.sleep").expect("backoff must actually sleep");
    assert!(
        body[sleep..].contains("isGenerationActive"),
        "a stop during backoff must abort the retry immediately"
    );
}

/// A fresh native session begins with a teardown stop(); that stop used to
/// emit playbackState 'ended' unconditionally. The event dispatch is async, so
/// after a cold app start (kill + clear storage + relaunch) it landed on the
/// NEW session's listener and finishNativeVoiceTts killed the session at
/// birth — TTS stayed silent until the next message.
#[test]
fn native_tts_stop_does_not_emit_ended_without_an_active_session() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let stop = java_method_body(tts, "private void stopPlaybackInternal(")
        .expect("stopPlaybackInternal must be declared");
    let was_active = stop
        .find("boolean wasActive = sessionActive.getAndSet(false)")
        .expect("stop must capture whether a session was actually active");
    let notify = stop
        .find("notifySessionEnded()")
        .expect("stop must keep the ended notification for real sessions");
    assert!(
        stop[..notify].contains("notifyStopped && wasActive"),
        "an idle stop must not emit 'ended'; the stale event kills the session begun right after it"
    );
    assert!(
        was_active < notify,
        "active state must be captured before teardown"
    );
    assert!(
        tts.contains("sessionActive.set(true)"),
        "beginSession/play must still mark the session active"
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

/// The screen-off microphone foreground service and file logger must be
/// robust against process kills, missing permissions, and uninitialized states.
/// Specifically:
/// 1. ConnectivityManager.requestNetwork requires CHANGE_NETWORK_STATE;
/// 2. FileLogger must not throw NullPointerException when logFile is null;
/// 3. FileLogger must catch Throwable on disk writes so logging cannot crash callers;
/// 4. VoiceModeForegroundService must handle null intents on restart and return START_NOT_STICKY;
/// 5. VoiceModeForegroundService must initialize FileLogger in onCreate.
#[test]
fn voice_mode_foreground_service_and_logger_robustness() {
    let manifest = include_str!("../../android/app/src/main/AndroidManifest.xml");
    let service = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceModeForegroundService.java"
    );
    let logger = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/util/FileLogger.java"
    );
    let logger_test = include_str!(
        "../../android/app/src/test/java/com/chatbot/app/util/FileLoggerTest.java"
    );

    assert!(
        manifest.contains("android.permission.CHANGE_NETWORK_STATE"),
        "manifest must declare CHANGE_NETWORK_STATE for ConnectivityManager.requestNetwork"
    );

    assert!(
        logger.contains("logFile == null") || logger.contains("logFile != null"),
        "FileLogger must null-check logFile before attempting to construct FileWriter"
    );
    assert!(
        logger.contains("catch (Throwable") || logger.contains("catch (Exception"),
        "FileLogger must catch Throwable/Exception so disk logging never crashes callers"
    );
    assert!(
        logger.contains("getFilesDir()"),
        "FileLogger must fall back to internal storage if getExternalFilesDir is null"
    );

    assert!(
        service.contains("intent == null"),
        "VoiceModeForegroundService.onStartCommand must check for null intent on process restart"
    );
    assert!(
        service.contains("START_NOT_STICKY") && !service.contains("START_STICKY"),
        "VoiceModeForegroundService must be START_NOT_STICKY so dead sessions are not auto-resurrected"
    );
    assert!(
        service.contains("FileLogger.init"),
        "VoiceModeForegroundService must initialize FileLogger in onCreate"
    );

    assert!(
        logger_test.contains("logWithoutInitDoesNotThrow")
            && logger_test.contains("logExceptionWithoutInitDoesNotThrow")
            && logger_test.contains("initWithNullContextDoesNotThrow"),
        "FileLoggerTest must verify null safety when uninitialized"
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

/// Voice mode TTS audio must be queued ahead in an audio queue rather than
/// streaming directly to AudioTrack with minimal preroll. On an unreliable
/// connection:
/// 1. A dropped connection during playback must not halt an already playing
///    sentence mid-sentence;
/// 2. A dropped connection during clip fetch must retry without dropping the
///    sentence or skipping ahead to the next sentence;
/// 3. The audio queue must decouple downloading from playback so network
///    drops cause only a temporary pause rather than audio skipping.
#[test]
fn native_voice_tts_queues_audio_ahead_without_skipping_sentences() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    assert!(
        tts.contains("TtsDownloadQueue<AudioClip>")
            && tts.contains("DOWNLOAD_CONCURRENCY")
            && tts.contains("MAX_QUEUED_CLIPS"),
        "native TTS must bound parallel downloads and buffered clips ahead of playback"
    );
    assert!(
        !tts.contains("STREAM_ATTEMPTS")
            && !tts.contains("attempt < STREAM_ATTEMPTS"),
        "clip fetching must not give up after a fixed 3-attempt cap and drop the sentence; it must retry while the session is active"
    );
    let worker = java_method_body(tts, "private void workerLoop(long generation,")
        .expect("workerLoop must be declared");
    assert!(
        worker.contains("queue.poll") && worker.contains("pending.await()")
            && worker.contains("writePcmToTrack") && worker.contains("queue.complete(pending)"),
        "workerLoop must consume complete clips in queue order and release playback capacity"
    );
    let enqueue = java_method_body(tts, "public void enqueue(PluginCall call)")
        .expect("enqueue must be declared");
    assert!(
        enqueue.contains("queue.offer") && enqueue.contains("playUrlToTrack"),
        "enqueue must schedule fetching through the bounded ordered queue"
    );
}

/// Desktop voice mode must achieve parity with native Android reliability:
/// 1. Audio must be fetched into in-memory Blobs and played via blob URLs so
///    network drops cannot halt playback mid-sentence.
/// 2. Audio must be prefetched ahead so consecutive sentences transition without
///    network latency gaps.
/// 3. While voice mode is active, transient failures must retry persistently
///    rather than giving up after 3 attempts and skipping the sentence.
/// 4. Silero VAD must configure preSpeechPadFrames for pre-roll speech onset parity.
#[test]
fn desktop_voice_tts_queues_audio_ahead_and_prevents_mid_sentence_cutoffs() {
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        chat_js.contains("createObjectURL")
            && chat_js.contains("revokeObjectURL"),
        "desktop TTS must buffer audio into in-memory blobs via object URLs to prevent mid-sentence network cutoffs"
    );
    assert!(
        chat_js.contains("preloadDesktopTtsSentence"),
        "desktop TTS must prefetch/preload upcoming sentences ahead of playback"
    );
    let body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    let pump_start = body
        .find("function pump(")
        .expect("playMessageBodyTts must contain a sentence pump");
    let pump = &body[pump_start..];
    assert!(
        pump.contains("window.voiceModeActive"),
        "desktop sentence pump must distinguish voice mode to persist retries during network drops without skipping"
    );
    assert!(
        function_contains(chat_js, "createVAD", "preSpeechPadFrames"),
        "desktop Silero VAD must configure preSpeechPadFrames to capture speech onset pre-roll"
    );
}

#[test]
fn manual_tts_play_in_voice_mode_reliably_coexists_on_android_and_desktop() {
    let chat_js = include_str!("../../static/chat.js");
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    // 1. Android NativeVoiceTtsPlugin tracks generation and cancels workers promptly
    assert!(
        plugin.contains("ret.put(\"generation\", gen)")
            || plugin.contains("ret.put(\"generation\", playbackGeneration.get())"),
        "beginSession must return generation to tie playbackState events to the active session"
    );
    assert!(
        plugin.contains("ret.put(\"generation\", generation)"),
        "notifyStarted and notifySessionEnded must pass session generation"
    );
    let stop_internal = java_method_body(plugin, "private void stopPlaybackInternal(")
        .expect("stopPlaybackInternal must be declared");
    assert!(
        stop_internal.contains("t.interrupt()") && stop_internal.contains("queue.close()")
            && stop_internal.contains("connection.disconnect()"),
        "stop must interrupt playback, close the download scheduler, and disconnect every active transfer"
    );

    // 2. Chat.js playNativeVoiceModeTts filters stale ended events and resets pre-click VAD state
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    assert!(
        native_tts.contains("onTtsPlaybackStarted") || native_tts.contains("resetSpeechCounters"),
        "playNativeVoiceModeTts must reset mic VAD speech state on start so pre-click noise does not immediately barge-in"
    );
    assert!(
        native_tts.contains("voiceSttAbortController.abort"),
        "playNativeVoiceModeTts must abort in-flight voice STT so stale utterances cannot disrupt playback"
    );
    assert!(
        native_tts.contains("nativeStarted") || native_tts.contains("nativeSessionGen"),
        "playNativeVoiceModeTts must filter out stale ended events that arrive before playback starts"
    );

    // 3. Chat.js desktop playTTS resets bargeInFrames and aborts in-flight STT
    let desktop_tts = function_body(chat_js, "playTTS")
        .expect("playTTS must be declared");
    assert!(
        desktop_tts.contains("bargeInFrames = 0"),
        "desktop playTTS must reset bargeInFrames on start"
    );
    assert!(
        desktop_tts.contains("voiceSttAbortController.abort"),
        "desktop playTTS must abort in-flight voice STT"
    );

    // 4. isStillGenerating checks message-specific generating status, not global abort controller
    let desktop_body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    assert!(
        desktop_body.contains("regenerate-button"),
        "playMessageBodyTts isStillGenerating must check regenerate-button/last-message to avoid falsely stalling completed messages"
    );
    assert!(
        native_tts.contains("regenerate-button"),
        "playNativeVoiceModeTts isStillGenerating must check regenerate-button/last-message to avoid falsely stalling completed messages"
    );
}

#[test]
fn native_tts_audio_focus_and_speaker_routing_during_voice_mode() {
    let chat_js = include_str!("../../static/chat.js");
    let tts_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let mic_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );

    // 1. NativeMicPlugin does not steal audio focus while NativeVoiceTts session is active
    let reclaim = java_method_body(mic_plugin, "void reclaimAudioFocus(")
        .expect("reclaimAudioFocus must be declared");
    assert!(
        reclaim.contains("isSessionActive"),
        "reclaimAudioFocus must not steal focus while NativeVoiceTtsPlugin session is active"
    );

    // 2. NativeVoiceTtsPlugin abandons audio focus and re-enables mic focus on stop
    let stop_internal = java_method_body(tts_plugin, "private void stopPlaybackInternal(")
        .expect("stopPlaybackInternal must be declared");
    assert!(
        stop_internal.contains("abandonAudioFocusRequest")
            && stop_internal.contains("reclaimAudioFocusIfPresent"),
        "stopPlaybackInternal must release audio focus and notify NativeMic to reclaim focus"
    );

    // 3. NativeVoiceTtsPlugin sets preferred device to speaker so media audio is not sent to earpiece
    let ensure_track = java_method_body(tts_plugin, "private AudioTrack ensureTrackPlaying(")
        .expect("ensureTrackPlaying must be declared");
    assert!(
        ensure_track.contains("setPreferredDevice"),
        "ensureTrackPlaying must route AudioTrack to speaker via setPreferredDevice in MODE_IN_COMMUNICATION"
    );

    // 4. CURRENT_AUDIO.stop in playNativeVoiceModeTts resets button UI
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    assert!(
        native_tts.contains("resetPlayButtonUi") || native_tts.contains("clearMessageTtsPlayingUi"),
        "playNativeVoiceModeTts CURRENT_AUDIO.stop must reset play button UI so stopped audio does not stay playing in UI"
    );
}

#[test]
fn streaming_tts_starts_on_first_sentence_without_waiting_for_generation_complete() {
    let chat_js = include_str!("../../static/chat.js");
    let tts_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    // 1. sentenceEndsWithTerminator must match terminators with trailing whitespace/newlines
    let term_body = function_body(chat_js, "sentenceEndsWithTerminator")
        .expect("sentenceEndsWithTerminator must be declared");
    assert!(
        term_body.contains("\\s*$") || term_body.contains(".trim()"),
        "sentenceEndsWithTerminator must handle trailing whitespace/newlines so sentences followed by whitespace or line breaks are recognized as terminated"
    );
    assert!(
        term_body.contains(":") || term_body.contains("[\\r\\n]"),
        "sentenceEndsWithTerminator must recognize colons or line terminators as sentence boundaries"
    );

    // 2. splitSentences must recognize paragraph breaks (\n\n) as sentence boundaries
    let split_body = function_body(chat_js, "splitSentences")
        .expect("splitSentences must be declared");
    assert!(
        split_body.contains("\\n\\n") || split_body.contains("\\n") || split_body.contains("newline"),
        "splitSentences must recognize paragraph breaks or newlines as sentence boundaries"
    );

    // 3. discoverSentences in playNativeVoiceModeTts must not stall preceding completed sentences
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    assert!(
        native_tts.contains("isTrailingFragment") || native_tts.contains("parts.length - 1"),
        "discoverSentences must distinguish trailing in-flight fragments from completed sentences so early sentences stream immediately"
    );

    // 4. playMessageBodyTts desktop path must also distinguish trailing in-flight fragments
    let desktop_tts = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts must be declared");
    assert!(
        desktop_tts.contains("isTrailingFragment") || desktop_tts.contains("sentences.length - 1"),
        "playMessageBodyTts discoverAbsolute must distinguish trailing in-flight fragments from completed sentences"
    );

    // 5. sanitizeForTTS must not destroy paragraph breaks by collapsing newlines into spaces
    let sanitize_body = function_body(chat_js, "sanitizeForTTS")
        .expect("sanitizeForTTS must be declared");
    assert!(
        !sanitize_body.contains(".replace(/\\s+/g, ' ')"),
        "sanitizeForTTS must not unconditionally collapse newlines into spaces, which destroys paragraph boundaries"
    );

    // 6. NativeVoiceTtsPlugin AudioTrack buffer must not exceed 64KB to ensure prompt playback on first sample
    let ensure_track = java_method_body(tts_plugin, "private AudioTrack ensureTrackPlaying(")
        .expect("ensureTrackPlaying must be declared");
    assert!(
        !ensure_track.contains("1024 * 256"),
        "AudioTrack buffer should not be 256KB which can delay initial hardware playback threshold"
    );
}

#[test]
fn unified_android_audio_output_and_reliable_routing() {
    let chat_js = include_str!("../../static/chat.js");
    let tts_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    // 1. Android unifies all TTS playback on NativeVoiceTts
    let play_msg = function_body(chat_js, "playMessageTts")
        .expect("playMessageTts must be declared");
    assert!(
        play_msg.contains("nativeVoiceTtsAvailable") && play_msg.contains("playNativeVoiceModeTts"),
        "playMessageTts must route to playNativeVoiceModeTts when nativeVoiceTtsAvailable is true"
    );

    let play_tts = function_body(chat_js, "playTTS")
        .expect("playTTS must be declared");
    assert!(
        play_tts.contains("nativeVoiceTtsAvailable") && play_tts.contains("playNativeVoiceModeTts"),
        "playTTS must route to playNativeVoiceModeTts when nativeVoiceTtsAvailable is true"
    );

    let play_voice_mode = function_body(chat_js, "playTTSVoiceMode")
        .expect("playTTSVoiceMode must be declared");
    assert!(
        play_voice_mode.contains("nativeVoiceTtsAvailable") && play_voice_mode.contains("playNativeVoiceModeTts"),
        "playTTSVoiceMode must route to playNativeVoiceModeTts when nativeVoiceTtsAvailable is true"
    );

    // 2. playNativeVoiceModeTts live() check does not require window.voiceModeActive
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    let live_fn = function_body(native_tts, "live")
        .expect("live() function inside playNativeVoiceModeTts must be declared");
    assert!(
        !live_fn.contains("window.voiceModeActive"),
        "playNativeVoiceModeTts live() must not require window.voiceModeActive so unified native TTS works outside voice mode"
    );

    // 3. findBuiltInSpeaker must not use getAvailableCommunicationDevices on AudioTrack
    let find_speaker = java_method_body(tts_plugin, "private AudioDeviceInfo findBuiltInSpeaker(")
        .expect("findBuiltInSpeaker must be declared");
    assert!(
        !find_speaker.contains("getAvailableCommunicationDevices"),
        "findBuiltInSpeaker must not pass communication devices to AudioTrack.setPreferredDevice"
    );
    assert!(
        find_speaker.contains("GET_DEVICES_OUTPUTS"),
        "findBuiltInSpeaker must query AudioManager.GET_DEVICES_OUTPUTS for AudioTrack output routing"
    );

    // 4. stopPlaybackInternal must not prematurely reclaim audio focus when starting a new session
    let stop_internal = java_method_body(tts_plugin, "private void stopPlaybackInternal(")
        .expect("stopPlaybackInternal must be declared");
    assert!(
        stop_internal.contains("if (notifyStopped)") || stop_internal.contains("if (!sessionActive.get() && notifyStopped)"),
        "stopPlaybackInternal must only notify NativeMic to reclaim focus when notifyStopped is true, not during beginSession(false)"
    );
}

#[test]
fn native_tts_downloader_bounds_clip_retries_to_avoid_head_of_line_stalls() {
    let tts_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let retry_body = java_method_body(tts_plugin, "private AudioClip playUrlToTrack(String urlStr")
        .expect("playUrlToTrack must be declared");
    assert!(
        retry_body.contains("MAX_CLIP_ATTEMPTS") && retry_body.contains("attempt <"),
        "playUrlToTrack must bound attempts so one failing clip skips instead of retrying forever and head-blocking later sentences"
    );
    assert!(
        retry_body.contains("CLIP_RETRY_BACKOFF_MS"),
        "bounded retries must still back off between attempts for brief blips"
    );
}

#[test]
fn native_tts_requests_audio_focus_once_per_track_not_per_sentence() {
    let tts_plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );
    let ensure = java_method_body(tts_plugin, "private AudioTrack ensureTrackPlaying(")
        .expect("ensureTrackPlaying must be declared");
    let reuse = ensure
        .find("trackSampleRate == sampleRate")
        .expect("reuse path must check for matching sample rate");
    let focus = ensure
        .find("requestAudioFocus()")
        .expect("track creation must still acquire audio focus");
    assert!(
        focus > reuse,
        "reusing the active AudioTrack must not re-request focus, reset volume, or rescan devices per sentence"
    );
    assert!(
        ensure.contains("setPreferredDevice"),
        "track creation must still route to the speaker when appropriate"
    );
}

#[test]
fn native_tts_prefetches_remaining_tokens_when_text_is_complete() {
    let chat_js = include_str!("../../static/chat.js");
    let native_tts = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts must be declared");
    assert!(
        native_tts.contains("inFlightSentences < lookahead") && native_tts.contains("queueSentence(text)"),
        "completed text must fill available look-ahead slots without issuing an unbounded tail of tokens"
    );
    assert!(
        native_tts.contains("const prepared = requestToken(text)")
            && native_tts.contains("enqueueTail = enqueueTail.then"),
        "token requests must start independently of ordered enqueueing"
    );
    assert!(
        native_tts.contains("in sentence order"),
        "prefetched tokens must still enqueue in sentence order to keep server synthesis and native download ordered"
    );
}

#[test]
fn native_tts_refills_a_bounded_window_as_clips_are_consumed() {
    let js = include_str!("../../static/chat.js");
    let native = function_body(js, "playNativeVoiceModeTts").unwrap();
    assert!(native.contains("clipConsumed"), "native playback must release look-ahead slots");
    assert!(native.contains("MAX_NATIVE_TTS_LOOKAHEAD"), "token issuance must be bounded");
    assert!(!native.contains("Promise.all(starters).then"),
        "a slow tail token must not block enqueueing an already-ready first sentence");
}

#[test]
fn native_tts_body_stalls_timeout_sooner_than_synthesis() {
    let tts = include_str!("../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java");
    let fetch = java_method_body(tts, "private AudioClip playUrlToTrackOnce(")
        .or_else(|| java_method_body(tts, "private void playUrlToTrackOnce("))
        .unwrap();
    let headers = fetch.find("conn.getResponseCode()").unwrap();
    let body_timeout = fetch.find("conn.setReadTimeout(CLIP_BODY_STALL_MS)")
        .expect("after synthesis, a stalled audio body must trigger a bounded retry");
    assert!(body_timeout > headers, "synthesis must retain its longer header timeout");
}

/// Desktop TTS blob-404ed forever: playOneTtsUtterance deleted the
/// preload-cache key BEFORE fetching, but a cache miss re-caches the new
/// promise — so the playing clip stayed cached. Any stop then revoked its
/// URL mid-play via clearDesktopTtsPreloads, and finish()'s own revoke let
/// the pump retry replay the same dead URL instead of fetching fresh.
#[test]
fn desktop_tts_playing_clip_is_owned_not_cached() {
    let chat_js = include_str!("../../static/chat.js");
    let play_one = function_body(chat_js, "playOneTtsUtterance")
        .expect("playOneTtsUtterance must be declared");
    let fetch_pos = play_one
        .find("fetchDesktopTtsClip(sessionId, text)")
        .expect("playOneTtsUtterance must fetch on a cache miss");
    let delete_pos = play_one
        .rfind("desktopTtsPreloadCache.delete(cacheKey)")
        .expect("playOneTtsUtterance must take the clip out of the preload cache");
    assert!(
        delete_pos > fetch_pos,
        "the preload-cache delete must come AFTER the fetch call so a cache-miss \
         re-add cannot leave the playing clip cached (revoked mid-play, replayed dead)"
    );
}

/// Retries must never replay an object URL: any earlier stop/finish may have
/// revoked it, and the element 404s a revoked blob:. Each attempt mints a
/// fresh URL from the retained blob.
#[test]
fn desktop_tts_retry_mints_fresh_blob_url_from_retained_blob() {
    let chat_js = include_str!("../../static/chat.js");
    let fetch_clip = function_body(chat_js, "fetchDesktopTtsClip")
        .expect("fetchDesktopTtsClip must be declared");
    assert!(
        fetch_clip.contains("blob: blob"),
        "the fetched clip must retain its blob so play attempts can mint fresh object URLs"
    );
    let play_one = function_body(chat_js, "playOneTtsUtterance")
        .expect("playOneTtsUtterance must be declared");
    assert!(
        play_one.contains("URL.createObjectURL(clip.blob)"),
        "each play attempt must mint its object URL from the retained blob, \
         never replay a possibly-revoked URL"
    );
}

/// The sentence pump only reports the skip; without the MediaError code and
/// the play() rejection reason every systematic playback failure is silent.
/// Both must be logged at the failure site.
#[test]
fn desktop_tts_logs_playback_failure_causes() {
    let chat_js = include_str!("../../static/chat.js");
    assert!(
        function_contains(chat_js, "playOneTtsUtterance", "TTS clip media error"),
        "audio element errors must log the MediaError code, not just fail the attempt"
    );
    assert!(
        function_contains(
            chat_js,
            "playOneTtsUtterance",
            "TTS audio.play() rejected"
        ),
        "non-NotAllowedError play() rejections (e.g. unplayable bytes) must be logged"
    );
}
