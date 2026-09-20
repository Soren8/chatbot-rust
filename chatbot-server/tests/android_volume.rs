//! Android must never change the user's system volume. Hardware keys follow
//! the active stream: the voice-call stream while voice-mode TTS plays the
//! communication path, the music stream for standalone media TTS.
//!
//! Regression history: entering voice mode forced STREAM_VOICE_CALL to max and
//! exiting restored the pre-session level (clobbering a user change made
//! mid-session); the first TTS clip of a session forced STREAM_MUSIC to max.
//! A later remote-volume workaround is retired: voice-mode TTS now plays
//! USAGE_VOICE_COMMUNICATION matching capture/focus/route, so no MediaSession
//! hack is needed and no activity stream pin is correct.

/// Voice-mode routing must hold mode/speakerphone only. Writing
/// STREAM_VOICE_CALL on enter raises the volume after the user lowered it,
/// and restoring on exit clobbers a user change made mid-session.
#[test]
fn voice_route_never_writes_voice_call_volume() {
    let route = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/audio/VoiceAudioRoute.java"
    );

    assert!(
        !route.contains("setVoiceCallVolume"),
        "VoiceAudioRoute must never write STREAM_VOICE_CALL: enter must not raise it to max, exit must not restore over the user's current level"
    );
    assert!(
        !route.contains("getVoiceCallMaxVolume"),
        "VoiceAudioRoute must not even read the max call volume: there is no level for it to impose"
    );
    assert!(
        route.contains("MODE_IN_COMMUNICATION") && route.contains("setSpeakerphoneOn"),
        "routing must still hold MODE_IN_COMMUNICATION + speakerphone for the session"
    );
}

/// The mic backend must not expose a voice-call volume knob at all, so no
/// future caller can reintroduce the raise. USAGE_VOICE_COMMUNICATION focus
/// is not a stream write.
#[test]
fn mic_backend_never_touches_voice_call_stream() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );

    assert!(
        !plugin.contains("setStreamVolume") && !plugin.contains("adjustStreamVolume"),
        "NativeMic must never write a stream volume: routing holds mode/speakerphone, the user owns every stream level"
    );
}

/// Acquiring focus must not raise a stream volume. The user lowering TTS
/// volume must survive the next clip's track creation, in either path.
#[test]
fn tts_focus_never_raises_stream_volume() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    assert!(
        !tts.contains("setStreamVolume") && !tts.contains("adjustStreamVolume"),
        "NativeVoiceTts must never write the system volume: acquiring focus must keep the user's level"
    );
    assert!(
        tts.contains("requestAudioFocus")
            && tts.contains("USAGE_VOICE_COMMUNICATION")
            && tts.contains("USAGE_MEDIA"),
        "TTS must acquire matching focus for both paths: communication in voice mode, media standalone"
    );
}

/// Voice-mode TTS plays the communication path, standalone keeps media, and
/// no activity pin picks a stream. Keys follow the active stream; call volume
/// steps/minimum are device-dependent.
#[test]
fn hardware_volume_keys_follow_active_tts_stream() {
    let activity = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/MainActivity.java"
    );
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    assert!(
        !activity.contains("setVolumeControlStream"),
        "MainActivity must not pin hardware keys to any stream: voice-mode comm TTS owns the call stream, standalone owns music"
    );
    assert!(
        tts.contains("TtsAudioPolicy.playbackUsage") && tts.contains("isVoiceRouteActive"),
        "TTS playback usage must follow actual route ownership so keys track the stream actually playing"
    );
}
