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

/// Voice-mode TTS plays the communication path, standalone keeps media, and
/// no activity pin picks a stream. Keys follow the active stream; call volume
/// steps/minimum are device-dependent.
#[test]
fn hardware_volume_keys_follow_active_tts_stream() {
    let activity = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/MainActivity.java"
    );
    assert!(
        !activity.contains("setVolumeControlStream"),
        "MainActivity must not pin hardware keys to any stream: voice-mode comm TTS owns the call stream, standalone owns music"
    );
}
