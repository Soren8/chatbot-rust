//! Android must never change the user's system volume and the hardware
//! volume keys must always drive the stream TTS actually plays on.
//!
//! Regression: entering voice mode forced STREAM_VOICE_CALL to max and
//! exiting restored the pre-session level (clobbering a user change made
//! mid-session); the first TTS clip of a session forced STREAM_MUSIC to
//! max; and with no volume-control-stream pin the hardware keys adjusted
//! STREAM_VOICE_CALL while TTS plays on STREAM_MUSIC (USAGE_MEDIA).

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
/// future caller can reintroduce the raise.
#[test]
fn mic_backend_never_touches_voice_call_stream() {
    let plugin = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java"
    );

    assert!(
        !plugin.contains("STREAM_VOICE_CALL"),
        "NativeMic must not reference STREAM_VOICE_CALL: routing holds mode/speakerphone, the user owns every stream level"
    );
}

/// Acquiring focus must not raise STREAM_MUSIC. The user lowering TTS volume
/// must survive the next clip's track creation.
#[test]
fn tts_focus_never_raises_music_volume() {
    let tts = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
    );

    assert!(
        !tts.contains("setStreamVolume"),
        "NativeVoiceTts must never write the system volume: acquiring focus must keep the user's STREAM_MUSIC level"
    );
    assert!(
        tts.contains("requestAudioFocus")
            && tts.contains("USAGE_MEDIA")
            && tts.contains("STREAM_MUSIC"),
        "TTS must still acquire media focus and play on STREAM_MUSIC/USAGE_MEDIA"
    );
}

/// In MODE_IN_COMMUNICATION the hardware keys default to STREAM_VOICE_CALL,
/// but TTS plays on STREAM_MUSIC. Pin the activity to MUSIC so the keys
/// always drive TTS loudness.
#[test]
fn hardware_volume_keys_drive_tts_music_stream() {
    let activity = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/MainActivity.java"
    );

    assert!(
        activity.contains("setVolumeControlStream(AudioManager.STREAM_MUSIC)"),
        "MainActivity must pin hardware volume keys to STREAM_MUSIC so they adjust TTS, not the voice-call stream"
    );
}
