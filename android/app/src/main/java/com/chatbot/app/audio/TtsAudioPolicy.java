package com.chatbot.app.audio;

import android.media.AudioAttributes;

/**
 * Selects handheld TTS playback attributes from actual voice-route ownership.
 *
 * <p>Voice mode holds {@code MODE_IN_COMMUNICATION} with {@code
 * VOICE_COMMUNICATION} capture; full-duplex output uses {@code
 * USAGE_VOICE_COMMUNICATION} / {@code CONTENT_TYPE_SPEECH} with matching
 * focus attributes (same-attributes player/focus per the audio-focus guide).
 * Standalone TTS outside voice mode keeps {@code USAGE_MEDIA} with the
 * {@code STREAM_MUSIC} legacy mapping. The communication path omits {@code
 * setLegacyStreamType} because it overwrites the attributes (AOSP audio
 * attributes). Preferred-device routing applies only where the route is
 * authoritative; a Bluetooth-skipped route stays {@code MODE_NORMAL} with
 * media playback. This owner never reads or writes any stream volume.
 */
public final class TtsAudioPolicy {
    private TtsAudioPolicy() {
    }

    /** Playback usage from actual route ownership, not foreground state. */
    public static int playbackUsage(boolean routeActive) {
        return routeActive
                ? AudioAttributes.USAGE_VOICE_COMMUNICATION
                : AudioAttributes.USAGE_MEDIA;
    }

    /** Only the media path keeps the legacy music-stream mapping. */
    public static boolean useLegacyMusicStream(boolean routeActive) {
        return !routeActive;
    }

    /** Preferred speaker only where the owned route holds communication. */
    public static boolean preferBuiltInSpeaker(boolean routeActive, boolean hasHeadsetOrBluetooth) {
        return routeActive && !hasHeadsetOrBluetooth;
    }

    /**
     * Recreate the track when usage or rate changes, including a same-rate
     * usage flip (voice enter/exit). Reuse only on identical usage and rate
     * so steady playback avoids per-sentence churn.
     */
    public static boolean shouldRecreateTrack(boolean hasTrack,
            int currentUsage, int currentRate, int desiredUsage, int desiredRate) {
        if (!hasTrack) {
            return true;
        }
        return currentUsage != desiredUsage || currentRate != desiredRate;
    }

    /** Refresh focus only when usage changes; the holder keeps it otherwise. */
    public static boolean shouldRefreshFocus(boolean hasFocus, int currentFocusUsage, int desiredUsage) {
        if (!hasFocus) {
            return true;
        }
        return currentFocusUsage != desiredUsage;
    }
}
