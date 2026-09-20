package android.media;

import java.util.ArrayList;
import java.util.List;

/**
 * Fake android.media.AudioManager leaf for the real TTS-adapter harness.
 * Adapted from the retired volume harness: now records focus ownership
 * (request/abandon with the requested usage) and any stream-volume writes
 * (which must stay empty), instead of driving music levels.
 */
public class AudioManager {
    public static final int STREAM_MUSIC = 3;
    public static final int FLAG_SHOW_UI = 1;
    public static final int AUDIOFOCUS_GAIN = 1;
    public static final int AUDIOFOCUS_REQUEST_GRANTED = 1;
    public static final int GET_DEVICES_OUTPUTS = 0;

    public final List<Integer> focusRequests = new ArrayList<>();
    public int focusAbandons;
    public final List<Integer> adjusts = new ArrayList<>();
    public final List<Integer> sets = new ArrayList<>();

    public int requestAudioFocus(AudioFocusRequest request) {
        focusRequests.add(request != null ? request.usage : -1);
        return AUDIOFOCUS_REQUEST_GRANTED;
    }

    public void abandonAudioFocusRequest(AudioFocusRequest request) {
        focusAbandons++;
    }

    public int getStreamMaxVolume(int stream) {
        return 15;
    }

    public int getStreamVolume(int stream) {
        return 5;
    }

    public void adjustStreamVolume(int stream, int direction, int flags) {
        adjusts.add(direction);
    }

    public void setStreamVolume(int stream, int index, int flags) {
        sets.add(index);
    }
}
