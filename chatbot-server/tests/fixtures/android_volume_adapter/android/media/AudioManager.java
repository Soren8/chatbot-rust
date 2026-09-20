package android.media;

import java.util.ArrayList;
import java.util.List;

/**
 * Fake android.media.AudioManager leaf for the real volume-adapter harness.
 * Only the music-stream surface the backend touches is provided.
 */
public class AudioManager {
    public static final int STREAM_MUSIC = 3;
    public static final int FLAG_SHOW_UI = 1;

    public int musicMax = 15;
    public int musicVolume = 5;
    public final List<Integer> adjusts = new ArrayList<>();
    public final List<Integer> sets = new ArrayList<>();

    public int getStreamMaxVolume(int stream) {
        return musicMax;
    }

    public int getStreamVolume(int stream) {
        return musicVolume;
    }

    public void adjustStreamVolume(int stream, int direction, int flags) {
        adjusts.add(direction);
        musicVolume = Math.max(0, Math.min(musicMax, musicVolume + direction));
    }

    public void setStreamVolume(int stream, int index, int flags) {
        sets.add(index);
        musicVolume = Math.max(0, Math.min(musicMax, index));
    }
}
