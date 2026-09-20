package android.media.session;

import android.content.Context;
import android.media.VolumeProvider;

/**
 * Fake android.media.session.MediaSession leaf for the real volume-adapter
 * harness. Tracks live sessions so setup-failure leaks fail loudly, exposes
 * the bound provider so stale provider objects stay reachable, and can throw
 * from {@code setPlaybackToRemote} to simulate setup failure.
 */
public class MediaSession {
    public static int liveCount;
    public static MediaSession lastCreated;
    public static boolean failOnPlaybackToRemote;

    private VolumeProvider provider;
    private boolean active;
    private boolean released;

    public MediaSession(Context context, String tag) {
        liveCount++;
        lastCreated = this;
    }

    public void setPlaybackToRemote(VolumeProvider provider) {
        if (failOnPlaybackToRemote) {
            throw new RuntimeException("injected playback-to-remote failure");
        }
        this.provider = provider;
    }

    public VolumeProvider getProvider() {
        return provider;
    }

    public void setPlaybackState(PlaybackState state) {
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public void release() {
        if (!released) {
            released = true;
            liveCount--;
        }
    }
}
