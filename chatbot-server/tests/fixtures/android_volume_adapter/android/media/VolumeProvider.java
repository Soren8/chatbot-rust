package android.media;

/**
 * Fake android.media.VolumeProvider leaf for the real volume-adapter harness.
 * Mirrors the platform API surface (absolute control, key/slider overrides,
 * display re-sync); dispatch stays virtual so the real anonymous provider
 * subclass drives behavior.
 */
public class VolumeProvider {
    public static final int VOLUME_CONTROL_FIXED = 0;
    public static final int VOLUME_CONTROL_RELATIVE = 1;
    public static final int VOLUME_CONTROL_ABSOLUTE = 2;

    private final int volumeControl;
    private final int maxVolume;
    private int currentVolume;

    public VolumeProvider(int volumeControl, int maxVolume, int currentVolume) {
        this.volumeControl = volumeControl;
        this.maxVolume = maxVolume;
        this.currentVolume = currentVolume;
    }

    public final int getVolumeControl() {
        return volumeControl;
    }

    public final int getMaxVolume() {
        return maxVolume;
    }

    public final int getCurrentVolume() {
        return currentVolume;
    }

    public final void setCurrentVolume(int currentVolume) {
        this.currentVolume = currentVolume;
    }

    public void onAdjustVolume(int direction) {
    }

    public void onSetVolumeTo(int volume) {
    }
}
