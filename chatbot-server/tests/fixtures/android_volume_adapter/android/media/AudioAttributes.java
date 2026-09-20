package android.media;

/**
 * Fake android.media.AudioAttributes leaf for the real TTS-adapter harness.
 * Records the built usage/content/legacy triple so the driver verifies the
 * production adapter builds communication attributes without a legacy
 * override and media attributes with the music mapping.
 */
public class AudioAttributes {
    public static final int USAGE_UNKNOWN = 0;
    public static final int USAGE_MEDIA = 1;
    public static final int USAGE_VOICE_COMMUNICATION = 2;
    public static final int CONTENT_TYPE_UNKNOWN = 0;
    public static final int CONTENT_TYPE_SPEECH = 1;
    public static final int CONTENT_TYPE_MUSIC = 2;

    public final int usage;
    public final int contentType;
    public final int legacyStreamType;
    public final boolean hasLegacyStreamType;

    private AudioAttributes(int usage, int contentType, int legacyStreamType, boolean hasLegacy) {
        this.usage = usage;
        this.contentType = contentType;
        this.legacyStreamType = legacyStreamType;
        this.hasLegacyStreamType = hasLegacy;
    }

    public static final class Builder {
        private int usage = USAGE_UNKNOWN;
        private int contentType = CONTENT_TYPE_UNKNOWN;
        private int legacyStreamType;
        private boolean hasLegacy;

        public Builder setUsage(int usage) {
            this.usage = usage;
            return this;
        }

        public Builder setContentType(int contentType) {
            this.contentType = contentType;
            return this;
        }

        public Builder setLegacyStreamType(int streamType) {
            this.legacyStreamType = streamType;
            this.hasLegacy = true;
            return this;
        }

        public AudioAttributes build() {
            return new AudioAttributes(usage, contentType, legacyStreamType, hasLegacy);
        }
    }
}
