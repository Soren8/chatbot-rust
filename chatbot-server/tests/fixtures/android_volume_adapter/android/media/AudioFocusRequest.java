package android.media;

/**
 * Fake android.media.AudioFocusRequest leaf for the real TTS-adapter harness.
 * Captures the requested usage so the driver verifies focus matches the
 * built playback attributes.
 */
public class AudioFocusRequest {
    public final int usage;

    private AudioFocusRequest(int usage) {
        this.usage = usage;
    }

    public static final class Builder {
        private final int focusGain;
        private AudioAttributes audioAttributes;

        public Builder(int focusGain) {
            this.focusGain = focusGain;
        }

        public Builder setAudioAttributes(AudioAttributes attributes) {
            this.audioAttributes = attributes;
            return this;
        }

        public AudioFocusRequest build() {
            int usage = audioAttributes != null
                    ? audioAttributes.usage
                    : AudioAttributes.USAGE_UNKNOWN;
            return new AudioFocusRequest(usage);
        }
    }
}
