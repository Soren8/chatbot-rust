package android.media;

/**
 * Fake android.media.AudioFormat leaf for the real TTS-adapter harness.
 * Only the builder surface the extracted track creation uses.
 */
public class AudioFormat {
    public static final int ENCODING_PCM_16BIT = 2;
    public static final int CHANNEL_OUT_MONO = 4;

    public final int encoding;
    public final int sampleRate;
    public final int channelMask;

    private AudioFormat(int encoding, int sampleRate, int channelMask) {
        this.encoding = encoding;
        this.sampleRate = sampleRate;
        this.channelMask = channelMask;
    }

    public static final class Builder {
        private int encoding;
        private int sampleRate;
        private int channelMask;

        public Builder setEncoding(int encoding) {
            this.encoding = encoding;
            return this;
        }

        public Builder setSampleRate(int sampleRate) {
            this.sampleRate = sampleRate;
            return this;
        }

        public Builder setChannelMask(int channelMask) {
            this.channelMask = channelMask;
            return this;
        }

        public AudioFormat build() {
            return new AudioFormat(encoding, sampleRate, channelMask);
        }
    }
}
