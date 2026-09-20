package android.media;

/**
 * Fake android.media.AudioTrack leaf for the real TTS-adapter harness.
 * Records the built attributes, preferred-device routing and lifecycle so
 * the driver verifies recreation on usage change, reuse otherwise, and
 * release on replacement without stream writes.
 */
public class AudioTrack {
    public static final int PLAYSTATE_PLAYING = 3;
    public static final int MODE_STREAM = 1;
    public static final int WRITE_BLOCKING = 0;

    public static int createdTracks;
    public static int releasedTracks;

    public final AudioAttributes attributes;
    public final AudioFormat format;
    public boolean preferredDeviceSet;
    public boolean playing;
    public boolean released;
    public float volume = 1.0f;

    public AudioTrack(AudioAttributes attributes, AudioFormat format) {
        this.attributes = attributes;
        this.format = format;
        createdTracks++;
    }

    public static int getMinBufferSize(int sampleRate, int channelConfig, int encoding) {
        return 4096;
    }

    public int getPlayState() {
        return playing ? PLAYSTATE_PLAYING : 0;
    }

    public void play() {
        playing = true;
    }

    public void stop() {
        playing = false;
    }

    public void release() {
        if (!released) {
            released = true;
            releasedTracks++;
        }
    }

    public void setPreferredDevice(AudioDeviceInfo device) {
        preferredDeviceSet = device != null;
    }

    public void setVolume(float volume) {
        this.volume = volume;
    }

    public static final class Builder {
        private AudioAttributes audioAttributes;
        private AudioFormat audioFormat;
        private int bufferSizeInBytes;
        private int transferMode;

        public Builder setAudioAttributes(AudioAttributes attributes) {
            this.audioAttributes = attributes;
            return this;
        }

        public Builder setAudioFormat(AudioFormat format) {
            this.audioFormat = format;
            return this;
        }

        public Builder setBufferSizeInBytes(int size) {
            this.bufferSizeInBytes = size;
            return this;
        }

        public Builder setTransferMode(int mode) {
            this.transferMode = mode;
            return this;
        }

        public AudioTrack build() {
            return new AudioTrack(audioAttributes, audioFormat);
        }
    }
}
