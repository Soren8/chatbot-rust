package android.media.session;

/**
 * Fake android.media.session.PlaybackState leaf for the real volume-adapter
 * harness. Only the playing-state builder surface the backend uses.
 */
public class PlaybackState {
    public static final int STATE_PLAYING = 3;

    public static final class Builder {
        public Builder setState(int state, long position, float speed) {
            return this;
        }

        public Builder setActions(long actions) {
            return this;
        }

        public PlaybackState build() {
            return new PlaybackState();
        }
    }
}
