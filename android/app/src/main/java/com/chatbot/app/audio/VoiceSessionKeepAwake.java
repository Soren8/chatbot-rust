package com.chatbot.app.audio;

/**
 * Holds the screen-on flag for one handheld voice-mode session.
 *
 * Voice mode is JS-driven (RMS VAD, STT, chat, TTS). Auto screen sleep
 * pauses the Activity and WebView, so the loop dies. {@link #enter} is a
 * no-op if already active so TTS start/stop cannot flicker the window flag.
 */
public final class VoiceSessionKeepAwake {
    public interface Backend {
        /**
         * Apply or clear the keep-screen-on window flag.
         *
         * @return false if the window is unavailable (do not mark the session
         *     active). Clearing during teardown with no window may return true.
         */
        boolean setKeepScreenOn(boolean on);
    }

    private boolean active;

    public synchronized boolean isActive() {
        return active;
    }

    /**
     * Keep the screen on for the voice-mode session. Returns false when already
     * active, {@code backend} is null, or the window is unavailable.
     */
    public synchronized boolean enter(Backend backend) {
        if (active || backend == null) {
            return false;
        }
        if (!backend.setKeepScreenOn(true)) {
            return false;
        }
        active = true;
        return true;
    }

    /**
     * Allow the screen to sleep again. Returns false when not active or
     * {@code backend} is null.
     */
    public synchronized boolean exit(Backend backend) {
        if (!active || backend == null) {
            return false;
        }
        if (!backend.setKeepScreenOn(false)) {
            return false;
        }
        active = false;
        return true;
    }
}
