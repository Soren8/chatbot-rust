package com.chatbot.app.audio;

/**
 * Holds the microphone foreground service for one handheld voice-mode session.
 *
 * Power-button lock backgrounds the Activity. The FGS keeps the process, mic,
 * and JS loop eligible to run. {@link #enter} is a no-op if already active so
 * TTS start/stop cannot flicker the notification.
 */
public final class VoiceModeForegroundSession {
    private static final VoiceModeForegroundSession INSTANCE = new VoiceModeForegroundSession();

    public interface Backend {
        /**
         * Start the microphone foreground service and its notification.
         *
         * @return false if the service could not be started (do not mark active).
         */
        boolean startForeground();

        /**
         * Stop the service and dismiss the notification.
         *
         * @return false if stop failed (keep the session marked active).
         */
        boolean stopForeground();
    }

    public static VoiceModeForegroundSession get() {
        return INSTANCE;
    }

    private boolean active;

    public synchronized boolean isActive() {
        return active;
    }

    /**
     * Start the FGS for the voice-mode session. Returns false when already
     * active, {@code backend} is null, or start fails.
     */
    public synchronized boolean enter(Backend backend) {
        if (active || backend == null) {
            return false;
        }
        if (!backend.startForeground()) {
            return false;
        }
        active = true;
        return true;
    }

    /**
     * Stop the FGS. Returns false when not active or {@code backend} is null.
     */
    public synchronized boolean exit(Backend backend) {
        if (!active || backend == null) {
            return false;
        }
        if (!backend.stopForeground()) {
            return false;
        }
        active = false;
        return true;
    }
}
