package com.chatbot.app.audio;

/**
 * Owns one voice-mode volume session: a remote absolute provider on the music
 * scale, held playing for the whole session so hardware keys drive music.
 * Never writes a level except on explicit key/slider callbacks; stale
 * callbacks are ignored by creation generation. A remote provider is a
 * platform workaround for local audio under the communication mode, not
 * canonical local-media behavior.
 */
public final class VoiceModeVolumeSession {
    public interface Backend {
        /** Platform volume-callback sink, invoked with the creating generation. */
        interface VolumeCallback {
            boolean onAdjustVolume(int direction, long generation);

            boolean onSetVolumeTo(int volume, long generation);
        }

        int getMusicMaxVolume();

        int getMusicVolume();

        /**
         * Create and activate the remote-volume session seeded with the music
         * max/level, holding the callback for later key/slider gestures.
         *
         * @return false when the platform session is unavailable (stay inactive).
         */
        boolean createRemoteVolumeSession(
                int maxVolume, int currentVolume, long generation, VolumeCallback callback);

        /** Refresh the provider display to the live music level. */
        void setProviderVolume(int currentVolume);

        /** Explicit user key gesture: adjust music with the system panel. */
        void adjustMusicVolume(int direction);

        /** Explicit user slider gesture: set music with the system panel. */
        void setMusicVolume(int index);

        void releaseVolumeSession();
    }

    private boolean active;
    private long generation;
    private Backend activeBackend;

    public synchronized boolean isActive() {
        return active;
    }

    public synchronized long currentGeneration() {
        return generation;
    }

    /**
     * Hold the volume session. Returns false when already active, {@code
     * backend} is null, the music level cannot be read, or the platform
     * refuses the session. Never adjusts or sets a stream level.
     */
    public synchronized boolean enter(Backend backend) {
        if (active || backend == null) {
            return false;
        }
        final int maxVolume;
        final int currentVolume;
        try {
            maxVolume = backend.getMusicMaxVolume();
            currentVolume = backend.getMusicVolume();
        } catch (RuntimeException e) {
            return false;
        }
        final long next = generation + 1;
        generation = next;
        final boolean created;
        try {
            created = backend.createRemoteVolumeSession(
                    maxVolume, currentVolume, next, new CallbackForwarder(next));
        } catch (RuntimeException e) {
            return false;
        }
        if (!created) {
            return false;
        }
        activeBackend = backend;
        active = true;
        return true;
    }

    /**
     * Release the volume session. Returns false when not active or {@code
     * backend} is null. Never adjusts or sets a stream level.
     */
    public synchronized boolean exit(Backend backend) {
        if (!active || backend == null) {
            return false;
        }
        try {
            backend.releaseVolumeSession();
        } catch (RuntimeException ignored) {
        }
        active = false;
        activeBackend = null;
        return true;
    }

    /**
     * Explicit user key gesture from the provider. Forwards to music and
     * re-syncs the display. Stale generations and idle sessions are ignored
     * without platform touch.
     */
    public synchronized boolean onAdjustVolume(int direction, long callbackGeneration) {
        if (!active || callbackGeneration != generation || activeBackend == null) {
            return false;
        }
        final Backend backend = activeBackend;
        try {
            backend.adjustMusicVolume(direction);
        } catch (RuntimeException e) {
            return false;
        }
        try {
            backend.setProviderVolume(backend.getMusicVolume());
        } catch (RuntimeException ignored) {
        }
        return true;
    }

    /**
     * Explicit user slider gesture from the provider. Forwards to music and
     * re-syncs the display. Stale generations and idle sessions are ignored
     * without platform touch.
     */
    public synchronized boolean onSetVolumeTo(int volume, long callbackGeneration) {
        if (!active || callbackGeneration != generation || activeBackend == null) {
            return false;
        }
        final Backend backend = activeBackend;
        try {
            backend.setMusicVolume(volume);
        } catch (RuntimeException e) {
            return false;
        }
        try {
            backend.setProviderVolume(backend.getMusicVolume());
        } catch (RuntimeException ignored) {
        }
        return true;
    }

    private final class CallbackForwarder implements Backend.VolumeCallback {
        private final long boundGeneration;

        CallbackForwarder(long boundGeneration) {
            this.boundGeneration = boundGeneration;
        }

        @Override
        public boolean onAdjustVolume(int direction, long generation) {
            return VoiceModeVolumeSession.this.onAdjustVolume(direction, boundGeneration);
        }

        @Override
        public boolean onSetVolumeTo(int volume, long generation) {
            return VoiceModeVolumeSession.this.onSetVolumeTo(volume, boundGeneration);
        }
    }
}
