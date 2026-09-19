package com.chatbot.app.audio;

/**
 * Holds the microphone foreground service for one handheld voice-mode session.
 *
 * <p>Power-button lock backgrounds the Activity. The FGS keeps the process, mic,
 * and JS loop eligible to run. {@link #enter} is a no-op if already requested so
 * TTS start/stop cannot flicker the notification.
 *
 * <p>Requested vs confirmed: {@link #enter} only records that a platform start
 * was <em>requested</em> and returns whether the backend accepted that request.
 * The service reports back asynchronously after {@code startForeground}
 * succeeds via {@link #onServiceConfirmed}, carrying the request generation
 * minted by {@link #enter}. Only an exact-token confirmation sets
 * {@link #isConfirmed}. Promotion failure ({@link #onServiceStartFailed}) and
 * service teardown ({@link #onServiceDestroyed}, {@link #exit}) clear the
 * confirmation, and a confirm for a stale generation (late start after stop,
 * or a superseded retry) is ignored. Security gates such as the resume
 * biometric bypass must read {@link #isConfirmed}, never {@link #isActive}.
 *
 * <p>No lock is held across backend calls: the backend is always invoked
 * outside the monitor with the reserved token reconciled afterwards, so a
 * destroy plus re-enter interleaved during a stop cannot be clobbered by the
 * older call.
 */
public final class VoiceModeForegroundSession {
    private static final VoiceModeForegroundSession INSTANCE = new VoiceModeForegroundSession();

    public interface Backend {
        /**
         * Honest platform stop outcome. {@code STOPPED} and
         * {@code ALREADY_STOPPED} both release the session; only
         * {@code FAILED} keeps it requested so a retry is allowed.
         */
        enum StopOutcome {
            STOPPED,
            ALREADY_STOPPED,
            FAILED
        }

        /**
         * Request the microphone foreground service and its notification.
         *
         * @return true if the platform request was accepted (not that the
         *     service is already foregrounded; confirmation arrives later via
         *     {@link #onServiceConfirmed}). False leaves the session
         *     unrequested.
         */
        boolean startForeground();

        /**
         * Token overload: labels the start with the reserved request
         * generation.
         */
        default boolean startForeground(long generation) {
            return startForeground();
        }

        /**
         * Stop the service and dismiss the notification.
         *
         * @return false if stop failed (keep the session marked requested).
         *     An already-stopped platform counts as success and clears.
         */
        boolean stopForeground();

        /**
         * Token overload: stops only the owning generation. Maps true to
         * {@code STOPPED}, false and throws to {@code FAILED}; stale tokens
         * report {@code ALREADY_STOPPED} without platform touch.
         */
        default StopOutcome stopForeground(long generation) {
            try {
                return stopForeground() ? StopOutcome.STOPPED : StopOutcome.FAILED;
            } catch (RuntimeException e) {
                return StopOutcome.FAILED;
            }
        }
    }

    public static VoiceModeForegroundSession get() {
        return INSTANCE;
    }

    /** A platform start was requested and not yet released. */
    private boolean requested;
    /** The platform confirmed {@code startForeground} for the current request. */
    private boolean confirmed;
    /** Monotonic token minted per accepted request; stale callbacks carry an old one. */
    private long requestGeneration;

    public synchronized boolean isActive() {
        return requested;
    }

    /**
     * True only after the service confirmed {@code startForeground} for the
     * current request. Promotion failure, stop, and destroy clear it.
     */
    public synchronized boolean isConfirmed() {
        return confirmed;
    }

    /** Token for the current request; the service echoes it back on confirm. */
    public synchronized long currentGeneration() {
        return requestGeneration;
    }

    /**
     * Request the FGS for the voice-mode session. Returns request acceptance:
     * false when already requested, {@code backend} is null, or the backend
     * rejects the request. Confirmation stays false until the service reports
     * {@code startForeground} success; a rejected request leaves the session
     * unrequested so a retry is allowed.
     */
    public boolean enter(Backend backend) {
        final long generation;
        synchronized (this) {
            if (requested || backend == null) {
                return false;
            }
            generation = ++requestGeneration;
            requested = true;
        }
        boolean accepted;
        try {
            accepted = backend.startForeground(generation);
        } catch (RuntimeException e) {
            accepted = false;
        }
        synchronized (this) {
            if (!accepted || generation != requestGeneration || !requested) {
                if (generation == requestGeneration && requested) {
                    requested = false;
                    confirmed = false;
                }
                return false;
            }
            return true;
        }
    }

    /**
     * Stop the FGS. Returns false when not requested, {@code backend} is
     * null, the platform reports failure, or a destroy plus re-enter minted
     * a newer token during the stop. An already-stopped platform clears like
     * a successful stop; only a failure keeps the request.
     */
    public boolean exit(Backend backend) {
        final long generation;
        synchronized (this) {
            if (!requested || backend == null) {
                return false;
            }
            generation = requestGeneration;
        }
        Backend.StopOutcome outcome;
        try {
            outcome = backend.stopForeground(generation);
        } catch (RuntimeException e) {
            outcome = Backend.StopOutcome.FAILED;
        }
        synchronized (this) {
            if (generation != requestGeneration) {
                return false;
            }
            if (outcome == null || outcome == Backend.StopOutcome.FAILED) {
                return false;
            }
            requested = false;
            confirmed = false;
            return true;
        }
    }

    /**
     * Record successful {@code startForeground} for {@code generation}.
     *
     * @return true only when the exact outstanding token confirms; stale
     *     callbacks (late start after stop, superseded retry) return false
     *     and change nothing.
     */
    public synchronized boolean onServiceConfirmed(long generation) {
        if (requested && generation == requestGeneration) {
            confirmed = true;
            return true;
        }
        return false;
    }

    /**
     * Record a failed {@code startForeground} for {@code generation}. The
     * current request is released (never confirmed) so a plain re-enter
     * retries; a stale failure for a superseded generation is ignored.
     */
    public synchronized void onServiceStartFailed(long generation) {
        if (requested && generation == requestGeneration) {
            requested = false;
            confirmed = false;
        }
    }

    /**
     * Record teardown of the service instance bound to {@code generation}.
     * Only that generation may release the session: a stale destroy from an
     * older instance dying after a newer request, or an unattributed one
     * from an instance that never started, leaves the live request alone.
     */
    public synchronized void onServiceDestroyed(long generation) {
        if (generation == requestGeneration) {
            requested = false;
            confirmed = false;
        }
    }

    /**
     * Pure service-side half of the request protocol, colocalized so the
     * trusted {@code javac} harness compiles it with the session (no Android
     * imports; the service keeps only resource handling). The service drives
     * one {@code onStarted} per start intent and one {@code onDestroyed} on
     * teardown; the bound token is set only on accepted confirmation, so a
     * stale intent never clobbers the owned instance token and its destroy
     * still clears the right request.
     */
    public static final class ServiceLifecycle {
        public enum StartOutcome {
            /** Exact token confirmed: acquire session resources. */
            ACQUIRE,
            /** Nobody owns the session: release this orphan service. */
            RELEASE_ORPHAN,
            /** Stale start for a superseded/released request: do nothing. */
            IGNORE_STALE
        }

        private static final long NO_GENERATION = -1;
        private final VoiceModeForegroundSession session;
        private long boundGeneration = NO_GENERATION;

        public ServiceLifecycle(VoiceModeForegroundSession session) {
            this.session = session;
        }

        public StartOutcome onStarted(long generation, boolean promoted) {
            if (!promoted) {
                session.onServiceStartFailed(generation);
                return session.isActive() ? StartOutcome.IGNORE_STALE
                        : StartOutcome.RELEASE_ORPHAN;
            }
            if (!session.onServiceConfirmed(generation)) {
                return session.isActive() ? StartOutcome.IGNORE_STALE
                        : StartOutcome.RELEASE_ORPHAN;
            }
            boundGeneration = generation;
            return StartOutcome.ACQUIRE;
        }

        public void onDestroyed() {
            session.onServiceDestroyed(boundGeneration);
        }
    }
}
