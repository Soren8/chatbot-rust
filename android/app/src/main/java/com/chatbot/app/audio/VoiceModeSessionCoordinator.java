package com.chatbot.app.audio;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns handheld voice-mode session composition for Capacitor voice mode.
 *
 * <p>One voice-mode session holds four resources for its whole lifetime:
 * speakerphone routing ({@link VoiceAudioRoute}), TTS volume keys
 * ({@link VoiceModeVolumeSession}), keep-screen-on
 * ({@link VoiceSessionKeepAwake}) and the microphone foreground service
 * ({@link VoiceModeForegroundSession}). A phone call ({@code MODE_IN_CALL})
 * pauses the session, and the lock-screen Stop broadcast tears it down. This
 * coordinator owns that pause/resume and enter/exit/stop composition with
 * injected mic/TTS/resource/event interfaces; the plugins keep only thin
 * Android hooks (AudioManager, MediaSession, Activity window, FGS start/stop,
 * Capacitor bridge) and per-plugin policy (mic capture, TTS queue/generation,
 * audio focus, volume provider).
 *
 * <p>Ordering and result semantics:
 * <ul>
 *   <li>enter checks Bluetooth before touching audio, then volume, route,
 *       keep-awake, foreground, then battery exemption and WebView keep-alive.
 *       Volume is held even when Bluetooth skips speaker routing.</li>
 *   <li>exit clears the phone-call pause flag, then route, volume, keep-awake,
 *       foreground.</li>
 *   <li>phone pause stops TTS, then mic, then route, volume, keep-awake,
 *       foreground, then notifies listeners and evals JS.</li>
 *   <li>notification stop evals JS first, then notifies listeners, then stops
 *       TTS/mic and exits resources.</li>
 *   <li>destroy stops mic (not TTS) and exits resources with no events.</li>
 *   <li>foreground enter returns the {@code enter} result, not
 *       {@code isActive()}: a second enter while active returns false.</li>
 *   <li>foreground results distinguish request from platform confirmation:
 *       {@code foreground} is request acceptance, {@code foregroundActive} is
 *       the outstanding request, and {@code foregroundConfirmed} is the live
 *       snapshot: false until the service confirms asynchronously, true on a
 *       repeat enter while the session is already confirmed.</li>
 * </ul>
 *
 * <p>Event delivery: the Capacitor listener channel ({@code notifyPhoneCall},
 * {@code notifyNotificationStop}) is the owned effective delivery for phone
 * pause/resume and notification stop. It is registered in the page before any
 * voice session can exist (sessions start JS-driven via
 * {@code enterVoiceRoute}), and native cleanup never depends on JS
 * acknowledging: pause releases TTS/mic/resources before emitting, and
 * notification stop tears down native audio after emitting even when the
 * bridge is dead. The {@code evalJs} fallback stays because a reloaded or
 * half-torn-down bridge can lose listener registrations while still
 * evaluating window functions; JS pause/resume handlers are idempotent so the
 * dual delivery applies exactly one transition.
 */
public final class VoiceModeSessionCoordinator {
    /** Mic capture owned by NativeMicPlugin. */
    public interface MicControl {
        void stopCapture();

        boolean isCapturing();
    }

    /** TTS playback owned by NativeVoiceTtsPlugin. */
    public interface TtsControl {
        void stopPlayback();

        boolean isSessionActive();
    }

    /** Capacitor dual notify + bridge eval, implemented thinly by the owner. */
    public interface SessionEvents {
        void notifyPhoneCall(boolean active, long transitionId);

        void notifyNotificationStop(long transitionId);

        void evalJs(String script);
    }

    /** Platform hooks implemented thinly by the owner. */
    public interface PlatformHooks {
        void requestBatteryExemption();

        void keepWebViewAlive();
    }

    /**
     * Eval scripts carrying the transition ID. Pause, resume and stop each
     * arrive twice (owned Capacitor listener plus the evalJs fallback) with
     * one monotonic ID; the page gate applies each logical event once and
     * rejects reordered stale ones.
     */
    public static String pauseScript(long transitionId) {
        return "if (window.pauseVoiceModeForPhoneCall) window.pauseVoiceModeForPhoneCall("
                + transitionId + ");";
    }

    public static String resumeScript(long transitionId) {
        return "if (window.resumeVoiceModeAfterPhoneCall) window.resumeVoiceModeAfterPhoneCall("
                + transitionId + ");";
    }

    public static String notificationStopScript(long transitionId) {
        return "if (window.stopVoiceMode) window.stopVoiceMode(" + transitionId + ");";
    }

    /** Mirrors the enterVoiceRoute JSObject fields. */
    public static final class EnterResult {
        public final boolean applied;
        public final boolean active;
        public final boolean bluetooth;
        public final boolean keepAwake;
        public final boolean keepAwakeActive;
        public final boolean foreground;
        public final boolean foregroundActive;
        public final boolean foregroundConfirmed;
        public final boolean volume;
        public final boolean volumeActive;

        public EnterResult(boolean applied, boolean active, boolean bluetooth,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive, boolean foregroundConfirmed) {
            this(applied, active, bluetooth,
                    keepAwake, keepAwakeActive,
                    foreground, foregroundActive, foregroundConfirmed,
                    false, false);
        }

        public EnterResult(boolean applied, boolean active, boolean bluetooth,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive, boolean foregroundConfirmed,
                boolean volume, boolean volumeActive) {
            this.applied = applied;
            this.active = active;
            this.bluetooth = bluetooth;
            this.keepAwake = keepAwake;
            this.keepAwakeActive = keepAwakeActive;
            this.foreground = foreground;
            this.foregroundActive = foregroundActive;
            this.foregroundConfirmed = foregroundConfirmed;
            this.volume = volume;
            this.volumeActive = volumeActive;
        }
    }

    /** Mirrors the exitVoiceRoute JSObject fields. */
    public static final class ExitResult {
        public final boolean applied;
        public final boolean active;
        public final boolean keepAwake;
        public final boolean keepAwakeActive;
        public final boolean foreground;
        public final boolean foregroundActive;
        public final boolean foregroundConfirmed;
        public final boolean volume;
        public final boolean volumeActive;

        public ExitResult(boolean applied, boolean active,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive, boolean foregroundConfirmed) {
            this(applied, active,
                    keepAwake, keepAwakeActive,
                    foreground, foregroundActive, foregroundConfirmed,
                    false, false);
        }

        public ExitResult(boolean applied, boolean active,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive, boolean foregroundConfirmed,
                boolean volume, boolean volumeActive) {
            this.applied = applied;
            this.active = active;
            this.keepAwake = keepAwake;
            this.keepAwakeActive = keepAwakeActive;
            this.foreground = foreground;
            this.foregroundActive = foregroundActive;
            this.foregroundConfirmed = foregroundConfirmed;
            this.volume = volume;
            this.volumeActive = volumeActive;
        }
    }

    private final VoiceAudioRoute route;
    private final VoiceSessionKeepAwake keepAwake;
    private final VoiceModeForegroundSession foreground;
    private final VoiceModeVolumeSession volume;
    private final VoiceAudioRoute.Backend routeBackend;
    private final VoiceSessionKeepAwake.Backend keepAwakeBackend;
    private final VoiceModeForegroundSession.Backend foregroundBackend;
    private final VoiceModeVolumeSession.Backend volumeBackend;
    private final MicControl mic;
    private final TtsControl tts;
    private final SessionEvents events;
    private final PlatformHooks platform;
    private boolean pausedForPhoneCall;
    /**
     * Process-wide transition IDs shared by every coordinator instance. The
     * page gate outlives plugin/coordinator recreation, so a per-instance
     * counter restarting at zero would have all new events silently ignored
     * until it catches up past the gate's last consumed ID.
     */
    private static final AtomicLong TRANSITION_IDS = new AtomicLong();

    /**
     * Production wiring: owns fresh route/keep-awake sessions and the shared
     * foreground singleton.
     */
    public VoiceModeSessionCoordinator(
            VoiceAudioRoute.Backend routeBackend,
            VoiceSessionKeepAwake.Backend keepAwakeBackend,
            VoiceModeForegroundSession.Backend foregroundBackend,
            MicControl mic,
            TtsControl tts,
            SessionEvents events,
            PlatformHooks platform) {
        this(new VoiceAudioRoute(), new VoiceSessionKeepAwake(),
                VoiceModeForegroundSession.get(), null,
                routeBackend, keepAwakeBackend, foregroundBackend, null,
                mic, tts, events, platform);
    }

    /**
     * Production wiring with TTS volume keys: owns fresh route/keep-awake/
     * volume sessions and the shared foreground singleton. The remote volume
     * session keeps background/locked keys on STREAM_MUSIC for the whole
     * voice-mode session.
     */
    public VoiceModeSessionCoordinator(
            VoiceAudioRoute.Backend routeBackend,
            VoiceSessionKeepAwake.Backend keepAwakeBackend,
            VoiceModeForegroundSession.Backend foregroundBackend,
            VoiceModeVolumeSession.Backend volumeBackend,
            MicControl mic,
            TtsControl tts,
            SessionEvents events,
            PlatformHooks platform) {
        this(new VoiceAudioRoute(), new VoiceSessionKeepAwake(),
                VoiceModeForegroundSession.get(), new VoiceModeVolumeSession(),
                routeBackend, keepAwakeBackend, foregroundBackend, volumeBackend,
                mic, tts, events, platform);
    }

    /**
     * Test wiring: injects resource instances so each test owns fresh session
     * state instead of the shared foreground singleton.
     */
    public VoiceModeSessionCoordinator(
            VoiceAudioRoute route,
            VoiceSessionKeepAwake keepAwake,
            VoiceModeForegroundSession foreground,
            VoiceAudioRoute.Backend routeBackend,
            VoiceSessionKeepAwake.Backend keepAwakeBackend,
            VoiceModeForegroundSession.Backend foregroundBackend,
            MicControl mic,
            TtsControl tts,
            SessionEvents events,
            PlatformHooks platform) {
        this(route, keepAwake, foreground, null,
                routeBackend, keepAwakeBackend, foregroundBackend, null,
                mic, tts, events, platform);
    }

    /**
     * Test wiring with volume: injects the volume session so each test owns
     * fresh volume state alongside route/keep-awake/foreground.
     */
    public VoiceModeSessionCoordinator(
            VoiceAudioRoute route,
            VoiceSessionKeepAwake keepAwake,
            VoiceModeForegroundSession foreground,
            VoiceModeVolumeSession volume,
            VoiceAudioRoute.Backend routeBackend,
            VoiceSessionKeepAwake.Backend keepAwakeBackend,
            VoiceModeForegroundSession.Backend foregroundBackend,
            VoiceModeVolumeSession.Backend volumeBackend,
            MicControl mic,
            TtsControl tts,
            SessionEvents events,
            PlatformHooks platform) {
        this.route = route;
        this.keepAwake = keepAwake;
        this.foreground = foreground;
        this.volume = volume;
        this.routeBackend = routeBackend;
        this.keepAwakeBackend = keepAwakeBackend;
        this.foregroundBackend = foregroundBackend;
        this.volumeBackend = volumeBackend;
        this.mic = mic;
        this.tts = tts;
        this.events = events;
        this.platform = platform;
    }

    public boolean isPausedForPhoneCall() {
        return pausedForPhoneCall;
    }

    public boolean isRouteActive() {
        return route != null && route.isActive();
    }

    public boolean isKeepAwakeActive() {
        return keepAwake != null && keepAwake.isActive();
    }

    public boolean isForegroundActive() {
        return foreground != null && foreground.isActive();
    }

    public boolean isForegroundConfirmed() {
        return foreground != null && foreground.isConfirmed();
    }

    public boolean isVolumeActive() {
        return volume != null && volume.isActive();
    }

    public boolean isTtsSessionActive() {
        TtsControl current = tts;
        return current != null && current.isSessionActive();
    }

    public boolean hasBluetoothAudio() {
        return routeBackend != null && routeBackend.hasBluetoothAudio();
    }

    /**
     * Holds speakerphone + TTS volume keys + keep-screen-on + microphone FGS
     * for the session. Volume is held first so the keys are already on music
     * before the communication mode flips; release clears the route first so
     * the keys are already back on music before the volume session goes.
     * Always runs platform hooks, even when already active.
     */
    public EnterResult enterVoiceSession() {
        boolean bluetooth = hasBluetoothAudio();
        boolean volumeEntered = volume != null && volume.enter(volumeBackend);
        boolean applied = route != null && route.enter(routeBackend);
        boolean keepAwakeEntered = keepAwake != null && keepAwake.enter(keepAwakeBackend);
        boolean foregroundEntered = foreground != null && foreground.enter(foregroundBackend);
        if (platform != null) {
            platform.requestBatteryExemption();
            platform.keepWebViewAlive();
        }
        return new EnterResult(applied,
                isRouteActive(), bluetooth,
                keepAwakeEntered, isKeepAwakeActive(),
                foregroundEntered, isForegroundActive(), isForegroundConfirmed(),
                volumeEntered, isVolumeActive());
    }

    /** Restores pre-voice-mode routing and clears any phone-call pause. */
    public ExitResult exitVoiceSession() {
        pausedForPhoneCall = false;
        boolean applied = route != null && route.exit(routeBackend);
        boolean volumeExited = volume != null && volume.exit(volumeBackend);
        boolean keepAwakeExited = keepAwake != null && keepAwake.exit(keepAwakeBackend);
        boolean foregroundExited = foreground != null && foreground.exit(foregroundBackend);
        return new ExitResult(applied, isRouteActive(),
                keepAwakeExited, isKeepAwakeActive(),
                foregroundExited, isForegroundActive(), isForegroundConfirmed(),
                volumeExited, isVolumeActive());
    }

    /**
     * Yields mic, TTS and the communication route for an answered call.
     * Keeps voiceModeWanted: resume is event-only, JS re-enters resources.
     *
     * @return true when the session was paused.
     */
    public boolean pauseForPhoneCall() {
        if (pausedForPhoneCall) {
            return false;
        }
        boolean capturing = mic != null && mic.isCapturing();
        if (!isRouteActive() && !capturing) {
            return false;
        }
        pausedForPhoneCall = true;
        TtsControl currentTts = tts;
        if (currentTts != null) {
            currentTts.stopPlayback();
        }
        if (mic != null) {
            mic.stopCapture();
        }
        if (route != null) {
            route.exit(routeBackend);
        }
        if (volume != null) {
            volume.exit(volumeBackend);
        }
        if (keepAwake != null) {
            keepAwake.exit(keepAwakeBackend);
        }
        if (foreground != null) {
            foreground.exit(foregroundBackend);
        }
        if (events != null) {
            long id = TRANSITION_IDS.incrementAndGet();
            events.notifyPhoneCall(true, id);
            events.evalJs(pauseScript(id));
        }
        return true;
    }

    /**
     * Emits the call-ended events. Resources stay released until JS resumes
     * voice mode after the call.
     *
     * @return true when a pause was cleared.
     */
    public boolean resumeAfterPhoneCall() {
        if (!pausedForPhoneCall) {
            return false;
        }
        pausedForPhoneCall = false;
        if (events != null) {
            long id = TRANSITION_IDS.incrementAndGet();
            events.notifyPhoneCall(false, id);
            events.evalJs(resumeScript(id));
        }
        return true;
    }

    /** Lock-screen Stop: asks JS first, then tears down native audio. */
    public void notificationStop() {
        if (events != null) {
            long id = TRANSITION_IDS.incrementAndGet();
            events.evalJs(notificationStopScript(id));
            events.notifyNotificationStop(id);
        }
        TtsControl currentTts = tts;
        if (currentTts != null) {
            currentTts.stopPlayback();
        }
        if (mic != null) {
            mic.stopCapture();
        }
        if (route != null) {
            route.exit(routeBackend);
        }
        if (volume != null) {
            volume.exit(volumeBackend);
        }
        if (keepAwake != null) {
            keepAwake.exit(keepAwakeBackend);
        }
        if (foreground != null) {
            foreground.exit(foregroundBackend);
        }
    }

    /** Activity teardown: stops mic and releases resources with no events. */
    public void destroy() {
        pausedForPhoneCall = false;
        if (mic != null) {
            mic.stopCapture();
        }
        if (route != null) {
            route.exit(routeBackend);
        }
        if (volume != null) {
            volume.exit(volumeBackend);
        }
        if (keepAwake != null) {
            keepAwake.exit(keepAwakeBackend);
        }
        if (foreground != null) {
            foreground.exit(foregroundBackend);
        }
    }

    /** Phone-call mode coordination: pause in call, resume otherwise. */
    public void onAudioRouteChanged(boolean inCall) {
        if (inCall) {
            pauseForPhoneCall();
        } else {
            resumeAfterPhoneCall();
        }
    }
}
