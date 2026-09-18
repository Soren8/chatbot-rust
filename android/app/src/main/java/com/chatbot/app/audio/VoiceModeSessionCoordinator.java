package com.chatbot.app.audio;

/**
 * Owns handheld voice-mode session composition for Capacitor voice mode.
 *
 * <p>One voice-mode session holds three resources for its whole lifetime:
 * speakerphone routing ({@link VoiceAudioRoute}), keep-screen-on
 * ({@link VoiceSessionKeepAwake}) and the microphone foreground service
 * ({@link VoiceModeForegroundSession}). A phone call ({@code MODE_IN_CALL})
 * pauses the session, and the lock-screen Stop broadcast tears it down. This
 * coordinator owns that pause/resume and enter/exit/stop composition with
 * injected mic/TTS/resource/event interfaces; the plugins keep only thin
 * Android hooks (AudioManager, Activity window, FGS start/stop, Capacitor
 * bridge) and per-plugin policy (mic capture, TTS queue/generation, audio
 * focus).
 *
 * <p>Ordering and result semantics:
 * <ul>
 *   <li>enter checks Bluetooth before touching audio, then route, keep-awake,
 *       foreground, then battery exemption and WebView keep-alive.</li>
 *   <li>exit clears the phone-call pause flag, then route, keep-awake,
 *       foreground.</li>
 *   <li>phone pause stops TTS, then mic, then route, keep-awake, foreground,
 *       then notifies listeners and evals JS.</li>
 *   <li>notification stop evals JS first, then notifies listeners, then stops
 *       TTS/mic and exits resources.</li>
 *   <li>destroy stops mic (not TTS) and exits resources with no events.</li>
 *   <li>foreground enter returns the {@code enter} result, not
 *       {@code isActive()}: a second enter while active returns false.</li>
 * </ul>
 *
 * <p>Pure-Java: no Android or Capacitor imports. Production wires real
 * backends; tests inject fakes alongside the real resource classes.
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
        void notifyPhoneCall(boolean active);

        void notifyNotificationStop();

        void evalJs(String script);
    }

    /** Platform hooks implemented thinly by the owner. */
    public interface PlatformHooks {
        void requestBatteryExemption();

        void keepWebViewAlive();
    }

    public static final String PAUSE_SCRIPT =
            "if (window.pauseVoiceModeForPhoneCall) window.pauseVoiceModeForPhoneCall();";
    public static final String RESUME_SCRIPT =
            "if (window.resumeVoiceModeAfterPhoneCall) window.resumeVoiceModeAfterPhoneCall();";
    public static final String NOTIFICATION_STOP_SCRIPT =
            "if (window.stopVoiceMode) window.stopVoiceMode();";

    /** Mirrors the enterVoiceRoute JSObject fields. */
    public static final class EnterResult {
        public final boolean applied;
        public final boolean active;
        public final boolean bluetooth;
        public final boolean keepAwake;
        public final boolean keepAwakeActive;
        public final boolean foreground;
        public final boolean foregroundActive;

        public EnterResult(boolean applied, boolean active, boolean bluetooth,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive) {
            this.applied = applied;
            this.active = active;
            this.bluetooth = bluetooth;
            this.keepAwake = keepAwake;
            this.keepAwakeActive = keepAwakeActive;
            this.foreground = foreground;
            this.foregroundActive = foregroundActive;
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

        public ExitResult(boolean applied, boolean active,
                boolean keepAwake, boolean keepAwakeActive,
                boolean foreground, boolean foregroundActive) {
            this.applied = applied;
            this.active = active;
            this.keepAwake = keepAwake;
            this.keepAwakeActive = keepAwakeActive;
            this.foreground = foreground;
            this.foregroundActive = foregroundActive;
        }
    }

    private final VoiceAudioRoute route;
    private final VoiceSessionKeepAwake keepAwake;
    private final VoiceModeForegroundSession foreground;
    private final VoiceAudioRoute.Backend routeBackend;
    private final VoiceSessionKeepAwake.Backend keepAwakeBackend;
    private final VoiceModeForegroundSession.Backend foregroundBackend;
    private final MicControl mic;
    private final TtsControl tts;
    private final SessionEvents events;
    private final PlatformHooks platform;
    private boolean pausedForPhoneCall;

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
                VoiceModeForegroundSession.get(),
                routeBackend, keepAwakeBackend, foregroundBackend,
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
        this.route = route;
        this.keepAwake = keepAwake;
        this.foreground = foreground;
        this.routeBackend = routeBackend;
        this.keepAwakeBackend = keepAwakeBackend;
        this.foregroundBackend = foregroundBackend;
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

    public boolean isTtsSessionActive() {
        TtsControl current = tts;
        return current != null && current.isSessionActive();
    }

    public boolean hasBluetoothAudio() {
        return routeBackend != null && routeBackend.hasBluetoothAudio();
    }

    /**
     * Holds speakerphone + keep-screen-on + microphone FGS for the session.
     * Always runs platform hooks, even when already active.
     */
    public EnterResult enterVoiceSession() {
        boolean bluetooth = hasBluetoothAudio();
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
                foregroundEntered, isForegroundActive());
    }

    /** Restores pre-voice-mode routing and clears any phone-call pause. */
    public ExitResult exitVoiceSession() {
        pausedForPhoneCall = false;
        boolean applied = route != null && route.exit(routeBackend);
        boolean keepAwakeExited = keepAwake != null && keepAwake.exit(keepAwakeBackend);
        boolean foregroundExited = foreground != null && foreground.exit(foregroundBackend);
        return new ExitResult(applied, isRouteActive(),
                keepAwakeExited, isKeepAwakeActive(),
                foregroundExited, isForegroundActive());
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
        if (keepAwake != null) {
            keepAwake.exit(keepAwakeBackend);
        }
        if (foreground != null) {
            foreground.exit(foregroundBackend);
        }
        if (events != null) {
            events.notifyPhoneCall(true);
            events.evalJs(PAUSE_SCRIPT);
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
            events.notifyPhoneCall(false);
            events.evalJs(RESUME_SCRIPT);
        }
        return true;
    }

    /** Lock-screen Stop: asks JS first, then tears down native audio. */
    public void notificationStop() {
        if (events != null) {
            events.evalJs(NOTIFICATION_STOP_SCRIPT);
            events.notifyNotificationStop();
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
