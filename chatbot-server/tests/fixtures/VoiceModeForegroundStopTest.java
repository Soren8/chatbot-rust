import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.audio.VoiceModeForegroundService;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.audio.VoiceModeSessionCoordinator;
import com.chatbot.app.audio.VoiceSessionKeepAwake;

/**
 * Foreground-stop honesty with the REAL production adapter.
 *
 * <p>Each session test owns a fresh {@link VoiceModeForegroundSession}; the
 * stop path always calls the real {@code VoiceModeForegroundService.stop}
 * through reflection (void on the old adapter, honest outcome on the fixed
 * one). A pure boolean fake would hide the fabrication, so the fake platform
 * context below is the only fake: it controls {@code stopService} success,
 * already-stopped and throw modes and counts platform touches.
 */
public final class VoiceModeForegroundStopTest {
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class FakeContext extends android.content.Context {
        boolean throwOnStop;
        boolean stopResult = true;
        int stopCalls;
        int startCalls;
        final java.util.List<String> platformEvents = new java.util.ArrayList<>();
        Runnable onGetApplicationContextOnce;
        private boolean hookFired;

        @Override
        public android.content.Context getApplicationContext() {
            if (onGetApplicationContextOnce != null && !hookFired) {
                hookFired = true;
                onGetApplicationContextOnce.run();
            }
            return this;
        }

        @Override
        public void startService(android.content.Intent intent) {
            startCalls++;
            platformEvents.add("start");
        }

        @Override
        public void startForegroundService(android.content.Intent intent) {
            startCalls++;
            platformEvents.add("start");
        }

        @Override
        public boolean stopService(android.content.Intent intent) {
            stopCalls++;
            platformEvents.add("stop");
            if (throwOnStop) {
                throw new RuntimeException("platform throw");
            }
            return stopResult;
        }
    }

    /**
     * Production-shaped adapter: start is accepted (start honesty is owned by
     * the earlier confirmation work); stop always goes through the real
     * service. Reflection keeps one fixture compiling against both the old
     * void adapter and the honest outcome without reading source text.
     */
    private static final class RealAdapterBackend
            implements VoiceModeForegroundSession.Backend {
        final FakeContext context;

        RealAdapterBackend(FakeContext context) {
            this.context = context;
        }

        @Override
        public boolean startForeground() {
            return true;
        }

        @Override
        public boolean stopForeground() {
            return callRealServiceStop(context);
        }
    }

    private static final class RealSingletonTokenBackend
            implements VoiceModeForegroundSession.Backend {
        final FakeContext context;

        RealSingletonTokenBackend(FakeContext context) {
            this.context = context;
        }

        @Override
        public boolean startForeground() {
            return true;
        }

        @Override
        public boolean stopForeground() {
            return callRealServiceStop(context);
        }

        @Override
        public VoiceModeForegroundSession.Backend.StopOutcome stopForeground(
                long generation) {
            return VoiceModeForegroundService.stop(context, generation);
        }
    }

    private static boolean callRealServiceStop(FakeContext context) {
        try {
            java.lang.reflect.Method single = null;
            for (java.lang.reflect.Method m
                    : VoiceModeForegroundService.class.getMethods()) {
                if (!m.getName().equals("stop")) {
                    continue;
                }
                if (m.getParameterTypes().length != 1) {
                    continue;
                }
                if (!m.getReturnType().equals(void.class)) {
                    single = m;
                    break;
                }
                if (single == null) {
                    single = m;
                }
            }
            if (single == null) {
                throw new AssertionError("Service.stop(Context) missing");
            }
            Object outcome = single.invoke(null, (Object) context);
            if (outcome == null) {
                return true;
            }
            return !"FAILED".equals(outcome.toString());
        } catch (java.lang.reflect.InvocationTargetException e) {
            return false;
        } catch (AssertionError e) {
            throw e;
        } catch (Exception e) {
            throw new AssertionError("adapter reflection failed: " + e);
        }
    }

    private static void callRealServiceStopWithGeneration(
            FakeContext context, long generation) throws Exception {
        for (java.lang.reflect.Method m
                : VoiceModeForegroundService.class.getMethods()) {
            if (m.getName().equals("stop")
                    && m.getParameterTypes().length == 2) {
                try {
                    m.invoke(null, context, generation);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException) {
                        throw (RuntimeException) cause;
                    }
                    throw new AssertionError("token stop threw: " + cause);
                }
                return;
            }
        }
        java.lang.reflect.Method single = VoiceModeForegroundService.class.getMethod(
                "stop", android.content.Context.class);
        try {
            single.invoke(null, (Object) context);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new AssertionError("stop threw: " + cause);
        }
    }

    private static void platformThrowKeepsSessionRequested() {
        FakeContext context = new FakeContext();
        context.throwOnStop = true;
        RealAdapterBackend backend = new RealAdapterBackend(context);
        VoiceModeForegroundSession session = new VoiceModeForegroundSession();

        check(session.enter(backend), "throw setup: enter must be accepted");
        session.onServiceConfirmed(session.currentGeneration());
        check(session.isConfirmed(), "throw setup: must be confirmed");

        boolean exited = session.exit(backend);

        check(!exited, "platform throw must not report stopped");
        check(session.isActive(), "platform throw must keep the request");
        check(session.isConfirmed(), "platform throw must keep the confirmation");
        check(context.stopCalls == 1, "platform throw must attempt once, got "
                + context.stopCalls);
    }

    private static void platformNullContextKeepsSessionRequested() {
        RealAdapterBackend failing = new RealAdapterBackend(null);
        VoiceModeForegroundSession session = new VoiceModeForegroundSession();
        FakeContext goodContext = new FakeContext();
        RealAdapterBackend good = new RealAdapterBackend(goodContext);

        check(session.enter(good), "null setup: enter must be accepted");
        session.onServiceConfirmed(session.currentGeneration());
        check(session.isConfirmed(), "null setup: must be confirmed");

        boolean exited = session.exit(failing);

        check(!exited, "null platform context must not report stopped");
        check(session.isActive(), "null platform context must keep the request");
        check(session.isConfirmed(), "null platform context must keep confirmation");
    }

    private static void alreadyStoppedClearsSession() {
        FakeContext context = new FakeContext();
        context.stopResult = false;
        RealAdapterBackend backend = new RealAdapterBackend(context);
        VoiceModeForegroundSession session = new VoiceModeForegroundSession();

        check(session.enter(backend), "already-stopped setup: enter accepted");
        session.onServiceConfirmed(session.currentGeneration());

        boolean exited = session.exit(backend);

        check(exited, "already-stopped must report stopped");
        check(!session.isActive(), "already-stopped must release the request");
        check(!session.isConfirmed(), "already-stopped must clear confirmation");
        check(context.stopCalls == 1, "already-stopped must touch once, got "
                + context.stopCalls);
        check(session.enter(backend), "re-enter after already-stopped accepted");
    }

    private static void successfulStopClearsSession() {
        FakeContext context = new FakeContext();
        context.stopResult = true;
        RealAdapterBackend backend = new RealAdapterBackend(context);
        VoiceModeForegroundSession session = new VoiceModeForegroundSession();

        check(session.enter(backend), "success setup: enter accepted");
        session.onServiceConfirmed(session.currentGeneration());

        boolean exited = session.exit(backend);

        check(exited, "successful stop must report stopped");
        check(!session.isActive(), "successful stop must release the request");
        check(!session.isConfirmed(), "successful stop must clear confirmation");
        check(context.stopCalls == 1, "successful stop must touch once, got "
                + context.stopCalls);
    }

    private static void serviceDestroyClearsAndStaleDestroyKeepsNewer() {
        VoiceModeForegroundSession session = new VoiceModeForegroundSession();
        RealAdapterBackend backend = new RealAdapterBackend(new FakeContext());

        check(session.enter(backend), "destroy setup: enter accepted");
        session.onServiceConfirmed(session.currentGeneration());
        long first = session.currentGeneration();

        session.onServiceDestroyed(first);

        check(!session.isActive(), "destroy must release the request");
        check(!session.isConfirmed(), "destroy must clear confirmation");

        check(session.enter(backend), "re-enter after destroy accepted");
        long second = session.currentGeneration();
        check(second != first, "re-enter must mint a fresh token");

        session.onServiceDestroyed(first);

        check(session.isActive(), "stale destroy must not release the newer request");
        check(session.currentGeneration() == second, "newer token must survive");

        session.onServiceDestroyed(-1L);

        check(session.isActive(), "unattributed destroy must clear nothing");
        session.onServiceDestroyed(second);
        check(!session.isActive(), "current destroy must clear the newer request");
    }

    private static void staleStopDoesNotTouchNewerGeneration() throws Exception {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext cleanupContext = new FakeContext();
        cleanupContext.stopResult = true;
        RealAdapterBackend cleanup = new RealAdapterBackend(cleanupContext);
        if (singleton.isActive()) {
            singleton.exit(cleanup);
            if (singleton.isActive()) {
                singleton.onServiceDestroyed(singleton.currentGeneration());
            }
        }
        check(!singleton.isActive(), "stale setup: singleton must start idle");

        FakeContext context = new FakeContext();
        context.stopResult = true;
        RealAdapterBackend backend = new RealAdapterBackend(context);

        check(singleton.enter(backend), "stale setup: first enter accepted");
        long first = singleton.currentGeneration();
        singleton.onServiceConfirmed(first);
        singleton.onServiceDestroyed(first);
        check(!singleton.isActive(), "stale setup: first request must be gone");

        check(singleton.enter(backend), "stale setup: second enter accepted");
        long second = singleton.currentGeneration();
        check(second != first, "stale setup: second must mint a fresh token");

        int before = context.stopCalls;
        callRealServiceStopWithGeneration(context, first);

        check(context.stopCalls == before,
                "stale stop must not touch the platform for a newer generation, calls="
                        + context.stopCalls);
        check(singleton.isActive(), "stale stop must not release the newer request");
        check(singleton.currentGeneration() == second, "newer token must survive");

        callRealServiceStopWithGeneration(context, second);

        check(context.stopCalls == before + 1,
                "current stop must touch the platform once, calls="
                        + context.stopCalls);
        check(singleton.exit(backend), "current exit must clear the newer request");
        check(!singleton.isActive(), "newer request must be gone after current stop");
    }

    private static void singletonTokenThrowKeepsRequest() {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext cleanupContext = new FakeContext();
        RealSingletonTokenBackend cleanup =
                new RealSingletonTokenBackend(cleanupContext);
        if (singleton.isActive()) {
            singleton.exit(cleanup);
            if (singleton.isActive()) {
                singleton.onServiceDestroyed(singleton.currentGeneration());
            }
        }
        FakeContext context = new FakeContext();
        RealSingletonTokenBackend backend = new RealSingletonTokenBackend(context);

        check(singleton.enter(backend), "token throw setup: enter accepted");
        singleton.onServiceConfirmed(singleton.currentGeneration());

        context.throwOnStop = true;
        boolean exited = singleton.exit(backend);

        check(!exited, "token throw must not report stopped");
        check(singleton.isActive(), "token throw must keep the request");
        check(singleton.isConfirmed(), "token throw must keep confirmation");

        context.throwOnStop = false;
        check(singleton.exit(backend), "token retry must clear");
        check(!singleton.isActive(), "token retry must release");
    }

    private static void singletonTokenAlreadyStoppedClears() {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext context = new FakeContext();
        context.stopResult = false;
        RealSingletonTokenBackend backend = new RealSingletonTokenBackend(context);
        if (singleton.isActive()) {
            singleton.onServiceDestroyed(singleton.currentGeneration());
        }

        check(singleton.enter(backend), "token already setup: enter accepted");
        singleton.onServiceConfirmed(singleton.currentGeneration());

        check(singleton.exit(backend), "token already-stopped must report stopped");
        check(!singleton.isActive(), "token already-stopped must release");
        check(!singleton.isConfirmed(), "token already-stopped must clear");
    }

    private static void singletonTokenSuccessClears() {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext context = new FakeContext();
        context.stopResult = true;
        RealSingletonTokenBackend backend = new RealSingletonTokenBackend(context);
        if (singleton.isActive()) {
            singleton.onServiceDestroyed(singleton.currentGeneration());
        }

        check(singleton.enter(backend), "token success setup: enter accepted");
        singleton.onServiceConfirmed(singleton.currentGeneration());

        check(singleton.exit(backend), "token success must report stopped");
        check(!singleton.isActive(), "token success must release");
    }

    private static void interleavedStopDuringPlatformCallNeverKillsNewer()
            throws Exception {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext setupContext = new FakeContext();
        RealSingletonTokenBackend setup =
                new RealSingletonTokenBackend(setupContext);
        if (singleton.isActive()) {
            singleton.exit(setup);
            if (singleton.isActive()) {
                singleton.onServiceDestroyed(singleton.currentGeneration());
            }
        }
        FakeContext context = new FakeContext();
        context.stopResult = true;
        RealSingletonTokenBackend backend = new RealSingletonTokenBackend(context);

        check(singleton.enter(backend), "interleave setup: enter accepted");
        final long first = singleton.currentGeneration();
        singleton.onServiceConfirmed(first);

        context.onGetApplicationContextOnce = new Runnable() {
            @Override
            public void run() {
                singleton.onServiceDestroyed(first);
                RealSingletonTokenBackend fresh =
                        new RealSingletonTokenBackend(context);
                check(singleton.enter(fresh), "latch re-enter accepted");
                long second = singleton.currentGeneration();
                check(second != first, "latch must mint a fresh token");
                check(VoiceModeForegroundService.start(context, second),
                        "latch platform start accepted");
            }
        };

        int stopsBefore = context.stopCalls;
        int startsBefore = context.startCalls;
        VoiceModeForegroundSession.Backend.StopOutcome outcome =
                VoiceModeForegroundService.stop(context, first);

        check(context.startCalls == startsBefore + 1,
                "latch must record the newer platform start, starts="
                        + context.startCalls);
        check(outcome
                        != VoiceModeForegroundSession.Backend.StopOutcome.FAILED,
                "interleaved stale stop must not report failure");
        int stopIndex = -1;
        int startIndex = -1;
        java.util.List<String> events = context.platformEvents;
        for (int i = 0; i < events.size(); i++) {
            if (events.get(i).equals("start") && startIndex < 0) {
                startIndex = i;
            }
            if (events.get(i).equals("stop")) {
                stopIndex = i;
            }
        }
        check(startIndex >= 0, "newer platform start must be recorded");
        check(stopIndex < 0 || stopIndex < startIndex,
                "old stop must never run after the newer start, events=" + events);
        check(singleton.isActive(), "newer request must survive the stale stop");
        check(singleton.exit(backend), "newer exit must clear");
        check(!singleton.isActive(), "singleton must be idle after newer exit");
        check(context.stopCalls == stopsBefore + 1,
                "newer exit must touch once, stops=" + context.stopCalls);
    }

    private static final class TestableService extends VoiceModeForegroundService {
        int stopSelfCalls;

        @Override
        public void stopSelf() {
            stopSelfCalls++;
        }
    }

    private static String generationExtraKey() throws Exception {
        java.lang.reflect.Field field = VoiceModeForegroundService.class
                .getDeclaredField("EXTRA_GENERATION");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    private static void realServiceStartCommandAndDestroyOwnLifecycle()
            throws Exception {
        VoiceModeForegroundSession singleton = VoiceModeForegroundSession.get();
        FakeContext cleanupContext = new FakeContext();
        RealSingletonTokenBackend cleanup =
                new RealSingletonTokenBackend(cleanupContext);
        if (singleton.isActive()) {
            singleton.exit(cleanup);
            if (singleton.isActive()) {
                singleton.onServiceDestroyed(singleton.currentGeneration());
            }
        }
        String extra = generationExtraKey();
        FakeContext context = new FakeContext();
        RealSingletonTokenBackend backend = new RealSingletonTokenBackend(context);

        check(singleton.enter(backend), "service setup: enter accepted");
        long generation = singleton.currentGeneration();
        TestableService service = new TestableService();

        android.content.Intent intent = new android.content.Intent(
                context, VoiceModeForegroundService.class);
        intent.setAction(VoiceModeForegroundService.ACTION_START);
        intent.putExtra(extra, generation);
        int result = service.onStartCommand(intent, 0, 1);

        check(result == 2, "start command must stay non-sticky");
        check(singleton.isConfirmed(), "real start command must confirm");
        check(service.stopSelfCalls == 0, "accepted start must not stop itself");

        service.onDestroy();

        check(!singleton.isActive(), "real destroy must release");
        check(!singleton.isConfirmed(), "real destroy must clear");

        check(singleton.enter(backend), "service re-enter accepted");
        long second = singleton.currentGeneration();
        android.content.Intent stale = new android.content.Intent(
                context, VoiceModeForegroundService.class);
        stale.setAction(VoiceModeForegroundService.ACTION_START);
        stale.putExtra(extra, generation);
        service.onStartCommand(stale, 0, 2);

        check(singleton.isActive(), "stale start must not release the newer request");
        check(singleton.currentGeneration() == second, "newer token must survive");
        check(!singleton.isConfirmed(), "stale start must not confirm");

        android.content.Intent current = new android.content.Intent(
                context, VoiceModeForegroundService.class);
        current.setAction(VoiceModeForegroundService.ACTION_START);
        current.putExtra(extra, second);
        service.onStartCommand(current, 0, 3);
        check(singleton.isConfirmed(), "current start must confirm");

        int nullStops = service.stopSelfCalls;
        check(service.onStartCommand(null, 0, 4) == 2, "null intent stays non-sticky");
        check(service.stopSelfCalls == nullStops + 1, "null intent must stop itself");

        service.onDestroy();
        check(!singleton.isActive(), "final destroy must release");
    }

    private static final class NoopRouteBackend implements VoiceAudioRoute.Backend {
        @Override
        public int getMode() {
            return 0;
        }

        @Override
        public void setMode(int mode) {
        }

        @Override
        public boolean isSpeakerphoneOn() {
            return false;
        }

        @Override
        public void setSpeakerphoneOn(boolean on) {
        }

        @Override
        public boolean requestCommunicationFocus() {
            return true;
        }

        @Override
        public void abandonCommunicationFocus() {
        }

        @Override
        public boolean supportsCommunicationDevice() {
            return false;
        }

        @Override
        public Object getCommunicationDevice() {
            return null;
        }

        @Override
        public boolean setCommunicationDeviceToSpeaker() {
            return false;
        }

        @Override
        public void restoreCommunicationDevice(Object previous) {
        }

        @Override
        public void clearCommunicationDevice() {
        }

        @Override
        public boolean hasBluetoothAudio() {
            return false;
        }
    }

    private static final class NoopKeepAwakeBackend
            implements VoiceSessionKeepAwake.Backend {
        @Override
        public boolean setKeepScreenOn(boolean on) {
            return true;
        }
    }

    private static final class NoopMic
            implements VoiceModeSessionCoordinator.MicControl {
        @Override
        public void stopCapture() {
        }

        @Override
        public boolean isCapturing() {
            return false;
        }
    }

    private static final class NoopTts
            implements VoiceModeSessionCoordinator.TtsControl {
        @Override
        public void stopPlayback() {
        }

        @Override
        public boolean isSessionActive() {
            return false;
        }
    }

    private static final class NoopEvents
            implements VoiceModeSessionCoordinator.SessionEvents {
        @Override
        public void notifyPhoneCall(boolean active, long transitionId) {
        }

        @Override
        public void notifyNotificationStop(long transitionId) {
        }

        @Override
        public void evalJs(String script) {
        }
    }

    private static final class NoopPlatform
            implements VoiceModeSessionCoordinator.PlatformHooks {
        @Override
        public void requestBatteryExemption() {
        }

        @Override
        public void keepWebViewAlive() {
        }
    }

    private static void coordinatorExitFailureKeepsForeground() {
        FakeContext context = new FakeContext();
        context.stopResult = true;
        RealAdapterBackend backend = new RealAdapterBackend(context);
        VoiceModeForegroundSession foreground = new VoiceModeForegroundSession();
        VoiceModeSessionCoordinator coordinator = new VoiceModeSessionCoordinator(
                new VoiceAudioRoute(), new VoiceSessionKeepAwake(), foreground,
                new NoopRouteBackend(), new NoopKeepAwakeBackend(), backend,
                new NoopMic(), new NoopTts(), new NoopEvents(), new NoopPlatform());

        VoiceModeSessionCoordinator.EnterResult entered =
                coordinator.enterVoiceSession();
        check(entered.foreground, "coordinator setup: foreground accepted");
        foreground.onServiceConfirmed(foreground.currentGeneration());

        context.throwOnStop = true;
        VoiceModeSessionCoordinator.ExitResult exited =
                coordinator.exitVoiceSession();

        check(!exited.foreground, "coordinator must report foreground failure");
        check(exited.foregroundActive, "failed exit keeps foreground requested");
        check(exited.foregroundConfirmed, "failed exit keeps the confirmation");
        check(foreground.isActive(), "foreground stays requested after failure");
        check(foreground.isConfirmed(), "confirmation survives a failed stop");

        context.throwOnStop = false;
        VoiceModeSessionCoordinator.ExitResult retried =
                coordinator.exitVoiceSession();
        check(retried.foreground, "retry after failure must clear");
        check(!foreground.isActive(), "retry must release the request");
    }

    public static void main(String[] args) throws Exception {
        platformThrowKeepsSessionRequested();
        platformNullContextKeepsSessionRequested();
        alreadyStoppedClearsSession();
        successfulStopClearsSession();
        serviceDestroyClearsAndStaleDestroyKeepsNewer();
        staleStopDoesNotTouchNewerGeneration();
        coordinatorExitFailureKeepsForeground();
        singletonTokenThrowKeepsRequest();
        singletonTokenAlreadyStoppedClears();
        singletonTokenSuccessClears();
        interleavedStopDuringPlatformCallNeverKillsNewer();
        realServiceStartCommandAndDestroyOwnLifecycle();
        System.out.println("VoiceModeForegroundStopTest: all 12 behaviors passed");
    }
}
