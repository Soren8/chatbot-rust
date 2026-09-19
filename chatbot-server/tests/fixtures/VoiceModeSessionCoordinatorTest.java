import android.media.AudioManager;
import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.audio.VoiceModeSessionCoordinator;
import com.chatbot.app.audio.VoiceSessionKeepAwake;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure-Java characterization of VoiceModeSessionCoordinator with the real
 * resource classes. Each test owns fresh route/keep-awake/foreground
 * sessions; only backends, mic/TTS, events and platform are fakes.
 */
public final class VoiceModeSessionCoordinatorTest {
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void checkOrder(SharedLog log, String... sequence) {
        int cursor = -1;
        for (String step : sequence) {
            int next = -1;
            List<String> steps = log.snapshot();
            for (int i = cursor + 1; i < steps.size(); i++) {
                if (steps.get(i).equals(step)) {
                    next = i;
                    break;
                }
            }
            check(next > cursor, "expected order " + String.join(" -> ", sequence)
                    + " but missing " + step + " after index " + cursor + " in " + steps);
            cursor = next;
        }
    }

    private static final class SharedLog {
        private final List<String> steps = new ArrayList<>();

        synchronized void add(String step) {
            steps.add(step);
        }

        synchronized List<String> snapshot() {
            return new ArrayList<>(steps);
        }
    }

    private static final class FakeRouteBackend implements VoiceAudioRoute.Backend {
        final SharedLog log;
        boolean bluetooth;
        int mode = AudioManager.MODE_NORMAL;
        boolean speakerphone;
        int voiceVolume = 3;
        final int voiceMax = 7;
        Object commDevice;
        int hasBluetoothCalls;

        FakeRouteBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public int getMode() {
            return mode;
        }

        @Override
        public void setMode(int next) {
            log.add("route.setMode:" + next);
            mode = next;
        }

        @Override
        public boolean isSpeakerphoneOn() {
            return speakerphone;
        }

        @Override
        public void setSpeakerphoneOn(boolean on) {
            log.add("route.speaker:" + on);
            speakerphone = on;
        }

        @Override
        public int getVoiceCallVolume() {
            return voiceVolume;
        }

        @Override
        public int getVoiceCallMaxVolume() {
            return voiceMax;
        }

        @Override
        public void setVoiceCallVolume(int index) {
            log.add("route.volume:" + index);
            voiceVolume = index;
        }

        @Override
        public boolean requestCommunicationFocus() {
            log.add("route.focus.request");
            return true;
        }

        @Override
        public void abandonCommunicationFocus() {
            log.add("route.focus.abandon");
        }

        @Override
        public boolean supportsCommunicationDevice() {
            return true;
        }

        @Override
        public Object getCommunicationDevice() {
            return commDevice;
        }

        @Override
        public boolean setCommunicationDeviceToSpeaker() {
            log.add("route.comm.speaker");
            commDevice = "speaker";
            return true;
        }

        @Override
        public void restoreCommunicationDevice(Object previous) {
            log.add("route.comm.restore");
            commDevice = previous;
        }

        @Override
        public void clearCommunicationDevice() {
            log.add("route.comm.clear");
            commDevice = null;
        }

        @Override
        public boolean hasBluetoothAudio() {
            hasBluetoothCalls++;
            log.add("route.bluetooth:" + bluetooth);
            return bluetooth;
        }
    }

    private static final class FakeKeepAwakeBackend implements VoiceSessionKeepAwake.Backend {
        final SharedLog log;
        boolean keepOn;
        boolean available = true;
        int calls;

        FakeKeepAwakeBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public boolean setKeepScreenOn(boolean on) {
            calls++;
            log.add("keepAwake.set:" + on);
            if (!available) {
                return false;
            }
            keepOn = on;
            return true;
        }
    }

    private static final class FakeForegroundBackend implements VoiceModeForegroundSession.Backend {
        final SharedLog log;
        boolean running;
        boolean available = true;
        int startCalls;
        int stopCalls;

        FakeForegroundBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public boolean startForeground() {
            startCalls++;
            log.add("foreground.start");
            if (!available) {
                return false;
            }
            running = true;
            return true;
        }

        @Override
        public boolean stopForeground() {
            stopCalls++;
            log.add("foreground.stop");
            if (!available) {
                return false;
            }
            running = false;
            return true;
        }
    }

    private static final class FakeMic implements VoiceModeSessionCoordinator.MicControl {
        final SharedLog log;
        boolean capturing;
        int stops;

        FakeMic(SharedLog log) {
            this.log = log;
        }

        @Override
        public void stopCapture() {
            stops++;
            capturing = false;
            log.add("mic.stop");
        }

        @Override
        public boolean isCapturing() {
            return capturing;
        }
    }

    private static final class FakeTts implements VoiceModeSessionCoordinator.TtsControl {
        final SharedLog log;
        boolean active;
        int stops;

        FakeTts(SharedLog log) {
            this.log = log;
        }

        @Override
        public void stopPlayback() {
            stops++;
            active = false;
            log.add("tts.stop");
        }

        @Override
        public boolean isSessionActive() {
            return active;
        }
    }

    private static final class FakeEvents implements VoiceModeSessionCoordinator.SessionEvents {
        final SharedLog log;
        int phoneTrue;
        int phoneFalse;
        int stopNotified;
        final List<String> evals = new ArrayList<>();
        final List<Long> transitionIds = new ArrayList<>();

        FakeEvents(SharedLog log) {
            this.log = log;
        }

        @Override
        public void notifyPhoneCall(boolean active, long transitionId) {
            log.add("events.phone:" + active);
            transitionIds.add(transitionId);
            if (active) {
                phoneTrue++;
            } else {
                phoneFalse++;
            }
        }

        @Override
        public void notifyNotificationStop(long transitionId) {
            log.add("events.stop");
            transitionIds.add(transitionId);
            stopNotified++;
        }

        @Override
        public void evalJs(String script) {
            log.add("events.eval:" + script);
            evals.add(script);
        }
    }

    private static final class FakePlatform implements VoiceModeSessionCoordinator.PlatformHooks {
        final SharedLog log;
        int batteryCalls;
        int keepAliveCalls;

        FakePlatform(SharedLog log) {
            this.log = log;
        }

        @Override
        public void requestBatteryExemption() {
            batteryCalls++;
            log.add("platform.battery");
        }

        @Override
        public void keepWebViewAlive() {
            keepAliveCalls++;
            log.add("platform.keepAlive");
        }
    }

    private static final class Fixture {
        final SharedLog log = new SharedLog();
        final VoiceAudioRoute route = new VoiceAudioRoute();
        final VoiceSessionKeepAwake keepAwake = new VoiceSessionKeepAwake();
        final VoiceModeForegroundSession foreground = new VoiceModeForegroundSession();
        final FakeRouteBackend routeBackend = new FakeRouteBackend(log);
        final FakeKeepAwakeBackend keepAwakeBackend = new FakeKeepAwakeBackend(log);
        final FakeForegroundBackend foregroundBackend = new FakeForegroundBackend(log);
        final FakeMic mic = new FakeMic(log);
        final FakeTts tts = new FakeTts(log);
        final FakeEvents events = new FakeEvents(log);
        final FakePlatform platform = new FakePlatform(log);
        final VoiceModeSessionCoordinator coordinator = new VoiceModeSessionCoordinator(
                route, keepAwake, foreground,
                routeBackend, keepAwakeBackend, foregroundBackend,
                mic, tts, events, platform);
    }

    private static void enterComposesRouteKeepAwakeForegroundInOrder() {
        Fixture f = new Fixture();

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(result.applied, "route enter must apply without bluetooth");
        check(result.active, "route must be active after enter");
        check(!result.bluetooth, "bluetooth must be false");
        check(result.keepAwake, "keep-awake enter must apply");
        check(result.keepAwakeActive, "keep-awake must be active");
        check(result.foreground, "foreground enter must apply");
        check(result.foregroundActive, "foreground must be active");
        check(f.route.isActive(), "real route must be active");
        check(f.keepAwake.isActive(), "real keep-awake must be active");
        check(f.foreground.isActive(), "real foreground must be active");
        check(f.platform.batteryCalls == 1, "battery exemption must run once");
        check(f.platform.keepAliveCalls == 1, "webview keep-alive must run once");
        checkOrder(f.log,
                "route.bluetooth:false",
                "route.focus.request",
                "keepAwake.set:true",
                "foreground.start",
                "platform.battery",
                "platform.keepAlive");
    }

    private static void secondEnterDoesNotRetouchResourcesButRunsPlatformHooks() {
        Fixture f = new Fixture();

        check(f.coordinator.enterVoiceSession().applied, "first enter must apply");

        int setModesBefore = countPrefix(f.log, "route.setMode:");

        VoiceModeSessionCoordinator.EnterResult second = f.coordinator.enterVoiceSession();

        check(!second.applied, "second route enter must report applied=false");
        check(second.active, "route stays active after second enter");
        check(!second.keepAwake, "second keep-awake enter must report false");
        check(second.keepAwakeActive, "keep-awake stays active");
        check(!second.foreground, "second foreground enter must report false, not isActive()");
        check(second.foregroundActive, "foreground stays active");
        check(countPrefix(f.log, "route.setMode:") == setModesBefore,
                "second enter must not retouch AudioManager mode");
        check(f.platform.batteryCalls == 2, "platform battery hook runs even when already active");
        check(f.platform.keepAliveCalls == 2, "platform keep-alive runs even when already active");
    }

    private static void exitClearsPauseAndExitsRouteKeepAwakeForegroundInOrder() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        f.coordinator.pauseForPhoneCall();
        check(f.coordinator.isPausedForPhoneCall(), "pause must set the flag");
        // Pause releases the route, so re-enter to observe exit releasing
        // held resources in order while the pause flag is still set.
        f.mic.capturing = true;
        f.coordinator.enterVoiceSession();

        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();

        check(!f.coordinator.isPausedForPhoneCall(), "exit must clear the phone-call pause");
        check(result.applied, "exit must report applied when route was active");
        check(!result.active, "route must be inactive after exit");
        check(result.keepAwake, "keep-awake exit must apply");
        check(!result.keepAwakeActive, "keep-awake must be inactive");
        check(!result.foregroundActive, "foreground must be inactive after exit");
        checkOrder(f.log, "route.focus.abandon", "keepAwake.set:false", "foreground.stop");
    }

    private static void exitWithoutEnterIsNoop() {
        Fixture f = new Fixture();

        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();

        check(!result.applied, "idle exit must report applied=false");
        check(!result.active, "idle exit stays inactive");
        check(!result.keepAwake, "idle keep-awake exit must be noop");
        check(!result.foreground, "idle foreground exit must be noop");
        check(f.events.phoneTrue == 0 && f.events.phoneFalse == 0,
                "idle exit must not emit phone events");
        check(f.events.stopNotified == 0, "idle exit must not emit stop events");
        check(f.tts.stops == 0 && f.mic.stops == 0, "idle exit must not stop mic or TTS");
    }

    private static void pauseWhenIdleIsNoop() {
        Fixture f = new Fixture();

        boolean paused = f.coordinator.pauseForPhoneCall();

        check(!paused, "idle pause must report false");
        check(!f.coordinator.isPausedForPhoneCall(), "idle pause must not set the flag");
        check(f.tts.stops == 0, "idle pause must not stop TTS");
        check(f.mic.stops == 0, "idle pause must not stop mic");
        check(f.events.phoneTrue == 0, "idle pause must not notify");
        check(f.events.evals.isEmpty(), "idle pause must not eval JS");
    }

    private static void pauseWhenRouteActiveStopsTtsThenMicThenExitsThenNotifies() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.tts.active = true;
        f.mic.capturing = true;

        boolean paused = f.coordinator.pauseForPhoneCall();

        check(paused, "active pause must report true");
        check(f.coordinator.isPausedForPhoneCall(), "pause must set the flag");
        check(!f.route.isActive(), "pause must release the route");
        check(!f.keepAwake.isActive(), "pause must release keep-awake");
        check(!f.foreground.isActive(), "pause must release the FGS");
        check(f.events.phoneTrue == 1, "pause must notify phone active once");
        long pauseId = f.events.transitionIds.get(0);
        check(f.events.evals.size() == 1
                && f.events.evals.get(0).equals(VoiceModeSessionCoordinator.pauseScript(pauseId)),
                "pause must eval the pause script carrying the transition ID");
        check(f.events.transitionIds.size() == 1,
                "pause emits one transition ID");
        checkOrder(f.log,
                "tts.stop",
                "mic.stop",
                "route.focus.abandon",
                "keepAwake.set:false",
                "foreground.stop",
                "events.phone:true",
                "events.eval:" + VoiceModeSessionCoordinator.pauseScript(pauseId));
    }

    private static void pauseWhenOnlyMicCapturingStillPauses() {
        Fixture f = new Fixture();
        f.mic.capturing = true;

        boolean paused = f.coordinator.pauseForPhoneCall();

        check(paused, "mic-only capture must still pause for the call");
        check(f.tts.stops == 1, "pause must stop TTS even without route");
        check(f.mic.stops == 1, "pause must stop mic capture");
        check(f.events.phoneTrue == 1, "pause must notify");
    }

    private static void secondPauseIsNoop() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.pauseForPhoneCall(), "first pause must act");

        int stops = f.tts.stops + f.mic.stops;
        boolean again = f.coordinator.pauseForPhoneCall();

        check(!again, "second pause must report false");
        check(f.tts.stops + f.mic.stops == stops, "second pause must not stop again");
        check(f.events.phoneTrue == 1, "second pause must not notify again");
    }

    private static void resumeWithoutPauseIsNoop() {
        Fixture f = new Fixture();

        boolean resumed = f.coordinator.resumeAfterPhoneCall();

        check(!resumed, "resume without pause must report false");
        check(f.events.phoneFalse == 0, "noop resume must not notify");
        check(f.events.evals.isEmpty(), "noop resume must not eval");
    }

    private static void resumeAfterPauseNotifiesWithoutReenteringResources() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.pauseForPhoneCall(), "setup pause must act");
        int foregroundStarts = f.foregroundBackend.startCalls;

        boolean resumed = f.coordinator.resumeAfterPhoneCall();

        check(resumed, "resume must report true after pause");
        check(!f.coordinator.isPausedForPhoneCall(), "resume must clear the flag");
        check(f.events.phoneFalse == 1, "resume must notify phone inactive");
        check(f.events.transitionIds.size() == 2
                && f.events.transitionIds.get(1) > f.events.transitionIds.get(0),
                "resume carries a newer transition ID than pause");
        check(f.events.evals.size() == 2
                && f.events.evals.get(1).equals(VoiceModeSessionCoordinator.resumeScript(
                        f.events.transitionIds.get(1))),
                "resume must eval the resume script carrying its own transition ID");
        check(!f.route.isActive(), "resume must not re-enter the route");
        check(!f.keepAwake.isActive(), "resume must not re-enter keep-awake");
        check(!f.foreground.isActive(), "resume must not restart the FGS");
        check(f.foregroundBackend.startCalls == foregroundStarts,
                "resume must not start the FGS again");
        long resumeId = f.events.transitionIds.get(1);
        checkOrder(f.log,
                "events.phone:false",
                "events.eval:" + VoiceModeSessionCoordinator.resumeScript(resumeId));
    }

    private static void notificationStopEvalsThenNotifiesThenStopsThenExits() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.tts.active = true;
        f.mic.capturing = true;

        f.coordinator.notificationStop();

        check(f.events.evals.size() == 1
                && f.events.evals.get(0).equals(
                        VoiceModeSessionCoordinator.notificationStopScript(
                                f.events.transitionIds.get(0))),
                "notification stop must eval stopVoiceMode carrying the transition ID");
        check(f.events.stopNotified == 1, "notification stop must notify once");
        check(!f.route.isActive(), "notification stop must release the route");
        check(!f.keepAwake.isActive(), "notification stop must release keep-awake");
        check(!f.foreground.isActive(), "notification stop must release the FGS");
        long stopId = f.events.transitionIds.get(0);
        checkOrder(f.log,
                "events.eval:" + VoiceModeSessionCoordinator.notificationStopScript(stopId),
                "events.stop",
                "tts.stop",
                "mic.stop",
                "route.focus.abandon",
                "keepAwake.set:false",
                "foreground.stop");
    }

    private static void notificationStopWhenIdleStillEvalsAndNotifies() {
        Fixture f = new Fixture();

        f.coordinator.notificationStop();

        check(f.events.stopNotified == 1, "idle notification stop must still notify");
        check(f.events.evals.size() == 1
                && f.events.evals.get(0).equals(
                        VoiceModeSessionCoordinator.notificationStopScript(
                                f.events.transitionIds.get(0))),
                "idle notification stop must still eval JS with the transition ID");
        check(f.tts.stops == 1 && f.mic.stops == 1,
                "idle notification stop still stops TTS/mic before exiting");
    }

    private static void destroyStopsMicNotTtsAndExitsWithoutEvents() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.tts.active = true;
        f.mic.capturing = true;

        f.coordinator.destroy();

        check(!f.coordinator.isPausedForPhoneCall(), "destroy must clear the pause flag");
        check(f.mic.stops == 1, "destroy must stop mic capture");
        check(f.tts.stops == 0, "destroy must not stop TTS (TTS plugin destroys itself)");
        check(!f.route.isActive(), "destroy must release the route");
        check(!f.keepAwake.isActive(), "destroy must release keep-awake");
        check(!f.foreground.isActive(), "destroy must release the FGS");
        check(f.events.phoneTrue == 0 && f.events.phoneFalse == 0,
                "destroy must not emit phone events");
        check(f.events.stopNotified == 0, "destroy must not emit stop events");
        check(f.events.evals.isEmpty(), "destroy must not eval JS");
    }

    private static void audioRouteChangedPausesInCallAndResumesAfter() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;

        f.coordinator.onAudioRouteChanged(true);

        check(f.coordinator.isPausedForPhoneCall(), "in-call route change must pause");
        check(f.events.phoneTrue == 1, "in-call change must notify");

        f.coordinator.onAudioRouteChanged(false);

        check(!f.coordinator.isPausedForPhoneCall(), "off-call change must resume");
        check(f.events.phoneFalse == 1, "off-call change must notify");
        check(!f.route.isActive(), "resume must not re-enter resources");
    }

    private static void audioRouteChangedOffCallWhenIdleIsNoop() {
        Fixture f = new Fixture();

        f.coordinator.onAudioRouteChanged(false);

        check(f.events.phoneTrue == 0 && f.events.phoneFalse == 0,
                "off-call change when idle must not notify");
        check(f.tts.stops == 0 && f.mic.stops == 0, "idle route change must not stop audio");
    }

    private static void enterWithBluetoothSkipsRouteButHoldsKeepAwakeAndForeground() {
        Fixture f = new Fixture();
        f.routeBackend.bluetooth = true;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(!result.applied, "bluetooth enter must report applied=false");
        check(!result.active, "route must stay inactive on bluetooth");
        check(result.bluetooth, "bluetooth flag must be true");
        check(result.keepAwake && result.keepAwakeActive,
                "keep-awake must still enter on bluetooth");
        check(result.foreground && result.foregroundActive,
                "FGS must still enter on bluetooth");
        check(!f.route.isActive(), "real route must stay inactive");
        check(f.keepAwake.isActive(), "keep-awake must be active");
        check(f.foreground.isActive(), "foreground must be active");
    }

    private static void enterWithForegroundFailureKeepsPartialEnter() {
        Fixture f = new Fixture();
        f.foregroundBackend.available = false;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(result.applied, "route still applies when the FGS fails");
        check(result.active, "route stays active after FGS failure");
        check(result.keepAwake && result.keepAwakeActive, "keep-awake stays entered");
        check(!result.foreground, "foreground must report false when start fails");
        check(!result.foregroundActive, "foreground must stay inactive when start fails");
        check(f.route.isActive(), "no rollback: route stays held");
        check(f.keepAwake.isActive(), "no rollback: keep-awake stays held");
    }

    private static void exitFailureKeepsSessionMarkedActive() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().applied, "setup enter must apply");
        f.keepAwakeBackend.available = false;

        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();

        check(!result.keepAwake, "failed keep-awake exit must report false");
        check(result.keepAwakeActive, "failed exit keeps keep-awake marked active");
        check(!result.active, "route exit still applies");
        check(!result.foregroundActive, "foreground exit still applies");
    }

    private static void exitClearsPauseSetByPhoneCall() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.pauseForPhoneCall(), "setup pause must act");

        f.coordinator.exitVoiceSession();

        check(!f.coordinator.isPausedForPhoneCall(), "exit must clear the pause flag");
        check(!f.coordinator.resumeAfterPhoneCall(),
                "resume after exit must be a noop");
        check(f.events.phoneFalse == 0, "exit must not emit the resume event");
    }

    private static void foregroundRequestIsUnconfirmedUntilServiceConfirms() {
        Fixture f = new Fixture();

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(result.foreground, "foreground request must be accepted");
        check(result.foregroundActive, "foreground stays requested after enter");
        check(!result.foregroundConfirmed, "platform confirmation is async; enter must not claim it");
        check(f.foreground.isActive(), "session stays requested after enter");
        check(!f.foreground.isConfirmed(), "request acceptance is not platform confirmation");
        check(!f.coordinator.isForegroundConfirmed(), "coordinator must not report confirmed yet");

        f.foreground.onServiceConfirmed(f.foreground.currentGeneration());

        check(f.foreground.isConfirmed(), "matching service confirmation must confirm the session");
        check(f.coordinator.isForegroundConfirmed(), "coordinator must expose the confirmed state");
    }

    private static void promotionFailureClearsRequestAndAllowsRetry() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long generation = f.foreground.currentGeneration();

        f.foreground.onServiceStartFailed(generation);

        check(!f.foreground.isActive(), "promotion failure must release the request");
        check(!f.foreground.isConfirmed(), "promotion failure must never confirm");
        check(!f.coordinator.isForegroundConfirmed(), "coordinator must not report confirmed");

        VoiceModeSessionCoordinator.EnterResult retry = f.coordinator.enterVoiceSession();
        check(retry.foreground, "retry after promotion failure must be accepted");
        check(f.foreground.currentGeneration() != generation,
                "retry must mint a fresh request generation");
        check(!f.foreground.isConfirmed(), "retry starts unconfirmed");
    }

    private static void backendStartFailureStaysUnrequestedAndRetryable() {
        Fixture f = new Fixture();
        f.foregroundBackend.available = false;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(!result.foreground, "failed request must report false");
        check(!result.foregroundActive, "failed request must not mark requested");
        check(!result.foregroundConfirmed, "failed request must not claim confirmation");
        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "failed startup leaves no session state");

        f.foregroundBackend.available = true;
        check(f.coordinator.enterVoiceSession().foreground,
                "retry after failed startup must be accepted");
    }

    private static void staleConfirmationAfterStopIsIgnored() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long generation = f.foreground.currentGeneration();
        f.coordinator.exitVoiceSession();

        f.foreground.onServiceConfirmed(generation);

        check(!f.foreground.isActive(), "late confirm must not re-request the session");
        check(!f.foreground.isConfirmed(), "late confirm after stop must stay unconfirmed");
        check(!f.coordinator.isForegroundConfirmed(), "coordinator must stay unconfirmed");
    }

    private static void wrongGenerationConfirmationIsIgnored() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long generation = f.foreground.currentGeneration();

        f.foreground.onServiceConfirmed(generation + 1);

        check(f.foreground.isActive(), "stale generation must not release the request");
        check(!f.foreground.isConfirmed(), "wrong-generation confirm must stay unconfirmed");
        check(!f.coordinator.isForegroundConfirmed(), "coordinator must stay unconfirmed");
    }

    private static void repeatedEnterKeepsSingleRequest() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "first request must be accepted");
        long generation = f.foreground.currentGeneration();

        VoiceModeSessionCoordinator.EnterResult second = f.coordinator.enterVoiceSession();

        check(!second.foreground, "second enter while requested must report false");
        check(second.foregroundActive, "session stays requested after repeat enter");
        check(f.foreground.currentGeneration() == generation,
                "repeat enter must not mint a new request token");

        f.foreground.onServiceConfirmed(generation + 1);
        check(!f.foreground.isConfirmed(), "no new token exists for a stale confirm to hit");
        f.foreground.onServiceConfirmed(generation);
        check(f.foreground.isConfirmed(), "the original token still confirms");
    }

    private static void exitAfterConfirmClearsConfirmation() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        f.foreground.onServiceConfirmed(f.foreground.currentGeneration());
        check(f.foreground.isConfirmed(), "setup must be confirmed");

        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();

        check(!result.foregroundActive, "exit must release the request");
        check(!result.foregroundConfirmed, "exit must clear the confirmation");
        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "confirmation must not survive exit");
        check(f.coordinator.enterVoiceSession().foreground,
                "re-enter after stop must be accepted");
    }

    private static void destroyClearsConfirmation() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        f.foreground.onServiceConfirmed(f.foreground.currentGeneration());
        check(f.foreground.isConfirmed(), "setup must be confirmed");

        f.coordinator.destroy();

        check(!f.foreground.isActive(), "destroy must release the request");
        check(!f.foreground.isConfirmed(), "destroy must clear the confirmation");
        check(f.coordinator.enterVoiceSession().foreground,
                "re-enter after destroy must be accepted");
    }

    private static void doubleConfirmIsASingleTransition() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long generation = f.foreground.currentGeneration();

        f.foreground.onServiceConfirmed(generation);
        f.foreground.onServiceConfirmed(generation);

        check(f.foreground.isConfirmed(), "repeat confirm keeps the single confirmed state");
        check(f.foreground.isActive(), "repeat confirm must not release the request");
    }

    private static void serviceDestroyClearsRequestedAndConfirmed() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        f.foreground.onServiceConfirmed(f.foreground.currentGeneration());
        check(f.foreground.isConfirmed(), "setup must be confirmed");

        f.foreground.onServiceDestroyed(f.foreground.currentGeneration());

        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "service destroy clears requested and confirmed");
        check(f.coordinator.enterVoiceSession().foreground,
                "re-enter after service destroy must be accepted");
    }

    private static void repeatEnterWhileConfirmedReportsLiveSnapshot() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        f.foreground.onServiceConfirmed(f.foreground.currentGeneration());
        check(f.foreground.isConfirmed(), "setup must be confirmed");

        VoiceModeSessionCoordinator.EnterResult second = f.coordinator.enterVoiceSession();

        check(!second.foreground, "repeat enter while requested must report false");
        check(second.foregroundActive, "session stays requested after repeat enter");
        check(second.foregroundConfirmed,
                "confirmed flag must reflect the live snapshot, not a hardcoded false");
    }

    private static void staleServiceDestroyKeepsNewerRequest() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long first = f.foreground.currentGeneration();
        f.foreground.onServiceConfirmed(first);
        f.coordinator.exitVoiceSession();
        check(f.coordinator.enterVoiceSession().foreground, "re-enter must be accepted");
        long second = f.foreground.currentGeneration();
        check(second != first, "re-enter must mint a fresh token");

        f.foreground.onServiceDestroyed(first);

        check(f.foreground.isActive(), "stale destroy must not release the newer request");
        check(f.foreground.currentGeneration() == second, "newer token must survive");
        check(!f.foreground.isConfirmed(), "newer request is still unconfirmed");
        f.foreground.onServiceConfirmed(second);
        check(f.foreground.isConfirmed(), "newer token still confirms after stale destroy");
        f.foreground.onServiceDestroyed(second);
        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "current destroy clears the newer request");
    }

    private static void destroyWithUnknownGenerationClearsNothing() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long generation = f.foreground.currentGeneration();

        f.foreground.onServiceDestroyed(-1L);

        check(f.foreground.isActive(), "unattributed destroy must not release the request");
        f.foreground.onServiceConfirmed(generation);
        check(f.foreground.isConfirmed(), "attributed confirm still applies afterwards");
    }

    private static void exitReconcilesAgainstTokenAfterInterleavedReenter() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        final VoiceModeForegroundSession session = f.foreground;
        final long first = session.currentGeneration();
        VoiceModeForegroundSession.Backend interleaving = new VoiceModeForegroundSession.Backend() {
            @Override
            public boolean startForeground() {
                return true;
            }

            @Override
            public boolean stopForeground() {
                session.onServiceDestroyed(first);
                session.enter(f.foregroundBackend);
                return true;
            }
        };

        boolean released = session.exit(interleaving);

        check(!released, "a superseded exit no longer owns the session");
        check(session.isActive(), "the newer request survives the old exit");
        check(session.currentGeneration() != first, "re-enter minted a fresh token");
        session.onServiceConfirmed(session.currentGeneration());
        check(session.isConfirmed(), "the newer token confirms");
    }

    private static void backendReceivesReservedToken() {
        Fixture f = new Fixture();
        final long[] seen = {-1L};
        VoiceModeForegroundSession.Backend tokenBackend = new VoiceModeForegroundSession.Backend() {
            @Override
            public boolean startForeground() {
                return true;
            }

            @Override
            public boolean startForeground(long generation) {
                seen[0] = generation;
                return true;
            }

            @Override
            public boolean stopForeground() {
                return true;
            }
        };

        check(f.foreground.enter(tokenBackend), "token request must be accepted");

        check(seen[0] != -1L, "enter must use the token overload");
        check(seen[0] == f.foreground.currentGeneration(),
                "backend must receive the reserved token, not a call-time re-read");
    }

    private static void eventTransitionIdsIncreaseAcrossPauseResumeStop() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.pauseForPhoneCall(), "setup pause must act");
        check(f.coordinator.resumeAfterPhoneCall(), "setup resume must act");
        f.coordinator.notificationStop();

        check(f.events.transitionIds.size() == 3,
                "one transition ID per pause/resume/stop event");
        check(f.events.transitionIds.get(0) < f.events.transitionIds.get(1)
                && f.events.transitionIds.get(1) < f.events.transitionIds.get(2),
                "transition IDs must increase monotonically, got " + f.events.transitionIds);
        check(f.events.evals.get(0).equals(
                VoiceModeSessionCoordinator.pauseScript(f.events.transitionIds.get(0))),
                "pause eval must carry its own transition ID");
        check(f.events.evals.get(1).equals(
                VoiceModeSessionCoordinator.resumeScript(f.events.transitionIds.get(1))),
                "resume eval must carry its own transition ID");
        check(f.events.evals.get(2).equals(
                VoiceModeSessionCoordinator.notificationStopScript(f.events.transitionIds.get(2))),
                "stop eval must carry its own transition ID");
    }

    private static void transitionIdsIncreaseAcrossCoordinatorInstances() {
        Fixture first = new Fixture();
        Fixture second = new Fixture();
        first.coordinator.enterVoiceSession();
        first.mic.capturing = true;
        check(first.coordinator.pauseForPhoneCall(), "first instance pause must act");
        second.coordinator.enterVoiceSession();
        second.mic.capturing = true;
        check(second.coordinator.pauseForPhoneCall(), "second instance pause must act");

        long firstId = first.events.transitionIds.get(0);
        long secondId = second.events.transitionIds.get(0);

        check(secondId > firstId,
                "a recreated coordinator must not restart IDs or the page gate ignores its events");
    }

    private static void staleStartPreservesBoundTokenUntilRealDestroy() {
        Fixture f = new Fixture();
        VoiceModeForegroundSession.ServiceLifecycle lifecycle =
                new VoiceModeForegroundSession.ServiceLifecycle(f.foreground);
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long current = f.foreground.currentGeneration();

        check(lifecycle.onStarted(current, true)
                        == VoiceModeForegroundSession.ServiceLifecycle.StartOutcome.ACQUIRE,
                "start for the current token acquires");
        check(f.foreground.isConfirmed(), "current token confirmed");
        check(lifecycle.onStarted(current - 1, true)
                        == VoiceModeForegroundSession.ServiceLifecycle.StartOutcome.IGNORE_STALE,
                "delayed stale start must not acquire");
        check(f.foreground.isConfirmed(), "stale start keeps the current confirmation");
        lifecycle.onDestroyed();
        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "destroy after a stale start still clears the owned token");
    }

    private static void orphanStartReleasesWithoutAcquiring() {
        Fixture f = new Fixture();
        VoiceModeForegroundSession.ServiceLifecycle lifecycle =
                new VoiceModeForegroundSession.ServiceLifecycle(f.foreground);
        check(f.coordinator.enterVoiceSession().foreground, "setup request must be accepted");
        long current = f.foreground.currentGeneration();
        f.coordinator.exitVoiceSession();

        check(lifecycle.onStarted(current, true)
                        == VoiceModeForegroundSession.ServiceLifecycle.StartOutcome.RELEASE_ORPHAN,
                "late start with nobody owning the session must release, not acquire");
        check(!f.foreground.isActive() && !f.foreground.isConfirmed(),
                "orphan start leaves no session state");
    }

    private static int countPrefix(SharedLog log, String prefix) {
        int count = 0;
        for (String step : log.snapshot()) {
            if (step.startsWith(prefix)) {
                count++;
            }
        }
        return count;
    }

    public static void main(String[] args) {
        enterComposesRouteKeepAwakeForegroundInOrder();
        secondEnterDoesNotRetouchResourcesButRunsPlatformHooks();
        exitClearsPauseAndExitsRouteKeepAwakeForegroundInOrder();
        exitWithoutEnterIsNoop();
        pauseWhenIdleIsNoop();
        pauseWhenRouteActiveStopsTtsThenMicThenExitsThenNotifies();
        pauseWhenOnlyMicCapturingStillPauses();
        secondPauseIsNoop();
        resumeWithoutPauseIsNoop();
        resumeAfterPauseNotifiesWithoutReenteringResources();
        notificationStopEvalsThenNotifiesThenStopsThenExits();
        notificationStopWhenIdleStillEvalsAndNotifies();
        destroyStopsMicNotTtsAndExitsWithoutEvents();
        audioRouteChangedPausesInCallAndResumesAfter();
        audioRouteChangedOffCallWhenIdleIsNoop();
        enterWithBluetoothSkipsRouteButHoldsKeepAwakeAndForeground();
        enterWithForegroundFailureKeepsPartialEnter();
        exitFailureKeepsSessionMarkedActive();
        exitClearsPauseSetByPhoneCall();
        foregroundRequestIsUnconfirmedUntilServiceConfirms();
        promotionFailureClearsRequestAndAllowsRetry();
        backendStartFailureStaysUnrequestedAndRetryable();
        staleConfirmationAfterStopIsIgnored();
        wrongGenerationConfirmationIsIgnored();
        repeatedEnterKeepsSingleRequest();
        exitAfterConfirmClearsConfirmation();
        destroyClearsConfirmation();
        doubleConfirmIsASingleTransition();
        serviceDestroyClearsRequestedAndConfirmed();
        repeatEnterWhileConfirmedReportsLiveSnapshot();
        staleServiceDestroyKeepsNewerRequest();
        destroyWithUnknownGenerationClearsNothing();
        exitReconcilesAgainstTokenAfterInterleavedReenter();
        backendReceivesReservedToken();
        eventTransitionIdsIncreaseAcrossPauseResumeStop();
        transitionIdsIncreaseAcrossCoordinatorInstances();
        staleStartPreservesBoundTokenUntilRealDestroy();
        orphanStartReleasesWithoutAcquiring();
        System.out.println("VoiceModeSessionCoordinatorTest: all 38 behaviors passed");
    }
}
