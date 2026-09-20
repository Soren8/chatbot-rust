import android.media.AudioManager;
import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.audio.VoiceModeSessionCoordinator;
import com.chatbot.app.audio.VoiceModeVolumeSession;
import com.chatbot.app.audio.VoiceSessionKeepAwake;
import java.util.ArrayList;
import java.util.List;

/**
 * Volume keys must drive the music stream TTS plays on, foreground and
 * background/locked, through the owned voice-mode session.
 *
 * <p>Drives the real {@link VoiceModeVolumeSession} and the real {@link
 * VoiceModeSessionCoordinator} with fake platform backends. String checks
 * alone cannot prove the keys reach music: every behavior below executes the
 * production owner/adapter composition.
 */
public final class VoiceModeVolumeSessionTest {
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
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

    private static final class FakeVolumeBackend implements VoiceModeVolumeSession.Backend {
        final SharedLog log;
        int musicMax = 15;
        int musicVolume = 5;
        int providerVolume = 5;
        boolean available = true;
        int createCalls;
        int releaseCalls;
        int getMaxCalls;
        int getVolumeCalls;
        final List<Integer> adjusts = new ArrayList<>();
        final List<Integer> sets = new ArrayList<>();
        final List<Integer> providerSyncs = new ArrayList<>();
        VolumeCallback callback;
        long boundGeneration = -1;
        boolean captureOnFailure;
        VolumeCallback lastCallback;
        long lastGeneration = -1;

        FakeVolumeBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public int getMusicMaxVolume() {
            getMaxCalls++;
            return musicMax;
        }

        @Override
        public int getMusicVolume() {
            getVolumeCalls++;
            return musicVolume;
        }

        @Override
        public boolean createRemoteVolumeSession(
                int maxVolume, int currentVolume, long generation, VolumeCallback cb) {
            createCalls++;
            log.add("volume.create:" + maxVolume + ":" + currentVolume + ":" + generation);
            if (!available || cb == null) {
                if (captureOnFailure && cb != null) {
                    callback = cb;
                    boundGeneration = generation;
                    lastCallback = cb;
                    lastGeneration = generation;
                }
                return false;
            }
            callback = cb;
            boundGeneration = generation;
            providerVolume = currentVolume;
            return true;
        }

        @Override
        public void setProviderVolume(int current) {
            providerSyncs.add(current);
            providerVolume = current;
            log.add("volume.provider:" + current);
        }

        @Override
        public void adjustMusicVolume(int direction) {
            adjusts.add(direction);
            log.add("volume.adjust:" + direction);
            musicVolume = Math.max(0, Math.min(musicMax, musicVolume + direction));
        }

        @Override
        public void setMusicVolume(int index) {
            sets.add(index);
            log.add("volume.set:" + index);
            musicVolume = Math.max(0, Math.min(musicMax, index));
        }

        @Override
        public void releaseVolumeSession() {
            releaseCalls++;
            log.add("volume.release");
            callback = null;
        }

        boolean pressKey(int direction) {
            if (callback == null) {
                throw new AssertionError("no provider callback to receive the key");
            }
            return callback.onAdjustVolume(direction, boundGeneration);
        }

        boolean dragSlider(int volume) {
            if (callback == null) {
                throw new AssertionError("no provider callback to receive the slider");
            }
            return callback.onSetVolumeTo(volume, boundGeneration);
        }
    }

    private static final class FakeRouteBackend implements VoiceAudioRoute.Backend {
        final SharedLog log;
        boolean bluetooth;
        int mode = AudioManager.MODE_NORMAL;
        boolean speakerphone;
        Object commDevice;

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
            log.add("route.bluetooth:" + bluetooth);
            return bluetooth;
        }
    }

    private static final class FakeKeepAwakeBackend implements VoiceSessionKeepAwake.Backend {
        final SharedLog log;
        boolean keepOn;
        boolean available = true;

        FakeKeepAwakeBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public boolean setKeepScreenOn(boolean on) {
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

        FakeForegroundBackend(SharedLog log) {
            this.log = log;
        }

        @Override
        public boolean startForeground() {
            log.add("foreground.start");
            if (!available) {
                return false;
            }
            running = true;
            return true;
        }

        @Override
        public boolean stopForeground() {
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

        FakeMic(SharedLog log) {
            this.log = log;
        }

        @Override
        public void stopCapture() {
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

        FakeTts(SharedLog log) {
            this.log = log;
        }

        @Override
        public void stopPlayback() {
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

        FakeEvents(SharedLog log) {
            this.log = log;
        }

        @Override
        public void notifyPhoneCall(boolean active, long transitionId) {
            log.add("events.phone:" + active);
            if (active) {
                phoneTrue++;
            } else {
                phoneFalse++;
            }
        }

        @Override
        public void notifyNotificationStop(long transitionId) {
            log.add("events.stop");
            stopNotified++;
        }

        @Override
        public void evalJs(String script) {
            log.add("events.eval");
        }
    }

    private static final class FakePlatform implements VoiceModeSessionCoordinator.PlatformHooks {
        final SharedLog log;

        FakePlatform(SharedLog log) {
            this.log = log;
        }

        @Override
        public void requestBatteryExemption() {
            log.add("platform.battery");
        }

        @Override
        public void keepWebViewAlive() {
            log.add("platform.keepAlive");
        }
    }

    private static final class Fixture {
        final SharedLog log = new SharedLog();
        final VoiceAudioRoute route = new VoiceAudioRoute();
        final VoiceSessionKeepAwake keepAwake = new VoiceSessionKeepAwake();
        final VoiceModeForegroundSession foreground = new VoiceModeForegroundSession();
        final VoiceModeVolumeSession volume = new VoiceModeVolumeSession();
        final FakeRouteBackend routeBackend = new FakeRouteBackend(log);
        final FakeKeepAwakeBackend keepAwakeBackend = new FakeKeepAwakeBackend(log);
        final FakeForegroundBackend foregroundBackend = new FakeForegroundBackend(log);
        final FakeVolumeBackend volumeBackend = new FakeVolumeBackend(log);
        final FakeMic mic = new FakeMic(log);
        final FakeTts tts = new FakeTts(log);
        final FakeEvents events = new FakeEvents(log);
        final FakePlatform platform = new FakePlatform(log);
        final VoiceModeSessionCoordinator coordinator = new VoiceModeSessionCoordinator(
                route, keepAwake, foreground, volume,
                routeBackend, keepAwakeBackend, foregroundBackend, volumeBackend,
                mic, tts, events, platform);
    }

    private static void enterSeedsProviderFromMusicWithoutWriting() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);

        check(session.enter(backend), "volume enter must apply");
        check(session.isActive(), "volume must be active after enter");
        check(backend.createCalls == 1, "enter must create one remote session");
        check(backend.adjusts.isEmpty() && backend.sets.isEmpty(),
                "enter must never write a stream level");
        check(backend.providerVolume == backend.musicVolume,
                "provider display must seed from the live music level");

        check(!session.enter(backend), "second enter must report false");
        check(backend.createCalls == 1, "second enter must not create again");
    }

    private static void keysForwardToMusicAndResyncDisplay() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        check(session.enter(backend), "setup enter must apply");
        long gen = session.currentGeneration();

        check(session.onAdjustVolume(1, gen), "key up must be handled");
        check(backend.adjusts.size() == 1 && backend.adjusts.get(0) == 1,
                "key up must adjust music by +1");
        check(backend.musicVolume == 6, "music must move 5 -> 6, got " + backend.musicVolume);
        check(backend.providerVolume == 6, "provider display must resync to 6");

        check(session.onAdjustVolume(-1, gen), "key down must be handled");
        check(backend.musicVolume == 5, "music must move back to 5");
        check(backend.providerVolume == 5, "provider display must resync to 5");
        check(backend.sets.isEmpty(), "keys must not use absolute sets");
    }

    private static void sliderForwardsToMusicAndResyncs() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        check(session.enter(backend), "setup enter must apply");
        long gen = session.currentGeneration();

        check(session.onSetVolumeTo(10, gen), "slider must be handled");
        check(backend.sets.size() == 1 && backend.sets.get(0) == 10,
                "slider must set music to 10");
        check(backend.musicVolume == 10, "music must be 10");
        check(backend.providerVolume == 10, "provider display must resync to 10");
    }

    private static void staleCallbacksAfterExitDoNotTouchPlatform() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        check(session.enter(backend), "setup enter must apply");
        long gen = session.currentGeneration();
        check(session.exit(backend), "setup exit must release");
        int adjusts = backend.adjusts.size();
        int sets = backend.sets.size();

        check(!session.onAdjustVolume(1, gen), "stale key after exit must be ignored");
        check(!session.onSetVolumeTo(10, gen), "stale slider after exit must be ignored");
        check(backend.adjusts.size() == adjusts && backend.sets.size() == sets,
                "stale callbacks must not touch the platform");
    }

    private static void staleGenerationAfterReplacementIsIgnored() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        check(session.enter(backend), "first enter must apply");
        long first = session.currentGeneration();
        check(session.exit(backend), "exit must release");
        check(session.enter(backend), "replacement enter must apply");
        long second = session.currentGeneration();
        check(second != first, "replacement must mint a fresh generation");

        check(!session.onAdjustVolume(1, first), "old generation key must be ignored");
        check(backend.adjusts.isEmpty(), "stale key must not touch music");
        check(session.onAdjustVolume(1, second), "current generation key must be handled");
        check(backend.adjusts.size() == 1, "current key must reach music");
    }

    private static void exitWithoutEnterIsNoop() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);

        check(!session.exit(backend), "idle exit must report false");
        check(backend.releaseCalls == 0, "idle exit must not touch the platform");
    }

    private static void failedCreateStaysInactiveAndRetryable() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        backend.available = false;

        check(!session.enter(backend), "failed create must report false");
        check(!session.isActive(), "failed create must stay inactive");

        backend.available = true;
        check(session.enter(backend), "retry after failure must apply");
        check(session.isActive(), "retry must hold the session");
        check(backend.adjusts.isEmpty() && backend.sets.isEmpty(),
                "failed enter must never write a level");
    }

    private static void failedAttemptGenerationIsConsumed() {
        SharedLog log = new SharedLog();
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        FakeVolumeBackend backend = new FakeVolumeBackend(log);
        backend.available = false;
        backend.captureOnFailure = true;

        check(!session.enter(backend), "failed create must report false");
        check(backend.lastCallback != null, "misbehaving backend escapes its callback");

        backend.available = true;
        check(session.enter(backend), "retry after failure must apply");
        check(session.currentGeneration() != backend.lastGeneration,
                "retry must mint a fresh generation, never reuse the failed attempt");
        check(!backend.lastCallback.onAdjustVolume(1, backend.lastGeneration),
                "escaped callback must be ignored");
        check(backend.adjusts.isEmpty() && backend.sets.isEmpty(),
                "escaped callback must not touch the platform");
    }

    private static void nullBackendIsNoop() {
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        check(!session.enter(null), "null enter must report false");
        check(!session.exit(null), "null exit must report false");
        check(!session.isActive(), "null backend must never activate");
    }

    private static void coordinatorEnterHoldsVolumeForKeys() {
        Fixture f = new Fixture();

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(result.volume, "coordinator enter must hold the volume session");
        check(result.volumeActive, "volume must be active after enter");
        check(f.coordinator.isVolumeActive(), "coordinator must report volume active");
        check(f.volumeBackend.createCalls == 1, "enter must create one remote session");
        check(f.volumeBackend.adjusts.isEmpty() && f.volumeBackend.sets.isEmpty(),
                "coordinator enter must never write a level");
        check(!f.tts.active, "volume stays held between clips even when TTS is idle");

        long gen = f.volume.currentGeneration();
        check(f.volume.onAdjustVolume(1, gen), "key through the owned session must reach music");
        check(f.volumeBackend.musicVolume == 6, "music must move 5 -> 6");
        check(f.volumeBackend.providerVolume == 6, "provider display must resync");
    }

    private static void coordinatorEnterHoldsVolumeOnBluetooth() {
        Fixture f = new Fixture();
        f.routeBackend.bluetooth = true;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(!result.applied, "bluetooth enter must skip speaker routing");
        check(!f.route.isActive(), "route must stay inactive on bluetooth");
        check(result.volume, "volume keys must still be held on bluetooth output");
        check(result.volumeActive && f.coordinator.isVolumeActive(),
                "volume must be active even when routing is skipped");
    }

    private static void coordinatorPauseReleasesVolumeForCallPriority() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.isVolumeActive(), "setup volume must be active");

        check(f.coordinator.pauseForPhoneCall(), "pause must act");
        check(!f.coordinator.isVolumeActive(), "pause must release volume so the call owns keys");
        check(f.volumeBackend.releaseCalls == 1, "pause must release the platform session");
        check(f.volumeBackend.adjusts.isEmpty() && f.volumeBackend.sets.isEmpty(),
                "pause must never write a level");

        check(f.coordinator.resumeAfterPhoneCall(), "resume must act");
        check(!f.coordinator.isVolumeActive(), "resume must not re-enter volume");
        check(f.coordinator.enterVoiceSession().volume, "JS re-enter must hold volume again");
        check(f.coordinator.isVolumeActive(), "volume must be active after re-enter");
    }

    private static void coordinatorExitReleasesVolumeWithoutWriting() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();

        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();

        check(result.volume, "exit must release the volume session");
        check(!result.volumeActive && !f.coordinator.isVolumeActive(),
                "volume must be inactive after exit");
        check(f.volumeBackend.releaseCalls == 1, "exit must release once");
        check(f.volumeBackend.adjusts.isEmpty() && f.volumeBackend.sets.isEmpty(),
                "exit must never write a level");
    }

    private static void coordinatorNotificationStopAndDestroyReleaseVolume() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.tts.active = true;
        f.mic.capturing = true;

        f.coordinator.notificationStop();
        check(!f.coordinator.isVolumeActive(), "notification stop must release volume");
        check(f.volumeBackend.adjusts.isEmpty() && f.volumeBackend.sets.isEmpty(),
                "notification stop must never write a level");

        check(f.coordinator.enterVoiceSession().volume, "re-enter must hold volume");
        f.tts.active = true;
        f.mic.capturing = true;
        f.coordinator.destroy();
        check(!f.coordinator.isVolumeActive(), "destroy must release volume");
        check(f.volumeBackend.adjusts.isEmpty() && f.volumeBackend.sets.isEmpty(),
                "destroy must never write a level");
    }

    private static void coordinatorVolumeCreateFailureKeepsOtherResources() {
        Fixture f = new Fixture();
        f.volumeBackend.available = false;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(!result.volume, "failed volume create must report false");
        check(!result.volumeActive && !f.coordinator.isVolumeActive(),
                "volume must stay inactive after failure");
        check(result.applied && result.active, "route still applies when volume fails");
        check(result.keepAwake && result.keepAwakeActive, "keep-awake stays entered");
        check(result.foreground && result.foregroundActive, "FGS still requested");

        f.volumeBackend.available = true;
        check(f.coordinator.enterVoiceSession().volume, "retry must hold volume");
    }

    private static void coordinatorStaleVolumeKeysAfterReplacementIgnored() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        long first = f.volume.currentGeneration();
        f.coordinator.exitVoiceSession();
        f.coordinator.enterVoiceSession();
        long second = f.volume.currentGeneration();
        check(second != first, "replacement must mint a fresh volume generation");

        check(!f.volume.onAdjustVolume(1, first), "old generation key must be ignored");
        check(f.volumeBackend.adjusts.isEmpty(), "stale key must not touch music");
        check(f.volume.onAdjustVolume(1, second), "current key must reach music");
        check(f.volumeBackend.adjusts.size() == 1, "current key must adjust once");
    }

    public static void main(String[] args) {
        enterSeedsProviderFromMusicWithoutWriting();
        keysForwardToMusicAndResyncDisplay();
        sliderForwardsToMusicAndResyncs();
        staleCallbacksAfterExitDoNotTouchPlatform();
        staleGenerationAfterReplacementIsIgnored();
        exitWithoutEnterIsNoop();
        failedCreateStaysInactiveAndRetryable();
        failedAttemptGenerationIsConsumed();
        nullBackendIsNoop();
        coordinatorEnterHoldsVolumeForKeys();
        coordinatorEnterHoldsVolumeOnBluetooth();
        coordinatorPauseReleasesVolumeForCallPriority();
        coordinatorExitReleasesVolumeWithoutWriting();
        coordinatorNotificationStopAndDestroyReleaseVolume();
        coordinatorVolumeCreateFailureKeepsOtherResources();
        coordinatorStaleVolumeKeysAfterReplacementIgnored();
        System.out.println("VoiceModeVolumeSessionTest: all 16 behaviors passed");
    }
}
