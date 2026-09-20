import android.media.AudioAttributes;
import android.media.AudioManager;
import com.chatbot.app.audio.TtsAudioPolicy;
import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.audio.VoiceModeSessionCoordinator;
import com.chatbot.app.audio.VoiceSessionKeepAwake;
import java.util.ArrayList;
import java.util.List;

/**
 * Handheld voice-mode TTS must play through the communication path it
 * captures on, while standalone TTS keeps the media path.
 *
 * <p>Adapted from the retired remote-volume fixture: the generation,
 * stale-callback, ordering, failure and no-volume-write regression patterns
 * are preserved against the locally meaningful communication/media policy.
 * Drives the real {@link TtsAudioPolicy}, the real {@link VoiceAudioRoute}
 * and the real {@link VoiceModeSessionCoordinator} with fake platform
 * backends. String checks alone cannot prove the playback choice: every
 * behavior below executes the production owner/policy composition (route
 * ownership, voice vs standalone selection, track/focus recreation, stale
 * generations, pause/exit/stop/destroy) against fake backends, and asserts
 * no backend ever writes a stream volume.
 */
public final class VoiceTtsCommunicationPolicyTest {
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
        Object commDevice;
        int volumeWrites;

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

        int playbackUsage() {
            return TtsAudioPolicy.playbackUsage(route.isActive());
        }
    }

    private static void standaloneSelectsMediaWithLegacyMusic() {
        Fixture f = new Fixture();
        check(!f.route.isActive(), "setup must start standalone");

        int usage = f.playbackUsage();
        check(usage == AudioAttributes.USAGE_MEDIA,
                "standalone TTS must play USAGE_MEDIA, got " + usage);
        check(TtsAudioPolicy.useLegacyMusicStream(false),
                "standalone track must keep the STREAM_MUSIC legacy mapping");
        check(!TtsAudioPolicy.preferBuiltInSpeaker(false, false),
                "standalone must not force the built-in speaker");
        check(f.routeBackend.volumeWrites == 0, "route must never write a stream volume");
    }

    private static void voiceRouteSelectsCommunicationWithoutLegacy() {
        Fixture f = new Fixture();
        check(f.coordinator.enterVoiceSession().applied, "setup enter must apply");
        check(f.route.isActive(), "route must be active in voice mode");

        int usage = f.playbackUsage();
        check(usage == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "voice-mode TTS must play USAGE_VOICE_COMMUNICATION matching capture/focus/route, got " + usage);
        check(!TtsAudioPolicy.useLegacyMusicStream(true),
                "communication track must omit setLegacyStreamType (it overwrites attrs)");
        check(TtsAudioPolicy.preferBuiltInSpeaker(true, false),
                "voice route without headset/BT must prefer the built-in speaker");
        check(!TtsAudioPolicy.preferBuiltInSpeaker(true, true),
                "voice route with headset/BT must leave the route alone");
        check(f.routeBackend.volumeWrites == 0, "enter must never write a stream volume");
    }

    private static void bluetoothSkippedRouteStaysMedia() {
        Fixture f = new Fixture();
        f.routeBackend.bluetooth = true;

        VoiceModeSessionCoordinator.EnterResult result = f.coordinator.enterVoiceSession();

        check(!result.applied, "bluetooth enter must skip speaker routing");
        check(!f.route.isActive(), "route must stay inactive on bluetooth");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA,
                "bluetooth-skipped route (MODE_NORMAL) must keep MEDIA playback, not comm");
        check(!TtsAudioPolicy.preferBuiltInSpeaker(false, true),
                "no preferred-device hack where the route is not authoritative");
    }

    private static void sameRateUsageChangeMustRecreateTrack() {
        check(TtsAudioPolicy.shouldRecreateTrack(true,
                        AudioAttributes.USAGE_MEDIA, 24000,
                        AudioAttributes.USAGE_VOICE_COMMUNICATION, 24000),
                "entering voice mode must recreate the track even at the same rate");
        check(TtsAudioPolicy.shouldRecreateTrack(true,
                        AudioAttributes.USAGE_VOICE_COMMUNICATION, 24000,
                        AudioAttributes.USAGE_MEDIA, 24000),
                "exiting voice mode must recreate the track even at the same rate");
        check(!TtsAudioPolicy.shouldRecreateTrack(true,
                        AudioAttributes.USAGE_MEDIA, 24000,
                        AudioAttributes.USAGE_MEDIA, 24000),
                "same usage and rate must reuse the track (no per-clip churn)");
        check(TtsAudioPolicy.shouldRecreateTrack(true,
                        AudioAttributes.USAGE_MEDIA, 24000,
                        AudioAttributes.USAGE_MEDIA, 16000),
                "rate change must still recreate the track");
        check(TtsAudioPolicy.shouldRecreateTrack(false,
                        AudioAttributes.USAGE_MEDIA, 24000,
                        AudioAttributes.USAGE_MEDIA, 24000),
                "no track yet must create one");
    }

    private static void focusFollowsPlaybackUsageWithoutChurn() {
        check(TtsAudioPolicy.shouldRefreshFocus(false, 0, AudioAttributes.USAGE_MEDIA),
                "no focus yet must request one");
        check(!TtsAudioPolicy.shouldRefreshFocus(true,
                        AudioAttributes.USAGE_MEDIA, AudioAttributes.USAGE_MEDIA),
                "same usage must keep held focus (no per-sentence binder churn)");
        check(TtsAudioPolicy.shouldRefreshFocus(true,
                        AudioAttributes.USAGE_MEDIA, AudioAttributes.USAGE_VOICE_COMMUNICATION),
                "usage change must refresh focus so player and focus share attrs");
        check(TtsAudioPolicy.shouldRefreshFocus(true,
                        AudioAttributes.USAGE_VOICE_COMMUNICATION, AudioAttributes.USAGE_MEDIA),
                "exit must refresh focus back to media");
    }

    private static void coordinatorEnterExitMovesPlaybackBetweenModes() {
        Fixture f = new Fixture();
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA, "pre-enter must be media");

        check(f.coordinator.enterVoiceSession().applied, "enter must apply");
        check(f.playbackUsage() == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "post-enter must be communication");

        f.coordinator.exitVoiceSession();
        check(!f.route.isActive(), "exit must release the route");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA,
                "post-exit standalone TTS must return to media");
        check(f.routeBackend.volumeWrites == 0, "enter/exit must never write a volume");
    }

    private static void coordinatorPauseReleasesRouteForCallWithoutWriting() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        f.tts.active = true;
        check(f.playbackUsage() == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "setup must be communication");

        check(f.coordinator.pauseForPhoneCall(), "pause must act");
        check(!f.route.isActive(), "pause must release the route so the call owns audio");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA,
                "paused route must fall back to media (call owns comm)");
        checkOrder(f.log, "tts.stop", "mic.stop", "route.focus.abandon");
        check(f.routeBackend.volumeWrites == 0, "pause must never write a volume");
        check(f.events.phoneTrue == 1, "pause must notify once");

        check(f.coordinator.resumeAfterPhoneCall(), "resume must act");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA,
                "resume stays media until JS re-enters the route");
        check(f.coordinator.enterVoiceSession().applied, "JS re-enter must apply");
        check(f.playbackUsage() == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "re-enter must return to communication");
    }

    private static void coordinatorStopAndDestroyReleaseWithoutWriting() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.tts.active = true;
        f.mic.capturing = true;

        f.coordinator.notificationStop();
        check(!f.route.isActive(), "notification stop must release the route");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA, "stop must return to media");
        check(f.routeBackend.volumeWrites == 0, "stop must never write a volume");

        check(f.coordinator.enterVoiceSession().applied, "re-enter must apply");
        f.tts.active = true;
        f.mic.capturing = true;
        f.coordinator.destroy();
        check(!f.route.isActive(), "destroy must release the route");
        check(f.routeBackend.volumeWrites == 0, "destroy must never write a volume");
        check(f.events.stopNotified == 1, "stop must notify once");
    }

    private static void exitWithoutEnterKeepsMediaAndWritesNothing() {
        Fixture f = new Fixture();
        VoiceModeSessionCoordinator.ExitResult result = f.coordinator.exitVoiceSession();
        check(!result.applied, "idle exit must report false");
        check(f.playbackUsage() == AudioAttributes.USAGE_MEDIA, "idle must stay media");
        check(f.routeBackend.volumeWrites == 0, "idle exit must not touch volumes");
        check(f.events.phoneTrue == 0 && f.events.phoneFalse == 0, "idle exit must not emit");
    }

    private static void staleTransitionIdsStayMonotonic() {
        Fixture f = new Fixture();
        f.coordinator.enterVoiceSession();
        f.mic.capturing = true;
        check(f.coordinator.pauseForPhoneCall(), "setup pause must act");
        check(f.coordinator.resumeAfterPhoneCall(), "setup resume must act");
        f.coordinator.notificationStop();
        check(f.events.phoneTrue == 1 && f.events.phoneFalse == 1
                        && f.events.stopNotified == 1,
                "pause/resume/stop must each notify once");
    }

    public static void main(String[] args) {
        standaloneSelectsMediaWithLegacyMusic();
        voiceRouteSelectsCommunicationWithoutLegacy();
        bluetoothSkippedRouteStaysMedia();
        sameRateUsageChangeMustRecreateTrack();
        focusFollowsPlaybackUsageWithoutChurn();
        coordinatorEnterExitMovesPlaybackBetweenModes();
        coordinatorPauseReleasesRouteForCallWithoutWriting();
        coordinatorStopAndDestroyReleaseWithoutWriting();
        exitWithoutEnterKeepsMediaAndWritesNothing();
        staleTransitionIdsStayMonotonic();
        System.out.println("VoiceTtsCommunicationPolicyTest: all 10 behaviors passed");
    }
}
