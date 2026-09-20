import com.chatbot.app.audio.VoiceModeVolumeSession;

/**
 * Exercises the REAL platform volume adapter (MediaVolumeBackend extracted
 * verbatim from NativeMicPlugin, never reimplemented) against fake platform
 * leaves: a stale provider object after replacement must not forward, and a
 * setup failure must not leak the constructed session.
 */
public final class VolumeAdapterDriver {
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static MediaVolumeBackend backend(android.media.AudioManager audio) {
        MediaVolumeBackend backend = new MediaVolumeBackend();
        backend.audioManager = audio;
        backend.testContext = new android.content.Context();
        return backend;
    }

    private static void staleOldProviderAfterReplacementIsIgnored() {
        android.media.AudioManager audio = new android.media.AudioManager();
        MediaVolumeBackend backend = backend(audio);
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        check(session.enter(backend), "first enter must apply");
        android.media.VolumeProvider oldProvider =
                android.media.session.MediaSession.lastCreated.getProvider();
        check(oldProvider != null, "first session must bind a provider");
        check(session.exit(backend), "exit must release");
        check(session.enter(backend), "replacement enter must apply");

        int before = audio.musicVolume;
        oldProvider.onAdjustVolume(1);
        oldProvider.onSetVolumeTo(15);
        check(audio.musicVolume == before
                        && audio.adjusts.isEmpty()
                        && audio.sets.isEmpty(),
                "stale provider object must not touch music, got " + audio.musicVolume);

        long gen = session.currentGeneration();
        check(session.onAdjustVolume(1, gen), "current generation must still apply");
        check(audio.musicVolume == before + 1, "current key must reach music");
        check(session.exit(backend), "cleanup exit must release");
        check(android.media.session.MediaSession.liveCount == 0,
                "no session may stay live after exit");
    }

    private static void setupFailureReleasesCreatedSession() {
        int baseline = android.media.session.MediaSession.liveCount;
        android.media.AudioManager audio = new android.media.AudioManager();
        MediaVolumeBackend backend = backend(audio);
        VoiceModeVolumeSession session = new VoiceModeVolumeSession();
        android.media.session.MediaSession.failOnPlaybackToRemote = true;
        try {
            check(!session.enter(backend), "failed create must report false");
            check(!session.isActive(), "failed create must stay inactive");
            check(android.media.session.MediaSession.liveCount == baseline,
                    "constructed session must be released on setup failure");
            check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                    "failed create must never write a level");
        } finally {
            android.media.session.MediaSession.failOnPlaybackToRemote = false;
        }
        check(session.enter(backend), "retry after failure must apply");
        check(session.exit(backend), "cleanup exit must release");
        check(android.media.session.MediaSession.liveCount == baseline,
                "no session may stay live after retry exit");
    }

    private static int run(String name, Runnable scenario) {
        try {
            scenario.run();
            System.out.println("VolumeAdapterDriver: " + name + " passed");
            return 0;
        } catch (AssertionError e) {
            System.out.println("VolumeAdapterDriver: " + name + " FAILED: " + e.getMessage());
            return 1;
        }
    }

    public static void main(String[] args) {
        int failures = 0;
        failures += run("staleOldProviderAfterReplacementIsIgnored",
                VolumeAdapterDriver::staleOldProviderAfterReplacementIsIgnored);
        failures += run("setupFailureReleasesCreatedSession",
                VolumeAdapterDriver::setupFailureReleasesCreatedSession);
        if (failures > 0) {
            throw new AssertionError(failures + " adapter scenario(s) failed");
        }
        System.out.println("VolumeAdapterDriver: platform-adapter regressions passed");
    }
}
