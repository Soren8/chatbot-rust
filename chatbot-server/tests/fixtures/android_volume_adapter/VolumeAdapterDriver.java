import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.AudioTrack;

/**
 * Exercises the REAL TTS playback adapter: {@code requestAudioFocus} and
 * {@code ensureTrackPlaying} are extracted verbatim from
 * NativeVoiceTtsPlugin (never reimplemented) into TtsAdapterUnderTest and
 * compiled with fake platform leaves plus the real TtsAudioPolicy.
 *
 * <p>Retained path from the retired volume harness; the stale-provider and
 * setup-cleanup regression intent now runs against the locally meaningful
 * playback adapter: built AudioAttributes AND matching focus, recreation on
 * usage change (including same-rate voice enter/exit), reuse otherwise, and
 * no stream writes. The retired VolumeProvider/MediaSession leaves stay as
 * unused guard stubs.
 */
public final class VolumeAdapterDriver {
    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static TtsAdapterUnderTest adapter(
            AudioManager audio, boolean routeActive, boolean headset, boolean speakerPresent) {
        android.content.Context ctx = new android.content.Context();
        ctx.audioService = audio;
        TtsAdapterUnderTest adapter = new TtsAdapterUnderTest();
        adapter.testContext = ctx;
        adapter.routeActiveFlag = routeActive;
        adapter.headsetFlag = headset;
        adapter.speakerPresentFlag = speakerPresent;
        return adapter;
    }

    private static void standaloneBuildsMediaWithLegacyAndMatchingFocus() {
        AudioTrack.createdTracks = 0;
        AudioTrack.releasedTracks = 0;
        AudioManager audio = new AudioManager();
        TtsAdapterUnderTest adapter = adapter(audio, false, false, true);

        AudioTrack track = adapter.ensureTrackPlayingPublic(24000, 1L);

        check(track != null, "standalone must build a track");
        check(track.attributes.usage == AudioAttributes.USAGE_MEDIA,
                "standalone track must be USAGE_MEDIA, got " + track.attributes.usage);
        check(track.attributes.contentType == AudioAttributes.CONTENT_TYPE_SPEECH,
                "track content must stay speech");
        check(track.attributes.hasLegacyStreamType
                        && track.attributes.legacyStreamType == AudioManager.STREAM_MUSIC,
                "standalone track must keep the STREAM_MUSIC legacy mapping");
        check(audio.focusRequests.size() == 1
                        && audio.focusRequests.get(0) == AudioAttributes.USAGE_MEDIA,
                "focus must match the media player, got " + audio.focusRequests);
        check(!track.preferredDeviceSet,
                "standalone must not force the built-in speaker");
        check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                "adapter must never write a stream volume");
    }

    private static void voiceBuildsCommunicationWithoutLegacyAndMatchingFocus() {
        AudioTrack.createdTracks = 0;
        AudioTrack.releasedTracks = 0;
        AudioManager audio = new AudioManager();
        TtsAdapterUnderTest adapter = adapter(audio, true, false, true);

        AudioTrack track = adapter.ensureTrackPlayingPublic(24000, 1L);

        check(track != null, "voice mode must build a track");
        check(track.attributes.usage == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "voice track must be USAGE_VOICE_COMMUNICATION, got " + track.attributes.usage);
        check(track.attributes.contentType == AudioAttributes.CONTENT_TYPE_SPEECH,
                "track content must stay speech");
        check(!track.attributes.hasLegacyStreamType,
                "communication track must omit setLegacyStreamType (it overwrites attrs)");
        check(audio.focusRequests.size() == 1
                        && audio.focusRequests.get(0) == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "focus must match the communication player, got " + audio.focusRequests);
        check(track.preferredDeviceSet,
                "owned voice route without headset must prefer the built-in speaker");
        check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                "adapter must never write a stream volume");
    }

    private static void sameRateUsageChangeRecreatesTrackAndRefreshesFocus() {
        AudioTrack.createdTracks = 0;
        AudioTrack.releasedTracks = 0;
        AudioManager audio = new AudioManager();
        android.content.Context ctx = new android.content.Context();
        ctx.audioService = audio;
        TtsAdapterUnderTest adapter = new TtsAdapterUnderTest();
        adapter.testContext = ctx;
        adapter.routeActiveFlag = false;
        adapter.headsetFlag = false;
        adapter.speakerPresentFlag = true;

        AudioTrack first = adapter.ensureTrackPlayingPublic(24000, 1L);
        check(first.attributes.usage == AudioAttributes.USAGE_MEDIA, "setup must start media");
        int tracksAfterFirst = AudioTrack.createdTracks;
        int focusAfterFirst = audio.focusRequests.size();

        adapter.routeActiveFlag = true;
        AudioTrack second = adapter.ensureTrackPlayingPublic(24000, 1L);

        check(second != first, "same-rate voice enter must recreate the track object");
        check(AudioTrack.createdTracks == tracksAfterFirst + 1,
                "usage flip must create exactly one replacement track");
        check(first.released, "replaced track must be released");
        check(second.attributes.usage == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "replacement must be communication");
        check(!second.attributes.hasLegacyStreamType, "replacement must drop the legacy mapping");
        check(audio.focusRequests.size() == focusAfterFirst + 1
                        && audio.focusRequests.get(audio.focusRequests.size() - 1)
                                == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "usage flip must refresh focus once to the new usage, got " + audio.focusRequests);

        adapter.routeActiveFlag = false;
        AudioTrack third = adapter.ensureTrackPlayingPublic(24000, 1L);
        check(third.attributes.usage == AudioAttributes.USAGE_MEDIA
                        && third.attributes.hasLegacyStreamType,
                "voice exit must return to media with the legacy mapping");
        check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                "transitions must never write a stream volume");
    }

    private static void sameUsageSameRateReusesTrackAndKeepsFocus() {
        AudioTrack.createdTracks = 0;
        AudioTrack.releasedTracks = 0;
        AudioManager audio = new AudioManager();
        TtsAdapterUnderTest adapter = adapter(audio, true, false, true);

        AudioTrack first = adapter.ensureTrackPlayingPublic(24000, 7L);
        int tracks = AudioTrack.createdTracks;
        int focus = audio.focusRequests.size();

        AudioTrack second = adapter.ensureTrackPlayingPublic(24000, 7L);

        check(second == first, "same usage and rate must reuse the live track object");
        check(AudioTrack.createdTracks == tracks, "reuse must not create another track");
        check(audio.focusRequests.size() == focus, "reuse must not re-request focus per sentence");
        check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                "reuse must never write a stream volume");
    }

    private static void headsetSkipsPreferredDeviceButKeepsCommunication() {
        AudioTrack.createdTracks = 0;
        AudioTrack.releasedTracks = 0;
        AudioManager audio = new AudioManager();
        TtsAdapterUnderTest adapter = adapter(audio, true, true, true);

        AudioTrack track = adapter.ensureTrackPlayingPublic(24000, 1L);

        check(track.attributes.usage == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "headset route must still play communication (route is authoritative)");
        check(!track.preferredDeviceSet,
                "headset/BT must skip the preferred-device hack");
        check(audio.focusRequests.size() == 1
                        && audio.focusRequests.get(0) == AudioAttributes.USAGE_VOICE_COMMUNICATION,
                "focus must still match communication, got " + audio.focusRequests);
        check(audio.adjusts.isEmpty() && audio.sets.isEmpty(),
                "headset path must never write a stream volume");
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
        failures += run("standaloneBuildsMediaWithLegacyAndMatchingFocus",
                VolumeAdapterDriver::standaloneBuildsMediaWithLegacyAndMatchingFocus);
        failures += run("voiceBuildsCommunicationWithoutLegacyAndMatchingFocus",
                VolumeAdapterDriver::voiceBuildsCommunicationWithoutLegacyAndMatchingFocus);
        failures += run("sameRateUsageChangeRecreatesTrackAndRefreshesFocus",
                VolumeAdapterDriver::sameRateUsageChangeRecreatesTrackAndRefreshesFocus);
        failures += run("sameUsageSameRateReusesTrackAndKeepsFocus",
                VolumeAdapterDriver::sameUsageSameRateReusesTrackAndKeepsFocus);
        failures += run("headsetSkipsPreferredDeviceButKeepsCommunication",
                VolumeAdapterDriver::headsetSkipsPreferredDeviceButKeepsCommunication);
        if (failures > 0) {
            throw new AssertionError(failures + " adapter scenario(s) failed");
        }
        System.out.println("VolumeAdapterDriver: playback-adapter regressions passed");
    }
}
