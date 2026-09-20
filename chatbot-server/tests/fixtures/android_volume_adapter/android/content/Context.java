package android.content;

/**
 * Fake android.content.Context leaf for the real TTS-adapter harness.
 * Retained path from the retired volume harness; now exposes the audio
 * service hook the extracted playback adapter resolves per call.
 */
public class Context {
    public static final String AUDIO_SERVICE = "audio";

    public android.media.AudioManager audioService;

    public Context getApplicationContext() {
        return this;
    }

    public Object getSystemService(String name) {
        if (AUDIO_SERVICE.equals(name)) {
            return audioService;
        }
        return null;
    }
}
