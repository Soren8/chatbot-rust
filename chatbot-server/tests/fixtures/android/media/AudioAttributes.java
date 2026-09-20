package android.media;

/**
 * Minimal stub of android.media.AudioAttributes for off-device javac harnesses.
 * Only the usage/content constants the TTS policy selects between are
 * provided; values are distinct so equality assertions stay meaningful.
 */
public class AudioAttributes {
    public static final int USAGE_UNKNOWN = 0;
    public static final int USAGE_MEDIA = 1;
    public static final int USAGE_VOICE_COMMUNICATION = 2;
    public static final int CONTENT_TYPE_UNKNOWN = 0;
    public static final int CONTENT_TYPE_SPEECH = 1;
    public static final int CONTENT_TYPE_MUSIC = 2;
}
