package android.media;

/**
 * Minimal stub of android.media.AudioManager for off-device javac harnesses.
 * Only the constants touched by VoiceAudioRoute are provided; values match
 * the platform so mode assertions stay meaningful.
 */
public class AudioManager {
    public static final int MODE_NORMAL = 0;
    public static final int MODE_RINGTONE = 1;
    public static final int MODE_IN_CALL = 2;
    public static final int MODE_IN_COMMUNICATION = 3;
    public static final int GET_DEVICES_OUTPUTS = 0;
}
