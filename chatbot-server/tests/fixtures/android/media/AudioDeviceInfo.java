package android.media;

/**
 * Minimal stub of android.media.AudioDeviceInfo for off-device javac harnesses.
 * Only the output types classified by VoiceAudioRoute are provided.
 */
public class AudioDeviceInfo {
    public static final int TYPE_BUILTIN_EARPIECE = 1;
    public static final int TYPE_BUILTIN_SPEAKER = 2;
    public static final int TYPE_WIRED_HEADSET = 3;
    public static final int TYPE_WIRED_HEADPHONES = 4;
    public static final int TYPE_BLUETOOTH_SCO = 7;
    public static final int TYPE_BLUETOOTH_A2DP = 8;
    public static final int TYPE_USB_HEADSET = 22;
    public static final int TYPE_BLE_HEADSET = 26;
    public static final int TYPE_BLE_SPEAKER = 27;
    public static final int TYPE_HEARING_AID = 28;
}
