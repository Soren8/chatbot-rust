package android.util;

/**
 * Fake android.util.Log leaf for the real TTS-adapter harness. Drops logs.
 */
public class Log {
    public static int w(String tag, String message, Throwable throwable) {
        return 0;
    }

    public static int w(String tag, String message) {
        return 0;
    }

    public static int d(String tag, String message) {
        return 0;
    }

    public static int e(String tag, String message, Throwable throwable) {
        return 0;
    }

    public static int e(String tag, String message) {
        return 0;
    }
}
