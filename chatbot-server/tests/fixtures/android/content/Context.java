package android.content;

/**
 * Minimal stub of android.content.Context for off-device javac harnesses.
 * Only the foreground-stop surface touched by VoiceModeForegroundService is
 * provided; values are inert.
 */
public class Context {
    public static final String POWER_SERVICE = "power";
    public static final String CONNECTIVITY_SERVICE = "connectivity";

    public Context getApplicationContext() {
        return this;
    }

    public boolean stopService(Intent intent) {
        return false;
    }

    public void startService(Intent intent) {
    }

    public void startForegroundService(Intent intent) {
    }

    public Object getSystemService(String name) {
        return null;
    }
}
