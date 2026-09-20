package android.content;

/**
 * Minimal stub of android.content.Intent for off-device javac harnesses.
 * Only the foreground-stop surface touched by VoiceModeForegroundService is
 * provided.
 */
public class Intent {
    private final java.util.Map<String, Long> longExtras = new java.util.HashMap<>();
    private String action;

    public Intent() {
    }

    public Intent(Context ctx, Class<?> cls) {
    }

    public Intent setAction(String action) {
        this.action = action;
        return this;
    }

    public Intent putExtra(String name, long value) {
        longExtras.put(name, value);
        return this;
    }

    public long getLongExtra(String name, long def) {
        Long stored = longExtras.get(name);
        return stored != null ? stored : def;
    }

    public String getAction() {
        return action;
    }
}
