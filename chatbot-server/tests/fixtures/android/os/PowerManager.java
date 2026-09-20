package android.os;

/** Minimal stub of android.os.PowerManager for off-device javac harnesses. */
public class PowerManager {
    public static final int PARTIAL_WAKE_LOCK = 1;

    public WakeLock newWakeLock(int level, String tag) {
        return new WakeLock();
    }

    public static class WakeLock {
        public void setReferenceCounted(boolean value) {
        }

        public boolean isHeld() {
            return false;
        }

        public void acquire() {
        }

        public void release() {
        }
    }
}
