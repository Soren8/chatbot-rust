package android.os;

/** Minimal stub of android.os.Handler for off-device javac harnesses. */
public class Handler {
    public Handler(Looper looper) {
    }

    public boolean post(Runnable r) {
        return true;
    }

    public boolean postDelayed(Runnable r, long delayMillis) {
        return true;
    }

    public void removeCallbacks(Runnable r) {
    }
}
