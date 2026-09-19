package android.os;

/** Minimal stub of android.os.Looper for off-device javac harnesses. */
public class Looper {
    public static Looper getMainLooper() {
        return new Looper();
    }
}
