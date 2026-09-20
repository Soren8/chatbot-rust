package android.os;

/**
 * Fake android.os.Build leaf for the real TTS-adapter harness.
 * Reports a modern SDK so the extracted focus/device branches execute.
 */
public class Build {
    public static final class VERSION {
        public static final int SDK_INT = 33;
    }

    public static final class VERSION_CODES {
        public static final int M = 23;
        public static final int O = 26;
        public static final int S = 31;
    }
}
