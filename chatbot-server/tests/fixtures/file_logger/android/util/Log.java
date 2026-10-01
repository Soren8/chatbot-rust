package android.util;

import java.io.PrintWriter;
import java.io.StringWriter;

/** Minimal stub of android.util.Log for the FileLogger harness. */
public final class Log {
    public static int d(String tag, String msg) {
        return 0;
    }

    public static int e(String tag, String msg, Throwable t) {
        return 0;
    }

    public static String getStackTraceString(Throwable t) {
        StringWriter out = new StringWriter();
        t.printStackTrace(new PrintWriter(out));
        return out.toString();
    }
}
