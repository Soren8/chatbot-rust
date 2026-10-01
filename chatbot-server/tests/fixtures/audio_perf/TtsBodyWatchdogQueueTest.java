import com.chatbot.app.audio.TtsBodyInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.concurrent.ScheduledThreadPoolExecutor;

/** Cancelled per-read watchdogs must not pile up in the scheduler queue for the timeout window. */
public final class TtsBodyWatchdogQueueTest {
    public static void main(String[] args) throws Exception {
        int reads = 5000;
        byte[] body = new byte[reads];
        for (int i = 0; i < reads; i++) body[i] = (byte) i;
        int[] disconnects = {0};
        try (TtsBodyInputStream in = new TtsBodyInputStream(
                new ByteArrayInputStream(body), 15_000, () -> disconnects[0]++)) {
            ScheduledThreadPoolExecutor watchdog = watchdogOf(in);
            for (int i = 0; i < reads; i++) {
                int b = in.read();
                if (b != (body[i] & 0xff)) throw new AssertionError("byte " + i + " mismatch: " + b);
            }
            if (in.read() != -1) throw new AssertionError("expected EOF");
            int queued = watchdog.getQueue().size();
            if (queued > 1) {
                throw new AssertionError("watchdog queue grew with reads: " + queued + " after " + reads + " reads");
            }
        }
        if (disconnects[0] != 0) throw new AssertionError("fast reads must not disconnect");
        System.out.println("watchdog queue bounded");
    }

    private static ScheduledThreadPoolExecutor watchdogOf(InputStream in) throws Exception {
        for (Field field : TtsBodyInputStream.class.getDeclaredFields()) {
            field.setAccessible(true);
            ScheduledThreadPoolExecutor found = unwrap(field.get(in));
            if (found != null) return found;
        }
        throw new AssertionError("TtsBodyInputStream must own a scheduled watchdog executor");
    }

    /** Executors.newSingleThreadScheduledExecutor wraps the pool; look through the delegate. */
    private static ScheduledThreadPoolExecutor unwrap(Object value) throws Exception {
        if (value instanceof ScheduledThreadPoolExecutor) return (ScheduledThreadPoolExecutor) value;
        if (!(value instanceof java.util.concurrent.ExecutorService)) return null;
        for (Class<?> c = value.getClass(); c != null; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (!java.util.concurrent.ExecutorService.class.isAssignableFrom(field.getType())) continue;
                field.setAccessible(true);
                ScheduledThreadPoolExecutor found = unwrap(field.get(value));
                if (found != null) return found;
            }
        }
        return null;
    }
}
