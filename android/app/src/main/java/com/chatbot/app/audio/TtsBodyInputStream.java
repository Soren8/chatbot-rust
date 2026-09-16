package com.chatbot.app.audio;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Body-only idle timeout; changing HttpURLConnection's timeout after connect is not portable. */
public final class TtsBodyInputStream extends FilterInputStream {
    private final long timeoutMs;
    private final Runnable disconnect;
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(
            runnable -> new Thread(runnable, "NativeVoiceTts-body-timeout"));

    public TtsBodyInputStream(InputStream input, long timeoutMs, Runnable disconnect) {
        super(input);
        this.timeoutMs = timeoutMs;
        this.disconnect = disconnect;
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        return read(one, 0, 1) == -1 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        AtomicBoolean reading = new AtomicBoolean(true);
        ScheduledFuture<?> alarm = watchdog.schedule(() -> {
            if (reading.compareAndSet(true, false)) disconnect.run();
        }, timeoutMs, TimeUnit.MILLISECONDS);
        int count;
        boolean expired;
        try {
            count = in.read(bytes, offset, length);
        } finally {
            expired = !reading.getAndSet(false);
            alarm.cancel(false);
        }
        if (expired) throw new SocketTimeoutException("TTS audio body stalled");
        return count;
    }

    @Override
    public void close() throws IOException {
        watchdog.shutdownNow();
        super.close();
    }
}
