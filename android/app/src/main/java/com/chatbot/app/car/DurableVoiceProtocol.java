package com.chatbot.app.car;

import java.io.IOException;

/** Contiguous event cursor shared by admission and reconnect views. */
public final class DurableVoiceProtocol {
    private final String generationId;
    private long seq;
    private boolean saved;
    private final StringBuilder text = new StringBuilder();

    public interface Admission<T> { T send(String key) throws IOException; }
    public interface Sleeper { void sleep(long ms) throws IOException; }

    public static <T> T retryAdmission(String key, Admission<T> admission, Sleeper sleeper) throws IOException {
        int attempt = 0;
        while (true) {
            try { return admission.send(key); }
            catch (IOException lost) {
                sleeper.sleep(backoffMs(attempt++));
            }
        }
    }

    private static long backoffMs(int attempt) {
        return Math.min(30000L, 500L << Math.min(attempt, 6));
    }

    public interface TokenStream<T> { T open(String token) throws IOException; }

    static final int MAX_TTS_OPENS = 3;

    /** A null stream denotes an expired token; renew the same sentence receipt, with backoff, a bounded number of times. */
    public static <T> T openTts(String key, Admission<String> admission, TokenStream<T> stream, Sleeper sleeper) throws IOException {
        for (int expired = 0; ; ) {
            String token = retryAdmission(key, admission, sleeper);
            if (token == null) return null;
            T opened = stream.open(token);
            if (opened != null) return opened;
            if (++expired >= MAX_TTS_OPENS) return null;
            sleeper.sleep(backoffMs(expired - 1));
        }
    }

    public static int selectSet(String[] ids, boolean[] defaults, String preferred) {
        int selected = -1;
        for (int i = 0; i < ids.length; i++) {
            if (ids[i].equals(preferred)) return i;
            if (selected < 0 || defaults[i]) selected = i;
        }
        return selected;
    }

    public static boolean refreshRejectedVersion(int status, String error) {
        return status == 409 && "version_conflict".equals(error);
    }

    public DurableVoiceProtocol(String generationId) {
        if (generationId == null || !generationId.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("Invalid generation id");
        }
        this.generationId = generationId;
    }

    private final StringBuilder pendingLine = new StringBuilder();

    public interface LineConsumer { void accept(String line) throws IOException; }

    public void feed(String chunk, LineConsumer consumer) throws IOException {
        pendingLine.append(chunk);
        int newline;
        while ((newline = pendingLine.indexOf("\n")) >= 0) {
            String line = pendingLine.substring(0, newline);
            pendingLine.delete(0, newline + 1);
            if (!line.trim().isEmpty()) consumer.accept(line);
        }
    }

    public void resetView() { pendingLine.setLength(0); }

    public boolean apply(long next, String type, String value) throws IOException {
        if ("heartbeat".equals(type) || next <= seq) return false;
        if (next != seq + 1) throw new IOException("Generation replay gap");
        seq = next;
        if ("error".equals(type)) throw new IOException("Generation failed");
        if ("delta".equals(type)) text.append(value);
        if ("saved".equals(type)) saved = true;
        return true;
    }

    public String eventsPath() { return "/generations/" + generationId + "/events?after=" + seq; }
    public String stopPath() { return "/generations/" + generationId + "/stop"; }
    public String text() { return text.toString(); }
    public boolean saved() { return saved; }
}
