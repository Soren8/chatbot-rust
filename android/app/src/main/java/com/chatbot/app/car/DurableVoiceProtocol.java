package com.chatbot.app.car;

import java.io.IOException;

/** Contiguous event cursor shared by admission and reconnect views. */
public final class DurableVoiceProtocol {
    private final String generationId;
    private long seq;
    private boolean saved;
    private final StringBuilder text = new StringBuilder();

    public DurableVoiceProtocol(String generationId) {
        if (generationId == null || !generationId.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("Invalid generation id");
        }
        this.generationId = generationId;
    }

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
