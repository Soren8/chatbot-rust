package com.chatbot.app.audio;

/** Stable native-to-JavaScript result vocabulary for one complete clip GET. */
public final class TtsClipOutcome {
    public static final String PLAYED = "played";
    public static final String EXPIRED = "expired";
    public static final String FAILED = "failed";

    private TtsClipOutcome() {}

    public static boolean isExpiredHttpStatus(int status) {
        return status == 404;
    }

    public static String forFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ExpiredToken) return EXPIRED;
        }
        return FAILED;
    }

    /** Marker exception used only to carry an HTTP 404 through retry plumbing. */
    public static final class ExpiredToken extends java.io.IOException {
        public ExpiredToken() { super("TTS token expired"); }
    }
}
