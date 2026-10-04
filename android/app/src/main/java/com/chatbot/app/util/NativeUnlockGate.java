package com.chatbot.app.util;

/** Pure decision over the platform biometric availability result. */
public final class NativeUnlockGate {
    private NativeUnlockGate() {}

    public static boolean canPrompt(int result, int success) {
        return result == success;
    }

    /** A prior unresolved lock survives Activity recreation, regardless of resume grace. */
    public static boolean shouldLockEntry(boolean previouslyLocked, boolean coldProcess,
            boolean confirmedBackgroundVoice, boolean hasCredentialState) {
        return previouslyLocked
                || (coldProcess && !confirmedBackgroundVoice && hasCredentialState);
    }

    /** Ignore an absent/future elapsed-realtime mark; otherwise compute safe resume age. */
    public static long elapsedSinceBackground(long backgroundedAt, long now) {
        if (backgroundedAt <= 0 || now <= backgroundedAt) return 0;
        return now - backgroundedAt;
    }

    /** Preserve the short same-process resume grace and only exempt confirmed voice. */
    public static boolean shouldLockResume(boolean loggedIn, long elapsedMs,
            long graceMs, boolean confirmedBackgroundVoice) {
        return loggedIn && elapsedMs >= graceMs && !confirmedBackgroundVoice;
    }
}
