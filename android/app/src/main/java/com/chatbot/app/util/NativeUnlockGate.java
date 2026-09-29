package com.chatbot.app.util;

/** Pure decision over the platform biometric availability result. */
public final class NativeUnlockGate {
    private NativeUnlockGate() {}

    public static boolean canPrompt(int result, int success) {
        return result == success;
    }
}
