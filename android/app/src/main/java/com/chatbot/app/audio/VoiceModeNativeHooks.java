package com.chatbot.app.audio;

/**
 * Lets the lock-screen Stop broadcast reach the live NativeMic session.
 */
public final class VoiceModeNativeHooks {
    public interface StopHandler {
        void stopFromNotification();
    }

    private static volatile StopHandler handler;

    private VoiceModeNativeHooks() {}

    public static void setHandler(StopHandler next) {
        handler = next;
    }

    public static void requestStop() {
        StopHandler current = handler;
        if (current != null) {
            current.stopFromNotification();
        }
    }
}
