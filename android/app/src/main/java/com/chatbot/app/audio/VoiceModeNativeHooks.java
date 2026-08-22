package com.chatbot.app.audio;

/**
 * Lets the lock-screen Stop broadcast and screen-off keep-alive reach the
 * live NativeMic / WebView session.
 */
public final class VoiceModeNativeHooks {
    public interface StopHandler {
        void stopFromNotification();
    }

    public interface KeepAliveHandler {
        void keepWebViewAlive();
    }

    private static volatile StopHandler handler;
    private static volatile KeepAliveHandler keepAliveHandler;

    private VoiceModeNativeHooks() {}

    public static void setHandler(StopHandler next) {
        handler = next;
    }

    public static void setKeepAliveHandler(KeepAliveHandler next) {
        keepAliveHandler = next;
    }

    public static void requestStop() {
        StopHandler current = handler;
        if (current != null) {
            current.stopFromNotification();
        }
    }

    public static void keepWebViewAlive() {
        KeepAliveHandler current = keepAliveHandler;
        if (current != null) {
            current.keepWebViewAlive();
        }
    }
}
