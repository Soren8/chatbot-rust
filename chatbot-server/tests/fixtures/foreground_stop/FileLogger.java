package com.chatbot.app.util;

import android.content.Context;

/**
 * Minimal stub of FileLogger for off-device foreground-stop harnesses.
 * Logging is a no-op; the real stop outcome stays observable via the fake
 * platform context.
 */
public class FileLogger {
    public static void init(Context context) {
    }

    public static void log(String tag, String msg) {
    }

    public static void log(String tag, String msg, Throwable throwable) {
    }
}
