package com.chatbot.app.util;

/**
 * Fake FileLogger leaf for the real volume-adapter harness. Drops logs.
 */
public class FileLogger {
    public static void log(String tag, String message) {
    }

    public static void log(String tag, String message, Throwable throwable) {
    }
}
