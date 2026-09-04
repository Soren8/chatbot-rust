package com.chatbot.app.util;

import org.junit.Test;

/**
 * FileLogger must never throw exceptions or crash the app under any circumstances,
 * especially before init, with null context, or when external storage is unavailable.
 */
public class FileLoggerTest {

    @Test
    public void logWithoutInitDoesNotThrow() {
        // Without init(context), logFile is null. Must not throw NullPointerException.
        FileLogger.log("TestTag", "test message");
    }

    @Test
    public void logExceptionWithoutInitDoesNotThrow() {
        // Logging an exception without init must not crash in exception handlers.
        FileLogger.log("TestTag", "error occurred", new RuntimeException("test failure"));
    }

    @Test
    public void initWithNullContextDoesNotThrow() {
        // Calling init with null must be safely handled.
        FileLogger.init(null);
    }
}
