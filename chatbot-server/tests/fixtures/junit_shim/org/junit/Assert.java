package org.junit;

import java.util.Objects;

public final class Assert {
    private Assert() {
    }

    public static void assertTrue(boolean condition) {
        assertTrue(null, condition);
    }

    public static void assertTrue(String message, boolean condition) {
        if (!condition) {
            throw failure(message, "expected true");
        }
    }

    public static void assertFalse(boolean condition) {
        assertFalse(null, condition);
    }

    public static void assertFalse(String message, boolean condition) {
        if (condition) {
            throw failure(message, "expected false");
        }
    }

    public static void assertNull(Object value) {
        assertNull(null, value);
    }

    public static void assertNull(String message, Object value) {
        if (value != null) {
            throw failure(message, "expected null, but was <" + value + ">");
        }
    }

    public static void assertEquals(Object expected, Object actual) {
        assertEquals(null, expected, actual);
    }

    public static void assertEquals(String message, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw failure(message, "expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void assertEquals(long expected, long actual) {
        assertEquals(null, expected, actual);
    }

    public static void assertEquals(String message, long expected, long actual) {
        if (expected != actual) {
            throw failure(message, "expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void assertEquals(double expected, double actual, double delta) {
        assertEquals(null, expected, actual, delta);
    }

    public static void assertEquals(String message, double expected, double actual, double delta) {
        if (!(Double.compare(expected, actual) == 0 || Math.abs(expected - actual) <= delta)) {
            throw failure(message, "expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static AssertionError failure(String message, String detail) {
        return new AssertionError(message == null || message.isEmpty() ? detail : message + ": " + detail);
    }
}
