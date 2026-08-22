package com.chatbot.app.audio;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * Microphone FGS must be a single session. Re-entering (TTS start, mic
 * restart) must not stop and restart the notification.
 */
public class VoiceModeForegroundSessionTest {
    private FakeBackend backend;
    private VoiceModeForegroundSession session;

    @Before
    public void setUp() {
        backend = new FakeBackend();
        session = new VoiceModeForegroundSession();
    }

    @Test
    public void enterStartsForegroundOnce() {
        assertTrue(session.enter(backend));

        assertTrue(session.isActive());
        assertTrue(backend.running);
        assertEquals(1, backend.startCount);
    }

    @Test
    public void secondEnterDoesNotRestartService() {
        assertTrue(session.enter(backend));
        backend.startCount = 0;
        backend.running = false;

        assertFalse(session.enter(backend));

        assertTrue(session.isActive());
        assertEquals(0, backend.startCount);
        assertFalse(backend.running);
    }

    @Test
    public void exitStopsForegroundAndAllowsReenter() {
        assertTrue(session.enter(backend));
        assertTrue(session.exit(backend));

        assertFalse(session.isActive());
        assertFalse(backend.running);
        assertEquals(1, backend.stopCount);

        assertTrue(session.enter(backend));
        assertTrue(session.isActive());
        assertTrue(backend.running);
    }

    @Test
    public void exitWithoutEnterIsNoOp() {
        assertFalse(session.exit(backend));
        assertEquals(0, backend.stopCount);
    }

    @Test
    public void enterAndExitWithNullBackendAreNoOps() {
        assertFalse(session.enter(null));
        assertFalse(session.isActive());
        assertFalse(session.exit(null));
    }

    @Test
    public void enterFailsWhenServiceUnavailable() {
        backend.available = false;

        assertFalse(session.enter(backend));

        assertFalse(session.isActive());
        assertEquals(1, backend.startCount);
        assertFalse(backend.running);
    }

    @Test
    public void exitStaysActiveWhenStopFails() {
        assertTrue(session.enter(backend));
        backend.available = false;

        assertFalse(session.exit(backend));

        assertTrue(session.isActive());
        assertTrue(backend.running);
    }

    private static final class FakeBackend implements VoiceModeForegroundSession.Backend {
        boolean running;
        int startCount;
        int stopCount;
        boolean available = true;

        @Override
        public boolean startForeground() {
            startCount++;
            if (!available) {
                return false;
            }
            running = true;
            return true;
        }

        @Override
        public boolean stopForeground() {
            stopCount++;
            if (!available) {
                return false;
            }
            running = false;
            return true;
        }
    }
}
