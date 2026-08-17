package com.chatbot.app.audio;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * Keep-screen-on must be a single session. Re-entering (TTS start, mic
 * restart) must not clear and re-set the window flag.
 */
public class VoiceSessionKeepAwakeTest {
    private FakeBackend backend;
    private VoiceSessionKeepAwake keepAwake;

    @Before
    public void setUp() {
        backend = new FakeBackend();
        keepAwake = new VoiceSessionKeepAwake();
    }

    @Test
    public void enterKeepsScreenOnOnce() {
        assertTrue(keepAwake.enter(backend));

        assertTrue(keepAwake.isActive());
        assertTrue(backend.keepScreenOn);
        assertEquals(1, backend.setCount);
    }

    @Test
    public void secondEnterDoesNotRetouchScreen() {
        assertTrue(keepAwake.enter(backend));
        backend.setCount = 0;
        backend.keepScreenOn = false;

        assertFalse(keepAwake.enter(backend));

        assertTrue(keepAwake.isActive());
        assertEquals(0, backend.setCount);
        assertFalse(backend.keepScreenOn);
    }

    @Test
    public void exitClearsScreenOnAndAllowsReenter() {
        assertTrue(keepAwake.enter(backend));
        assertTrue(keepAwake.exit(backend));

        assertFalse(keepAwake.isActive());
        assertFalse(backend.keepScreenOn);
        assertEquals(2, backend.setCount);

        assertTrue(keepAwake.enter(backend));
        assertTrue(keepAwake.isActive());
        assertTrue(backend.keepScreenOn);
    }

    @Test
    public void exitWithoutEnterIsNoOp() {
        assertFalse(keepAwake.exit(backend));
        assertEquals(0, backend.setCount);
    }

    @Test
    public void enterAndExitWithNullBackendAreNoOps() {
        assertFalse(keepAwake.enter(null));
        assertFalse(keepAwake.isActive());
        assertFalse(keepAwake.exit(null));
    }

    @Test
    public void enterFailsWhenWindowUnavailable() {
        backend.available = false;

        assertFalse(keepAwake.enter(backend));

        assertFalse(keepAwake.isActive());
        assertEquals(1, backend.setCount);
        assertFalse(backend.keepScreenOn);
    }

    @Test
    public void exitStaysActiveWhenClearFails() {
        assertTrue(keepAwake.enter(backend));
        backend.available = false;

        assertFalse(keepAwake.exit(backend));

        assertTrue(keepAwake.isActive());
        assertTrue(backend.keepScreenOn);
    }

    private static final class FakeBackend implements VoiceSessionKeepAwake.Backend {
        boolean keepScreenOn;
        int setCount;
        boolean available = true;

        @Override
        public boolean setKeepScreenOn(boolean on) {
            setCount++;
            if (!available) {
                return false;
            }
            keepScreenOn = on;
            return true;
        }
    }
}
