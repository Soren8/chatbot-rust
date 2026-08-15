package com.chatbot.app.audio;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.media.AudioManager;

import org.junit.Before;
import org.junit.Test;

/**
 * Speakerphone routing must be a single session. Re-entering (TTS start, mic
 * restart) used to re-apply MODE_IN_COMMUNICATION / speakerphone and interrupt
 * playback with a volume jump.
 */
public class VoiceAudioRouteTest {
    private FakeBackend backend;
    private VoiceAudioRoute route;

    @Before
    public void setUp() {
        backend = new FakeBackend();
        route = new VoiceAudioRoute();
    }

    @Test
    public void enterAppliesCallRoutingOnce() {
        assertTrue(route.enter(backend));

        assertTrue(route.isActive());
        assertEquals(AudioManager.MODE_IN_COMMUNICATION, backend.mode);
        assertTrue(backend.speakerphoneOn);
        assertEquals(backend.voiceCallMaxVolume, backend.voiceCallVolume);
        assertEquals(1, backend.setModeCount);
        assertEquals(1, backend.focusRequests);
        assertTrue(backend.speakerDeviceSet);
    }

    @Test
    public void secondEnterDoesNotRetouchAudioManager() {
        assertTrue(route.enter(backend));
        backend.setModeCount = 0;
        backend.setSpeakerphoneCount = 0;
        backend.focusRequests = 0;
        backend.speakerDeviceSet = false;
        backend.mode = AudioManager.MODE_NORMAL;
        backend.speakerphoneOn = false;

        assertFalse(route.enter(backend));

        assertTrue(route.isActive());
        assertEquals(0, backend.setModeCount);
        assertEquals(0, backend.setSpeakerphoneCount);
        assertEquals(0, backend.focusRequests);
        assertFalse(backend.speakerDeviceSet);
        assertEquals(AudioManager.MODE_NORMAL, backend.mode);
        assertFalse(backend.speakerphoneOn);
    }

    @Test
    public void exitRestoresCapturedPreVoiceStateNotCommunicationMode() {
        backend.mode = AudioManager.MODE_NORMAL;
        backend.speakerphoneOn = false;
        backend.voiceCallVolume = 3;

        assertTrue(route.enter(backend));
        // Simulate a TTS session that would have overwritten previousMode
        // if enter() ran again while already in communication mode.
        assertFalse(route.enter(backend));
        assertTrue(route.exit(backend));

        assertFalse(route.isActive());
        assertEquals(AudioManager.MODE_NORMAL, backend.mode);
        assertFalse(backend.speakerphoneOn);
        assertEquals(3, backend.voiceCallVolume);
        assertEquals(1, backend.focusAbandons);
        assertTrue(backend.communicationDeviceCleared);
    }

    @Test
    public void exitWithoutEnterIsNoOp() {
        assertFalse(route.exit(backend));
        assertEquals(0, backend.setModeCount);
        assertEquals(0, backend.focusAbandons);
    }

    @Test
    public void enterAndExitWithNullBackendAreNoOps() {
        assertFalse(route.enter(null));
        assertFalse(route.isActive());
        assertFalse(route.exit(null));
    }

    private static final class FakeBackend implements VoiceAudioRoute.Backend {
        int mode = AudioManager.MODE_NORMAL;
        boolean speakerphoneOn;
        int voiceCallVolume = 4;
        final int voiceCallMaxVolume = 7;
        int setModeCount;
        int setSpeakerphoneCount;
        int focusRequests;
        int focusAbandons;
        boolean speakerDeviceSet;
        boolean communicationDeviceCleared;
        Object communicationDevice;

        @Override
        public int getMode() {
            return mode;
        }

        @Override
        public void setMode(int mode) {
            setModeCount++;
            this.mode = mode;
        }

        @Override
        public boolean isSpeakerphoneOn() {
            return speakerphoneOn;
        }

        @Override
        public void setSpeakerphoneOn(boolean on) {
            setSpeakerphoneCount++;
            speakerphoneOn = on;
        }

        @Override
        public int getVoiceCallVolume() {
            return voiceCallVolume;
        }

        @Override
        public int getVoiceCallMaxVolume() {
            return voiceCallMaxVolume;
        }

        @Override
        public void setVoiceCallVolume(int index) {
            voiceCallVolume = index;
        }

        @Override
        public boolean requestCommunicationFocus() {
            focusRequests++;
            return true;
        }

        @Override
        public void abandonCommunicationFocus() {
            focusAbandons++;
        }

        @Override
        public boolean supportsCommunicationDevice() {
            return true;
        }

        @Override
        public Object getCommunicationDevice() {
            return communicationDevice;
        }

        @Override
        public boolean setCommunicationDeviceToSpeaker() {
            speakerDeviceSet = true;
            communicationDevice = "speaker";
            return true;
        }

        @Override
        public void restoreCommunicationDevice(Object previous) {
            communicationDevice = previous;
        }

        @Override
        public void clearCommunicationDevice() {
            communicationDeviceCleared = true;
            communicationDevice = null;
        }
    }
}
