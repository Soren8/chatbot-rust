package com.chatbot.app.audio;

import android.media.AudioManager;

/**
 * Holds speakerphone (VoIP communication) routing for one handheld voice-mode session.
 *
 * {@link #enter} is a no-op if already active so TTS start/stop cannot flip
 * {@link AudioManager#MODE_IN_COMMUNICATION} or the communication device mid-utterance.
 */
public final class VoiceAudioRoute {
    public interface Backend {
        int getMode();

        void setMode(int mode);

        boolean isSpeakerphoneOn();

        void setSpeakerphoneOn(boolean on);

        int getVoiceCallVolume();

        int getVoiceCallMaxVolume();

        void setVoiceCallVolume(int index);

        boolean requestCommunicationFocus();

        void abandonCommunicationFocus();

        boolean supportsCommunicationDevice();

        Object getCommunicationDevice();

        boolean setCommunicationDeviceToSpeaker();

        void restoreCommunicationDevice(Object previous);

        void clearCommunicationDevice();
    }

    private boolean active;
    private int previousMode = AudioManager.MODE_NORMAL;
    private boolean previousSpeakerphone;
    private int previousVoiceCallVolume = -1;
    private Object previousCommunicationDevice;
    private boolean communicationDeviceTouched;

    public synchronized boolean isActive() {
        return active;
    }

    /**
     * Apply speakerphone routing once. Returns false when already active or {@code backend} is null
     * (caller must not mutate {@link AudioManager} in that case).
     */
    public synchronized boolean enter(Backend backend) {
        if (active || backend == null) {
            return false;
        }

        previousMode = backend.getMode();
        previousSpeakerphone = backend.isSpeakerphoneOn();
        previousVoiceCallVolume = backend.getVoiceCallVolume();
        communicationDeviceTouched = false;
        previousCommunicationDevice = null;

        backend.requestCommunicationFocus();
        backend.setMode(AudioManager.MODE_IN_COMMUNICATION);
        backend.setSpeakerphoneOn(true);
        if (backend.supportsCommunicationDevice()) {
            previousCommunicationDevice = backend.getCommunicationDevice();
            communicationDeviceTouched = true;
            backend.setCommunicationDeviceToSpeaker();
        }
        backend.setVoiceCallVolume(backend.getVoiceCallMaxVolume());
        active = true;
        return true;
    }

    /**
     * Restore the pre-voice-mode route. Returns false when not active or {@code backend} is null.
     */
    public synchronized boolean exit(Backend backend) {
        if (!active || backend == null) {
            return false;
        }

        if (communicationDeviceTouched) {
            if (previousCommunicationDevice != null) {
                backend.restoreCommunicationDevice(previousCommunicationDevice);
            } else {
                backend.clearCommunicationDevice();
            }
        }
        if (previousVoiceCallVolume >= 0) {
            backend.setVoiceCallVolume(previousVoiceCallVolume);
        }
        backend.setSpeakerphoneOn(previousSpeakerphone);
        backend.setMode(previousMode);
        backend.abandonCommunicationFocus();

        active = false;
        previousVoiceCallVolume = -1;
        previousCommunicationDevice = null;
        communicationDeviceTouched = false;
        return true;
    }
}
