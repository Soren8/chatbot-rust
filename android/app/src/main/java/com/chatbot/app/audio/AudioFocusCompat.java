package com.chatbot.app.audio;

import android.media.AudioAttributes;
import android.media.AudioManager;
import android.os.Build;

/** API-24-compatible wrapper for the API-26 audio-focus request objects. */
public final class AudioFocusCompat {
    private AudioFocusCompat() {}

    public static final class Focus {
        private final Object request;
        private final AudioManager.OnAudioFocusChangeListener listener;
        public final boolean granted;

        private Focus(Object request, AudioManager.OnAudioFocusChangeListener listener,
                boolean granted) {
            this.request = request;
            this.listener = listener;
            this.granted = granted;
        }
    }

    public static Focus request(AudioManager manager,
            AudioManager.OnAudioFocusChangeListener listener,
            AudioAttributes attributes, int legacyStream) {
        if (manager == null || listener == null) return null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return Api26.request(manager, listener, attributes, legacyStream);
        }
        int result = manager.requestAudioFocus(listener, legacyStream, AudioManager.AUDIOFOCUS_GAIN);
        return new Focus(null, listener, result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
    }

    public static void abandon(AudioManager manager, Focus focus) {
        if (manager == null || focus == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && focus.request != null) {
            Api26.abandon(manager, focus.request);
        } else {
            manager.abandonAudioFocus(focus.listener);
        }
    }

    /** Keep API-26 types out of the helper loaded on API 24/25. */
    private static final class Api26 {
        static Focus request(AudioManager manager,
                AudioManager.OnAudioFocusChangeListener listener,
                AudioAttributes attributes, int legacyStream) {
            android.media.AudioFocusRequest request =
                    new android.media.AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                            .setAudioAttributes(attributes)
                            .setOnAudioFocusChangeListener(listener)
                            .build();
            int result = manager.requestAudioFocus(request);
            return new Focus(request, listener,
                    result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
        }

        static void abandon(AudioManager manager, Object request) {
            manager.abandonAudioFocusRequest((android.media.AudioFocusRequest) request);
        }
    }
}
