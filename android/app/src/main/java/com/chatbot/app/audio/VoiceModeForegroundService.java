package com.chatbot.app.audio;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.media.MediaMetadata;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import com.chatbot.app.R;
import com.chatbot.app.util.FileLogger;

/**
 * Microphone + media-playback foreground service for handheld voice mode
 * with the screen off. Holds a playing {@link MediaSession} so the keyguard
 * shows the Stop bar.
 */
public class VoiceModeForegroundService extends Service {
    public static final String ACTION_START = "com.chatbot.app.START_VOICE_MODE";
    private static final String TAG = "VoiceModeFgs";
    private static final int FGS_TYPES = ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            | ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK;

    private PowerManager.WakeLock cpuWakeLock;
    private MediaSession mediaSession;

    public static void start(Context context) {
        Context app = context.getApplicationContext();
        Intent intent = new Intent(app, VoiceModeForegroundService.class);
        intent.setAction(ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            app.startForegroundService(intent);
        } else {
            app.startService(intent);
        }
    }

    public static void stop(Context context) {
        context.getApplicationContext().stopService(
                new Intent(context.getApplicationContext(), VoiceModeForegroundService.class));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        ensureMediaSession();
        promoteToForeground();
        acquireCpuWakeLock();
        FileLogger.log(TAG, "onStartCommand action="
                + (intent != null ? intent.getAction() : "null"));
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        releaseMediaSession();
        releaseCpuWakeLock();
        FileLogger.log(TAG, "onDestroy");
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void promoteToForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                    VoiceModeNotification.NOTIFICATION_ID,
                    VoiceModeNotification.build(this, mediaSession),
                    FGS_TYPES);
        } else {
            startForeground(
                    VoiceModeNotification.NOTIFICATION_ID,
                    VoiceModeNotification.build(this, mediaSession));
        }
    }

    private void ensureMediaSession() {
        if (mediaSession != null) {
            return;
        }
        mediaSession = new MediaSession(this, "chatbot:voice-mode");
        mediaSession.setMetadata(new MediaMetadata.Builder()
                .putString(MediaMetadata.METADATA_KEY_TITLE,
                        getString(R.string.voice_mode_notification_title))
                .putString(MediaMetadata.METADATA_KEY_ARTIST,
                        getString(R.string.voice_mode_notification_text))
                .putString(MediaMetadata.METADATA_KEY_DISPLAY_TITLE,
                        getString(R.string.voice_mode_notification_title))
                .build());
        mediaSession.setPlaybackState(new PlaybackState.Builder()
                .setActions(PlaybackState.ACTION_STOP | PlaybackState.ACTION_PAUSE)
                .setState(PlaybackState.STATE_PLAYING, PlaybackState.PLAYBACK_POSITION_UNKNOWN, 1f)
                .build());
        mediaSession.setCallback(new MediaSession.Callback() {
            @Override
            public void onStop() {
                requestStopFromSession();
            }

            @Override
            public void onPause() {
                requestStopFromSession();
            }
        });
        mediaSession.setActive(true);
    }

    private void requestStopFromSession() {
        VoiceModeNativeHooks.requestStop();
        stop(this);
    }

    private void releaseMediaSession() {
        if (mediaSession == null) {
            return;
        }
        mediaSession.setActive(false);
        mediaSession.release();
        mediaSession = null;
    }

    private void acquireCpuWakeLock() {
        if (cpuWakeLock != null && cpuWakeLock.isHeld()) {
            return;
        }
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm == null) {
            return;
        }
        cpuWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "chatbot:voice-mode");
        cpuWakeLock.setReferenceCounted(false);
        cpuWakeLock.acquire();
    }

    private void releaseCpuWakeLock() {
        if (cpuWakeLock != null && cpuWakeLock.isHeld()) {
            cpuWakeLock.release();
        }
        cpuWakeLock = null;
    }
}
