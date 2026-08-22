package com.chatbot.app.audio;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import com.chatbot.app.util.FileLogger;

/**
 * Microphone foreground service for handheld voice mode with the screen off.
 * Posts an ongoing public notification so the keyguard can show Stop.
 */
public class VoiceModeForegroundService extends Service {
    public static final String ACTION_START = "com.chatbot.app.START_VOICE_MODE";
    private static final String TAG = "VoiceModeFgs";
    private static final int FGS_TYPE = ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;

    private PowerManager.WakeLock cpuWakeLock;

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
        promoteToForeground();
        acquireCpuWakeLock();
        FileLogger.log(TAG, "onStartCommand action="
                + (intent != null ? intent.getAction() : "null"));
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
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
                    VoiceModeNotification.build(this),
                    FGS_TYPE);
        } else {
            startForeground(
                    VoiceModeNotification.NOTIFICATION_ID,
                    VoiceModeNotification.build(this));
        }
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
