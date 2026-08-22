package com.chatbot.app.audio;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;

import com.chatbot.app.util.FileLogger;

/**
 * Microphone foreground service for handheld voice mode with the screen off.
 * Posts an ongoing CallStyle banner so the keyguard can show Stop.
 */
public class VoiceModeForegroundService extends Service {
    public static final String ACTION_START = "com.chatbot.app.START_VOICE_MODE";
    private static final String TAG = "VoiceModeFgs";
    private static final int FGS_TYPE = ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
    /** Chromium freezes a background WebView after a few minutes; re-resume before that. */
    private static final long KEEP_ALIVE_INTERVAL_MS = 15_000;

    private PowerManager.WakeLock cpuWakeLock;
    private ConnectivityManager.NetworkCallback networkCallback;
    private final Handler keepAliveHandler = new Handler(Looper.getMainLooper());
    private final Runnable keepAliveTick = new Runnable() {
        @Override
        public void run() {
            acquireCpuWakeLock();
            VoiceModeNativeHooks.keepWebViewAlive();
            keepAliveHandler.postDelayed(this, KEEP_ALIVE_INTERVAL_MS);
        }
    };

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
        acquireNetwork();
        startKeepAlive();
        FileLogger.log(TAG, "onStartCommand action="
                + (intent != null ? intent.getAction() : "null"));
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopKeepAlive();
        releaseNetwork();
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

    private void acquireNetwork() {
        if (networkCallback != null) {
            return;
        }
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) {
            return;
        }
        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();
        networkCallback = new ConnectivityManager.NetworkCallback();
        try {
            cm.requestNetwork(request, networkCallback);
            FileLogger.log(TAG, "requestNetwork held");
        } catch (Exception e) {
            networkCallback = null;
            FileLogger.log(TAG, "requestNetwork failed: " + e.getMessage(), e);
        }
    }

    private void releaseNetwork() {
        if (networkCallback == null) {
            return;
        }
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm != null) {
            try {
                cm.unregisterNetworkCallback(networkCallback);
            } catch (Exception ignored) {
            }
        }
        networkCallback = null;
    }

    private void startKeepAlive() {
        keepAliveHandler.removeCallbacks(keepAliveTick);
        keepAliveHandler.post(keepAliveTick);
    }

    private void stopKeepAlive() {
        keepAliveHandler.removeCallbacks(keepAliveTick);
    }
}
