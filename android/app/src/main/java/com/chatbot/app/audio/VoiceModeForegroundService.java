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
        if (context == null) {
            return;
        }
        try {
            Context app = context.getApplicationContext();
            Intent intent = new Intent(app, VoiceModeForegroundService.class);
            intent.setAction(ACTION_START);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                app.startForegroundService(intent);
            } else {
                app.startService(intent);
            }
        } catch (Exception e) {
            FileLogger.log(TAG, "start failed: " + e.getMessage(), e);
        }
    }

    public static void stop(Context context) {
        if (context == null) {
            return;
        }
        try {
            context.getApplicationContext().stopService(
                    new Intent(context.getApplicationContext(), VoiceModeForegroundService.class));
        } catch (Exception e) {
            FileLogger.log(TAG, "stop failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        FileLogger.init(getApplicationContext());
        FileLogger.log(TAG, "onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            FileLogger.log(TAG, "onStartCommand called with null intent, stopping");
            stopSelf();
            return START_NOT_STICKY;
        }
        promoteToForeground();
        acquireCpuWakeLock();
        acquireNetwork();
        startKeepAlive();
        FileLogger.log(TAG, "onStartCommand action=" + intent.getAction());
        return START_NOT_STICKY;
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
        try {
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
        } catch (Exception e) {
            FileLogger.log(TAG, "promoteToForeground failed: " + e.getMessage(), e);
            stopSelf();
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
        try {
            if (cpuWakeLock == null) {
                cpuWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "chatbot:voice-mode");
                cpuWakeLock.setReferenceCounted(false);
            }
            if (!cpuWakeLock.isHeld()) {
                cpuWakeLock.acquire();
            }
        } catch (Exception e) {
            FileLogger.log(TAG, "acquireCpuWakeLock failed: " + e.getMessage(), e);
        }
    }

    private void releaseCpuWakeLock() {
        try {
            if (cpuWakeLock != null && cpuWakeLock.isHeld()) {
                cpuWakeLock.release();
            }
        } catch (Exception e) {
            FileLogger.log(TAG, "releaseCpuWakeLock failed: " + e.getMessage(), e);
        } finally {
            cpuWakeLock = null;
        }
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
