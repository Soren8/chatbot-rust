package android.app;

import android.content.Context;
import android.content.Intent;
import android.os.IBinder;

/**
 * Minimal stub of android.app.Service for off-device javac harnesses.
 * Only the lifecycle surface touched by VoiceModeForegroundService is
 * provided.
 */
public class Service extends Context {
    public static final int START_NOT_STICKY = 2;
    public static final int START_STICKY = 1;

    public void onCreate() {
    }

    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    public void onDestroy() {
    }

    public IBinder onBind(Intent intent) {
        return null;
    }

    public void stopSelf() {
    }

    public void startForeground(int id, Object notification) {
    }

    public void startForeground(int id, Object notification, int type) {
    }
}
