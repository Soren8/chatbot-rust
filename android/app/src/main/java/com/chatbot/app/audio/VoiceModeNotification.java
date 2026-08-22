package com.chatbot.app.audio;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.chatbot.app.R;

/**
 * Ongoing lock-screen notification for a live voice-mode session.
 *
 * Stop is a {@link PendingIntent#getBroadcast} so it works after the user
 * wakes the screen without unlocking. Do not launch an Activity for Stop —
 * that requires the keyguard.
 */
public final class VoiceModeNotification {
    public static final String ACTION_STOP = "com.chatbot.app.STOP_VOICE_MODE";
    public static final String CHANNEL_ID = "voice_mode";
    public static final int NOTIFICATION_ID = 7101;

    private VoiceModeNotification() {}

    @SuppressWarnings("deprecation")
    public static Notification build(Context context) {
        ensureChannel(context);
        Notification.Action stopAction = new Notification.Action.Builder(
                android.R.drawable.ic_menu_close_clear_cancel,
                context.getString(R.string.voice_mode_notification_stop),
                stopBroadcast(context))
                .build();
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);
        builder.setSmallIcon(android.R.drawable.ic_btn_speak_now)
                .setContentTitle(context.getString(R.string.voice_mode_notification_title))
                .setContentText(context.getString(R.string.voice_mode_notification_text))
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setVisibility(Notification.VISIBILITY_PUBLIC)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(stopAction)
                .setStyle(new Notification.MediaStyle().setShowActionsInCompactView(0));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        }
        return builder.build();
    }

    static PendingIntent stopBroadcast(Context context) {
        Intent intent = new Intent(context, VoiceModeStopReceiver.class);
        intent.setAction(ACTION_STOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getBroadcast(context, 0, intent, flags);
    }

    private static void ensureChannel(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.voice_mode_notification_channel),
                NotificationManager.IMPORTANCE_DEFAULT);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        channel.setSound(null, null);
        channel.enableVibration(false);
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }
}
