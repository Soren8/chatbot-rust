package com.chatbot.app.audio;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.session.MediaSession;
import android.os.Build;

import com.chatbot.app.R;

/**
 * Ongoing lock-screen media notification for a live voice-mode session.
 *
 * A bare FGS chip is hidden on the keyguard. Attach a {@link MediaSession}
 * so Android shows the compact media bar (title + Stop) after the user wakes
 * the screen, without unlocking. Stop is a broadcast — do not launch an
 * Activity for it.
 */
public final class VoiceModeNotification {
    public static final String ACTION_STOP = "com.chatbot.app.STOP_VOICE_MODE";
    public static final String CHANNEL_ID = "voice_mode_lock";
    public static final int NOTIFICATION_ID = 7101;

    private VoiceModeNotification() {}

    @SuppressWarnings("deprecation")
    public static Notification build(Context context, MediaSession session) {
        ensureChannel(context);
        Notification.Action stopAction = new Notification.Action.Builder(
                android.R.drawable.ic_media_pause,
                context.getString(R.string.voice_mode_notification_stop),
                stopBroadcast(context))
                .build();
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);
        Notification.MediaStyle style = new Notification.MediaStyle()
                .setShowActionsInCompactView(0);
        if (session != null) {
            style.setMediaSession(session.getSessionToken());
        }
        builder.setSmallIcon(android.R.drawable.ic_btn_speak_now)
                .setContentTitle(context.getString(R.string.voice_mode_notification_title))
                .setContentText(context.getString(R.string.voice_mode_notification_text))
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setVisibility(Notification.VISIBILITY_PUBLIC)
                .setCategory(Notification.CATEGORY_TRANSPORT)
                .addAction(stopAction)
                .setStyle(style);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            builder.setPriority(Notification.PRIORITY_HIGH);
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
        manager.deleteNotificationChannel("voice_mode");
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.voice_mode_notification_channel),
                NotificationManager.IMPORTANCE_HIGH);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }
}
