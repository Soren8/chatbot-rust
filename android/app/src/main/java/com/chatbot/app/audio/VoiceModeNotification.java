package com.chatbot.app.audio;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Person;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;
import android.os.Build;

import com.chatbot.app.R;

/**
 * Ongoing lock-screen banner for a live voice-mode session.
 *
 * Do not attach a {@link android.media.session.MediaSession}: SystemUI moves
 * that into the media player and GrapheneOS/AOSP hide it unless real
 * {@code USAGE_MEDIA} audio is playing, so the shade row disappears too.
 * {@link Notification.CallStyle} is the lock-screen template that stays a
 * bar with hangup. {@code POST_NOTIFICATIONS} is required on API 33+.
 * Hangup/Stop is a broadcast — do not launch an Activity for it.
 */
public final class VoiceModeNotification {
    public static final String ACTION_STOP = "com.chatbot.app.STOP_VOICE_MODE";
    public static final String CHANNEL_ID = "voice_mode_call";
    public static final int NOTIFICATION_ID = 7101;

    private VoiceModeNotification() {}

    @SuppressWarnings("deprecation")
    public static Notification build(Context context) {
        ensureChannel(context);
        PendingIntent hangup = stopBroadcast(context);
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(context, CHANNEL_ID)
                : new Notification.Builder(context);
        builder.setSmallIcon(android.R.drawable.ic_btn_speak_now)
                .setContentTitle(context.getString(R.string.voice_mode_notification_title))
                .setContentText(context.getString(R.string.voice_mode_notification_text))
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setVisibility(Notification.VISIBILITY_PUBLIC);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Person person = new Person.Builder()
                    .setName(context.getString(R.string.voice_mode_notification_title))
                    .setIcon(Icon.createWithBitmap(appArtwork(context)))
                    .setImportant(true)
                    .build();
            builder.setCategory(Notification.CATEGORY_CALL)
                    .setStyle(Notification.CallStyle.forOngoingCall(person, hangup))
                    .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        } else {
            builder.setCategory(Notification.CATEGORY_SERVICE)
                    .setLargeIcon(appArtwork(context))
                    .addAction(new Notification.Action.Builder(
                            android.R.drawable.ic_menu_close_clear_cancel,
                            context.getString(R.string.voice_mode_notification_stop),
                            hangup)
                            .build())
                    .setStyle(new Notification.MediaStyle().setShowActionsInCompactView(0));
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                builder.setPriority(Notification.PRIORITY_HIGH);
            }
        }
        return builder.build();
    }

    static Bitmap appArtwork(Context context) {
        try {
            Drawable d = context.getApplicationInfo().loadIcon(context.getPackageManager());
            if (d instanceof BitmapDrawable) {
                Bitmap bitmap = ((BitmapDrawable) d).getBitmap();
                if (bitmap != null) {
                    return bitmap;
                }
            }
            if (d != null) {
                int w = Math.max(d.getIntrinsicWidth(), 1);
                int h = Math.max(d.getIntrinsicHeight(), 1);
                Bitmap bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
                Canvas canvas = new Canvas(bitmap);
                d.setBounds(0, 0, canvas.getWidth(), canvas.getHeight());
                d.draw(canvas);
                return bitmap;
            }
        } catch (Throwable ignored) {
        }
        return Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888);
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
        manager.deleteNotificationChannel("voice_mode_lock");
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.voice_mode_notification_channel),
                NotificationManager.IMPORTANCE_HIGH);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }
}
