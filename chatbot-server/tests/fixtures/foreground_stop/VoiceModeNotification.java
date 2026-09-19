package com.chatbot.app.audio;

import android.content.Context;

/**
 * Minimal stub of VoiceModeNotification for off-device foreground-stop
 * harnesses. Promotion is not under test; only the notification ID and a
 * build entry point are needed to compile the real foreground service.
 */
public class VoiceModeNotification {
    public static final int NOTIFICATION_ID = 7101;

    public static Object build(Context context) {
        return new Object();
    }
}
