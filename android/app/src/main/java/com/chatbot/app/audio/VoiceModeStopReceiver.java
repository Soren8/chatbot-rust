package com.chatbot.app.audio;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Lock-screen Stop. Broadcast so the keyguard does not have to unlock.
 */
public class VoiceModeStopReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !VoiceModeNotification.ACTION_STOP.equals(intent.getAction())) {
            return;
        }
        VoiceModeNativeHooks.requestStop();
        VoiceModeForegroundService.stop(context);
    }
}
