package com.chatbot.app.car;

import android.content.Intent;
import android.util.Log;

import androidx.car.app.Screen;
import androidx.car.app.Session;

public class VoiceSession extends Session {
    private static final String TAG = "VoiceSession";

    @Override
    public Screen onCreateScreen(Intent intent) {
        Log.i(TAG, "Creating voice screen");
        return new VoiceScreen(getCarContext());
    }
}