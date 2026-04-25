package com.chatbot.app.car;

import android.content.ComponentName;
import android.content.Intent;
import android.util.Log;

import androidx.car.app.CarAppService;
import androidx.car.app.Screen;
import androidx.car.app.Session;
import androidx.car.app.validation.HostValidator;

public class VoiceSession extends Session {
    private static final String TAG = "VoiceSession";
    private VoiceScreen voiceScreen;

    @Override
    public Screen onCreateScreen(Intent intent) {
        Log.i(TAG, "Creating voice screen");
        voiceScreen = new VoiceScreen(getCarContext());
        return voiceScreen;
    }
}