package com.chatbot.app.car;

import android.content.Intent;
import android.util.Log;

import androidx.car.app.CarAppService;
import androidx.car.app.Session;
import androidx.car.app.validation.HostValidator;

public class ChatbotCarAppService extends CarAppService {
    private static final String TAG = "ChatbotCarAppService";

    @Override
    public Session onCreateSession() {
        Log.i(TAG, "Creating Android Auto session");
        return new VoiceSession();
    }

    @Override
    public HostValidator createHostValidator() {
        return HostValidator.ALLOW_ALL_HOSTS_VALIDATOR;
    }
}