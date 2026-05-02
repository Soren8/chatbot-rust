package com.chatbot.app.car;

import android.content.Intent;
import android.util.Log;

import androidx.car.app.CarAppService;
import androidx.car.app.Session;
import androidx.car.app.validation.HostValidator;

import com.chatbot.app.util.FileLogger;

public class ChatbotCarAppService extends CarAppService {
    private static final String TAG = "ChatbotCarAppService";

    @Override
    public void onCreate() {
        super.onCreate();
        FileLogger.init(getApplicationContext());
        FileLogger.log(TAG, "=== ChatbotCarAppService.onCreate ===");
    }

    @Override
    public Session onCreateSession() {
        Log.i(TAG, "Creating Android Auto session");
        FileLogger.log(TAG, "onCreateSession called");
        return new VoiceSession();
    }

    @Override
    public HostValidator createHostValidator() {
        FileLogger.log(TAG, "createHostValidator called");
        return HostValidator.ALLOW_ALL_HOSTS_VALIDATOR;
    }
}
