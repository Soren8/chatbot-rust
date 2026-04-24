package com.chatbot.app;

import android.os.Bundle;
import android.util.Log;

import com.chatbot.app.NativeMicPlugin;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        initialPlugins.add(NativeMicPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
