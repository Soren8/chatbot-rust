package com.chatbot.app;

import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;

import com.chatbot.app.Logger.LoggerPlugin;
import com.chatbot.app.NativeVoiceTtsPlugin;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        registerPlugin(NativeMicPlugin.class);
        registerPlugin(NativeVoiceTtsPlugin.class);
        registerPlugin(NativeSecureKeyPlugin.class);
        registerPlugin(LoggerPlugin.class);
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onStart() {
        super.onStart();
        WebView webView = getBridge().getWebView();
        if (webView != null) {
            webView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);
            Log.i(TAG, "Disabled WebView caching");
        }
    }
}
