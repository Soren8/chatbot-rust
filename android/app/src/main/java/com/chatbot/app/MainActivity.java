package com.chatbot.app;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;

import com.chatbot.app.Logger.LoggerPlugin;
import com.chatbot.app.NativeVoiceTtsPlugin;
import com.chatbot.app.audio.VoiceModeForegroundSession;
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
            webView.getSettings().setCacheMode(WebSettings.LOAD_DEFAULT);
            Log.i(TAG, "WebView HTTP cache enabled (LOAD_DEFAULT)");
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        keepVoiceWebViewRunning();
    }

    @Override
    public void onStop() {
        super.onStop();
        keepVoiceWebViewRunning();
    }

    public void keepVoiceWebViewRunning() {
        if (!VoiceModeForegroundSession.get().isActive()) {
            return;
        }
        runOnUiThread(() -> {
            if (!VoiceModeForegroundSession.get().isActive()
                    || isFinishing()
                    || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1 && isDestroyed())
                    || getBridge() == null) {
                return;
            }
            WebView webView = getBridge().getWebView();
            if (webView == null) {
                return;
            }
            webView.onResume();
            webView.resumeTimers();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                webView.setRendererPriorityPolicy(WebView.RENDERER_PRIORITY_IMPORTANT, false);
            }
            webView.evaluateJavascript("void 0", null);
        });
    }
}
