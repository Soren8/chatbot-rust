package com.chatbot.app;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.webkit.WebSettings;
import android.webkit.WebView;

import com.chatbot.app.Logger.LoggerPlugin;
import com.chatbot.app.NativeVoiceTtsPlugin;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.getcapacitor.BridgeActivity;
import com.getcapacitor.CapConfig;

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
    protected void load() {
        // Vanadium/Chromium throttles Capacitor's WebMessage bridge in the
        // background. Keep the legacy bridge for the voice-mode event stream.
        CapConfig base = CapConfig.loadDefault(this);
        config = new CapConfig.Builder(this)
                .setHTML5mode(base.isHTML5Mode())
                .setServerUrl(base.getServerUrl())
                .setErrorPath(base.getErrorPath())
                .setHostname(base.getHostname())
                .setStartPath(base.getStartPath())
                .setAndroidScheme(base.getAndroidScheme())
                .setAllowNavigation(base.getAllowNavigation())
                .setOverriddenUserAgentString(base.getOverriddenUserAgentString())
                .setAppendedUserAgentString(base.getAppendedUserAgentString())
                .setBackgroundColor(base.getBackgroundColor())
                .setAllowMixedContent(base.isMixedContentAllowed())
                .setCaptureInput(base.isInputCaptured())
                .setUseLegacyBridge(true)
                .setResolveServiceWorkerRequests(base.isResolveServiceWorkerRequests())
                .setWebContentsDebuggingEnabled(base.isWebContentsDebuggingEnabled())
                .setZoomableWebView(base.isZoomableWebView())
                .setLoggingEnabled(base.isLoggingEnabled())
                .setInitialFocus(base.isInitialFocus())
                .setPluginsConfiguration(base.getObject("plugins"))
                .create();
        super.load();
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
            // Chromium may mark a hidden WebView as background-optimized even
            // while the app owns a foreground service. Reassert visibility for
            // the active voice session so native mic events reach JavaScript.
            webView.dispatchWindowVisibilityChanged(View.VISIBLE);
            webView.evaluateJavascript("void 0", null);
        });
    }
}
