package com.chatbot.app;

import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.util.concurrent.Executor;

import com.chatbot.app.Logger.LoggerPlugin;
import com.chatbot.app.NativeVoiceTtsPlugin;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.util.FileLogger;
import com.getcapacitor.BridgeActivity;
import com.getcapacitor.CapConfig;

public class MainActivity extends BridgeActivity {
    private static final String TAG = "MainActivity";
    public static final long RESUME_LOCK_GRACE_MS = 60_000; // 1 minute
    private long backgroundedAt = 0;
    private boolean isLocked = false;
    private FrameLayout lockOverlay = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        FileLogger.init(getApplicationContext());
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );
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
    public void onResume() {
        super.onResume();
        checkResumeLock();
    }

    @Override
    public void onPause() {
        super.onPause();
        keepVoiceWebViewRunning();
        if (!isFinishing()) {
            backgroundedAt = SystemClock.elapsedRealtime();
        }
    }

    @Override
    public void onStop() {
        super.onStop();
        keepVoiceWebViewRunning();
    }

    private void checkResumeLock() {
        if (backgroundedAt > 0) {
            long elapsed = SystemClock.elapsedRealtime() - backgroundedAt;
            if (elapsed >= RESUME_LOCK_GRACE_MS) {
                if (!VoiceModeForegroundSession.get().isActive() && isUserLoggedIn()) {
                    lockApp();
                    return;
                }
            }
            backgroundedAt = 0;
        }
    }

    private boolean isUserLoggedIn() {
        try {
            String serverUrl = getString(R.string.server_url);
            String cookieHeader = CookieManager.getInstance().getCookie(serverUrl);
            if (cookieHeader != null) {
                for (String part : cookieHeader.split(";")) {
                    String trimmed = part.trim();
                    if (trimmed.startsWith("session=") && trimmed.length() > "session=".length()) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "isUserLoggedIn check failed", e);
        }
        return false;
    }

    private void lockApp() {
        if (isLocked) {
            return;
        }
        isLocked = true;
        runOnUiThread(() -> {
            ensureLockOverlay();
            if (lockOverlay != null) {
                lockOverlay.setVisibility(View.VISIBLE);
            }
            promptResumeUnlock();
        });
    }

    private void ensureLockOverlay() {
        if (lockOverlay != null) {
            return;
        }
        FrameLayout root = findViewById(android.R.id.content);
        if (root == null) {
            return;
        }
        lockOverlay = new FrameLayout(this);
        lockOverlay.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        lockOverlay.setBackgroundColor(0xFF121212);
        lockOverlay.setClickable(true);
        lockOverlay.setFocusable(true);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        layoutParams.gravity = Gravity.CENTER;
        layout.setLayoutParams(layoutParams);

        TextView title = new TextView(this);
        title.setText("Chatbot");
        title.setTextColor(0xFFFFFFFF);
        title.setTextSize(24f);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 16);
        layout.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Session locked for privacy");
        subtitle.setTextColor(0xFFAAAAAA);
        subtitle.setTextSize(14f);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 0, 0, 32);
        layout.addView(subtitle);

        Button unlockBtn = new Button(this);
        unlockBtn.setText("Unlock");
        unlockBtn.setOnClickListener(v -> promptResumeUnlock());
        layout.addView(unlockBtn);

        Button switchBtn = new Button(this);
        switchBtn.setText("Switch Account");
        switchBtn.setOnClickListener(v -> {
            unlockApp();
            if (getBridge() != null && getBridge().getWebView() != null) {
                getBridge().getWebView().loadUrl(getString(R.string.server_url) + "/login");
            }
        });
        layout.addView(switchBtn);

        lockOverlay.addView(layout);
        root.addView(lockOverlay);
    }

    private void promptResumeUnlock() {
        BiometricManager biometricManager = BiometricManager.from(this);
        int authenticators;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK
                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        } else {
            authenticators = BiometricManager.Authenticators.BIOMETRIC_WEAK;
        }
        if (biometricManager.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            unlockApp();
            return;
        }
        Executor executor = ContextCompat.getMainExecutor(this);
        BiometricPrompt prompt = new BiometricPrompt(
                this,
                executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        unlockApp();
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        Log.w(TAG, "resume unlock error: " + errString);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                    }
                }
        );

        BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Chatbot")
                .setSubtitle("Confirm with fingerprint or device PIN");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG
                            | BiometricManager.Authenticators.DEVICE_CREDENTIAL
            );
        } else {
            builder.setDeviceCredentialAllowed(true);
        }
        prompt.authenticate(builder.build());
    }

    private void unlockApp() {
        isLocked = false;
        backgroundedAt = 0;
        if (lockOverlay != null) {
            lockOverlay.setVisibility(View.GONE);
        }
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
