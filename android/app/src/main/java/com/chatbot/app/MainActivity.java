package com.chatbot.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
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
import com.chatbot.app.util.ClientLogReporter;
import com.chatbot.app.util.FileLogger;
import com.chatbot.app.util.ServerUrlResolver;
import com.chatbot.app.util.ServerUrlSetting;
import com.chatbot.app.util.ServerUrlSettingStore;
import com.getcapacitor.BridgeActivity;
import com.getcapacitor.BridgeWebViewClient;
import com.getcapacitor.CapConfig;

public class MainActivity extends BridgeActivity {
    private static final String TAG = "MainActivity";
    public static final long RESUME_LOCK_GRACE_MS = 60_000; // 1 minute
    private static final int SETTINGS_REQUEST = 4071;
    private long backgroundedAt = 0;
    private boolean isLocked = false;
    private FrameLayout lockOverlay = null;
    private FrameLayout offlineOverlay = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        FileLogger.init(getApplicationContext());
        ClientLogReporter.init(getApplicationContext());
        installCrashReporter();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false);
        }
        updateWindowSecurity(false);
        registerPlugin(NativeMicPlugin.class);
        registerPlugin(NativeVoiceTtsPlugin.class);
        registerPlugin(NativeSecureKeyPlugin.class);
        registerPlugin(LoggerPlugin.class);
        super.onCreate(savedInstanceState);
        installOfflineErrorHandler();
        installServerMenuEntry();
    }

    /**
     * Offline/error entry point: when the main frame fails (server
     * unreachable, HTTP error), a native overlay offers Retry and Change
     * server. Without the server there is no WebView page able to host a
     * settings link, so the entry lives in native UI.
     */
    private void installOfflineErrorHandler() {
        if (getBridge() == null || getBridge().getWebView() == null) {
            return;
        }
        getBridge().setWebViewClient(new BridgeWebViewClient(getBridge()) {
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request,
                    WebResourceError error) {
                super.onReceivedError(view, request, error);
                if (request != null && request.isForMainFrame()) {
                    showOfflineOverlay();
                }
            }

            @Override
            public void onReceivedHttpError(WebView view, WebResourceRequest request,
                    WebResourceResponse errorResponse) {
                super.onReceivedHttpError(view, request, errorResponse);
                if (request != null && request.isForMainFrame()) {
                    showOfflineOverlay();
                }
            }
        });
    }

    /**
     * Small always-available server entry pinned to the content edge: works
     * while the server is reachable and offline. Kept compact and translucent
     * so it does not obstruct page content.
     */
    private void installServerMenuEntry() {
        FrameLayout root = findViewById(android.R.id.content);
        if (root == null) {
            return;
        }
        float density = getResources().getDisplayMetrics().density;
        TextView menu = new TextView(this);
        menu.setText("⚙");
        menu.setTextSize(18f);
        menu.setTextColor(0xFFFFFFFF);
        menu.setGravity(Gravity.CENTER);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                (int) (34 * density), (int) (34 * density));
        params.gravity = Gravity.TOP | Gravity.END;
        params.setMargins(0, (int) (6 * density), (int) (6 * density), 0);
        menu.setBackgroundColor(0x66000000);
        menu.setOnClickListener(v -> openServerSettings());
        root.addView(menu, params);
    }


    /**
     * Debug builds upload the crash plus recent FileLogger lines to the
     * webserver (POST /client_logs) before chaining to the previous
     * handler. Every step is exception-guarded so a reporter failure can
     * never break normal crash handling.
     */
    private void installCrashReporter() {
        final Thread.UncaughtExceptionHandler previous =
                Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            try {
                FileLogger.log(TAG, "uncaught exception on thread "
                        + (thread != null ? thread.getName() : "unknown"), throwable);
            } catch (Throwable ignored) {
            }
            try {
                ClientLogReporter.reportCrash(thread, throwable);
            } catch (Throwable ignored) {
            }
            if (previous != null) {
                previous.uncaughtException(thread, throwable);
            }
        });
    }

    @Override
    protected void load() {
        // Vanadium/Chromium throttles Capacitor's WebMessage bridge in the
        // background. Keep the legacy bridge for the voice-mode event stream.
        CapConfig base = CapConfig.loadDefault(this);
        // Flavor authority + persisted user override: the WebView origin is
        // the flavor server_url resource unless a valid user-selected
        // override is persisted. capacitor.config.json carries no server.url
        // override, so the Bridge/Config URL is never consulted.
        String flavorUrl = null;
        try {
            flavorUrl = getString(R.string.server_url);
        } catch (Exception ignored) {}
        String serverUrl = ServerUrlSetting.selected(
                ServerUrlSettingStore.store(this), ServerUrlResolver.resolveCanonical(flavorUrl));
        config = new CapConfig.Builder(this)
                .setHTML5mode(base.isHTML5Mode())
                .setServerUrl(serverUrl)
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
        updateWindowSecurity(hasWindowFocus());
    }

    @Override
    public void onPause() {
        super.onPause();
        updateWindowSecurity(false);
        keepVoiceWebViewRunning();
        if (!isFinishing()) {
            backgroundedAt = SystemClock.elapsedRealtime();
        }
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        updateWindowSecurity(hasFocus);
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
                // Security gate: only a platform-confirmed foreground service
                // bypasses the lock. A merely requested (unconfirmed) session
                // must not skip biometric unlock.
                if (!VoiceModeForegroundSession.get().isConfirmed() && isUserLoggedIn()) {
                    lockApp();
                    return;
                }
            }
            backgroundedAt = 0;
        }
    }

    // Selected native origin for every consumer: flavor resource through the
    // resolver plus a persisted user override owned by ServerUrlSetting.
    private String resolveServerUrl() {
        String resourceUrl = null;
        try {
            resourceUrl = getString(R.string.server_url);
        } catch (Exception ignored) {}
        try {
            return ServerUrlSetting.selected(
                    ServerUrlSettingStore.store(this),
                    ServerUrlResolver.resolveCanonical(resourceUrl));
        } catch (Exception e) {
            Log.w(TAG, "server selection resolve failed, using flavor resource", e);
            return ServerUrlResolver.resolveCanonical(resourceUrl);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != SETTINGS_REQUEST || resultCode != Activity.RESULT_OK) {
            return;
        }
        // Selection changed inside ServerSettingsActivity (validated, cookie
        // purge + persisted there). The CapConfig origin only applies to a
        // newly created Bridge, so recreate the activity: the old Bridge and
        // its injected JS/cookie origin are fully replaced.
        try {
            NativeSecureKeyPlugin.onServerSelectionChanged();
        } catch (Throwable ignored) {}
        recreate();
    }

    /** Change-server entry point (button from the offline overlay). */
    private void openServerSettings() {
        try {
            startActivityForResult(
                    new Intent(this, ServerSettingsActivity.class), SETTINGS_REQUEST);
        } catch (Exception e) {
            Log.w(TAG, "failed to open server settings", e);
        }
    }

    private FrameLayout ensureOfflineOverlay() {
        if (offlineOverlay != null) {
            return offlineOverlay;
        }
        FrameLayout root = findViewById(android.R.id.content);
        if (root == null) {
            return null;
        }
        offlineOverlay = new FrameLayout(this);
        offlineOverlay.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));
        offlineOverlay.setBackgroundColor(0xFF121212);
        offlineOverlay.setClickable(true);
        offlineOverlay.setFocusable(true);

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
        title.setText("Server unreachable");
        title.setTextColor(0xFFFFFFFF);
        title.setTextSize(20f);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 16);
        layout.addView(title);

        TextView selected = new TextView(this);
        selected.setText(resolveServerUrl());
        selected.setTextColor(0xFF999999);
        selected.setTextSize(13f);
        selected.setGravity(Gravity.CENTER);
        selected.setPadding(0, 0, 0, 32);
        layout.addView(selected);

        Button retryBtn = new Button(this);
        retryBtn.setText("Retry");
        retryBtn.setOnClickListener(v -> {
            if (offlineOverlay != null) {
                offlineOverlay.setVisibility(View.GONE);
            }
            if (getBridge() != null && getBridge().getWebView() != null) {
                getBridge().getWebView().loadUrl(resolveServerUrl());
            }
        });
        layout.addView(retryBtn);

        Button settingsBtn = new Button(this);
        settingsBtn.setText("Change server");
        settingsBtn.setOnClickListener(v -> openServerSettings());
        layout.addView(settingsBtn);

        offlineOverlay.addView(layout);
        root.addView(offlineOverlay);
        return offlineOverlay;
    }

    private void showOfflineOverlay() {
        runOnUiThread(() -> {
            FrameLayout overlay = ensureOfflineOverlay();
            if (overlay != null) {
                overlay.setVisibility(View.VISIBLE);
            }
        });
    }

    private boolean isUserLoggedIn() {
        try {
            String serverUrl = resolveServerUrl();
            String cookieHeader = CookieManager.getInstance().getCookie(serverUrl);
            if (cookieHeader != null) {
                for (String part : cookieHeader.split(";")) {
                    String trimmed = part.trim();
                    if ((trimmed.startsWith("remember=") && trimmed.length() > "remember=".length())
                            || trimmed.startsWith("remember-")
                            || (trimmed.startsWith("enc_key=") && trimmed.length() > "enc_key=".length())
                            || trimmed.startsWith("enc_key-")) {
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
            updateWindowSecurity(hasWindowFocus());
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
                getBridge().getWebView().loadUrl(resolveServerUrl() + "/login");
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
        updateWindowSecurity(hasWindowFocus());
    }

    private void updateWindowSecurity(boolean hasFocus) {
        runOnUiThread(() -> {
            if (isLocked || !hasFocus) {
                getWindow().setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE
                );
            } else {
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        });
    }


    // Liveness only (not a security bypass): keep the JS loop running while a
    // voice-mode foreground request is outstanding. The resume biometric lock
    // above instead requires isConfirmed().
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
