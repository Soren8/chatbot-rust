package com.chatbot.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.webkit.CookieManager;

import com.chatbot.app.util.FileLogger;
import com.chatbot.app.util.IapSignIn;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Android glue for {@link IapSignIn}: runs the identity-aware proxy start
 * and callback requests off the main thread against the WebView cookie jar,
 * and persists the "sign-in pending" marker that survives process death
 * while the user is in the system browser.
 */
final class IapSignInFlow {
    private static final String TAG = "IapSignIn";
    private static final String PREFS_NAME = "chatbot_iap_signin";
    private static final String PREF_PENDING_SINCE = "pending_since";
    static final long PENDING_TTL_MS = 10 * 60 * 1000;
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS = 15_000;
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor(
            runnable -> new Thread(runnable, "IapSignIn"));

    /** Delivered on the worker thread; null means the step failed. */
    interface Result {
        void onResult(String url);
    }

    static final IapSignIn.Transport TRANSPORT = (url, cookieHeader) -> {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setUseCaches(false);
            connection.setRequestMethod("GET");
            if (cookieHeader != null) {
                connection.setRequestProperty("Cookie", cookieHeader);
            }
            int status = connection.getResponseCode();
            String location = connection.getHeaderField("Location");
            List<String> setCookies = new ArrayList<>();
            for (Map.Entry<String, List<String>> header : connection.getHeaderFields().entrySet()) {
                if (header.getKey() != null && "Set-Cookie".equalsIgnoreCase(header.getKey())
                        && header.getValue() != null) {
                    setCookies.addAll(header.getValue());
                }
            }
            return new IapSignIn.Response(status, location, setCookies);
        } finally {
            connection.disconnect();
        }
    };

    static final IapSignIn.CookieJar COOKIE_JAR = new IapSignIn.CookieJar() {
        @Override
        public String get(String url) {
            return CookieManager.getInstance().getCookie(url);
        }

        @Override
        public void set(String url, String setCookie) {
            CookieManager.getInstance().setCookie(url, setCookie);
        }

        @Override
        public void flush() {
            CookieManager.getInstance().flush();
        }
    };

    private IapSignInFlow() {
    }

    /** Runs the start request; on success the pending marker is persisted before delivery. */
    static void begin(Context context, String serverUrl, String startUrl, Result result) {
        Context app = context.getApplicationContext();
        EXECUTOR.execute(() -> {
            String providerUrl = null;
            try {
                providerUrl = IapSignIn.begin(serverUrl, startUrl, TRANSPORT, COOKIE_JAR);
            } catch (IOException | RuntimeException e) {
                FileLogger.log(TAG, "start request failed: " + e.getClass().getSimpleName());
            }
            if (providerUrl != null) {
                prefs(app).edit().putLong(PREF_PENDING_SINCE, System.currentTimeMillis()).commit();
            } else {
                FileLogger.log(TAG, "start request returned no provider redirect");
            }
            result.onResult(providerUrl);
        });
    }

    /** Runs the callback request; delivers the page to load, or null on failure. */
    static void complete(String serverUrl, String callbackUrl, Result result) {
        EXECUTOR.execute(() -> {
            String next = null;
            try {
                next = IapSignIn.complete(serverUrl, callbackUrl, TRANSPORT, COOKIE_JAR);
            } catch (IOException | RuntimeException e) {
                FileLogger.log(TAG, "callback request failed: " + e.getClass().getSimpleName());
            }
            FileLogger.log(TAG, next != null ? "sign-in completed" : "sign-in did not complete");
            result.onResult(next);
        });
    }

    /** Clears the marker and reports whether a fresh sign-in was pending. */
    static boolean consumePending(Context context) {
        SharedPreferences prefs = prefs(context);
        long since = prefs.getLong(PREF_PENDING_SINCE, 0);
        prefs.edit().remove(PREF_PENDING_SINCE).apply();
        long age = System.currentTimeMillis() - since;
        return since > 0 && age >= 0 && age <= PENDING_TTL_MS;
    }

    static void clearPending(Context context) {
        prefs(context).edit().remove(PREF_PENDING_SINCE).apply();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}
