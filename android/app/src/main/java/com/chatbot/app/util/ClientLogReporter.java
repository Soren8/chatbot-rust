package com.chatbot.app.util;

import android.content.Context;
import android.util.Log;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import android.webkit.CookieManager;

import com.chatbot.app.BuildConfig;
import com.chatbot.app.R;

/**
 * Ships Android error/crash logs to the webserver's POST /client_logs so
 * field problems are visible in host logs instead of only adb logcat.
 *
 * Debug builds only ({@code BuildConfig.DEBUG}); release builds are silent.
 * Lines are sanitized again server-side (defense in depth). The server
 * authorizes on the session cookie — the native side has no CSRF token.
 */
public final class ClientLogReporter {
    private static final String TAG = "ClientLogReporter";
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int CRASH_CONNECT_TIMEOUT_MS = 3000;
    private static final int CRASH_READ_TIMEOUT_MS = 3000;
    private static final int MAX_LINES_PER_REPORT = 64;
    private static final int MAX_LINE_CHARS = 512;

    private static volatile String serverUrl;

    private ClientLogReporter() {
    }

    public static void init(Context context) {
        if (context == null) {
            return;
        }
        try {
            String url = context.getString(R.string.server_url);
            if (url != null && !url.trim().isEmpty()) {
                serverUrl = url.trim().replaceAll("/+$", "");
            }
        } catch (Throwable t) {
            Log.w(TAG, "init failed to resolve server_url", t);
        }
    }

    private static boolean enabled() {
        return serverUrl != null && BuildConfig.DEBUG;
    }

    /** Asynchronous report for non-fatal errors (Logger.report bridge, exceptions). */
    public static void report(String level, String message) {
        if (!enabled() || message == null || message.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        appendLine(sb, level + ": " + message);
        post(serverUrl + "/client_logs", sb.toString(), false, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS);
    }

    /**
     * Synchronous best-effort upload from the uncaught-exception handler:
     * the process is about to die, so a background thread would not survive.
     * Bounded to a few seconds so crash handling stays prompt.
     */
    public static void reportCrash(Thread thread, Throwable throwable) {
        if (!enabled()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("CRASH: uncaught exception on thread ")
                .append(thread != null ? thread.getName() : "unknown")
                .append('\n');
        if (throwable != null) {
            sb.append(Log.getStackTraceString(throwable));
        }
        List<String> history = FileLogger.snapshotLines();
        int start = Math.max(0, history.size() - (MAX_LINES_PER_REPORT - 2));
        for (int i = start; i < history.size(); i++) {
            appendLine(sb, history.get(i));
        }
        post(serverUrl + "/client_logs", sb.toString(), true, CRASH_CONNECT_TIMEOUT_MS, CRASH_READ_TIMEOUT_MS);
    }

    private static void appendLine(StringBuilder sb, String line) {
        if (line == null) {
            return;
        }
        String trimmed = line.length() > MAX_LINE_CHARS ? line.substring(0, MAX_LINE_CHARS) : line;
        sb.append(trimmed.replace("\n", " | ")).append('\n');
    }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static void post(String urlStr, String bodyText, boolean synchronous, int connectTimeoutMs, int readTimeoutMs) {
        // Never throw into a crash handler or plugin call; report failures are
        // logcat-only and must not recurse back into FileLogger/reporter.
        try {
            if (synchronous) {
                postOnce(urlStr, bodyText, connectTimeoutMs, readTimeoutMs);
            } else {
                Thread worker = new Thread(() -> {
                    try {
                        postOnce(urlStr, bodyText, connectTimeoutMs, readTimeoutMs);
                    } catch (Throwable t) {
                        Log.e(TAG, "report failed", t);
                    }
                }, "ClientLogReporter");
                worker.setDaemon(true);
                worker.start();
            }
        } catch (Throwable t) {
            Log.e(TAG, "report scheduling failed", t);
        }
    }

    private static void postOnce(String urlStr, String bodyText, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            String cookie = CookieManager.getInstance().getCookie(urlStr);
            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }
            conn.setDoOutput(true);
            byte[] payload = ("{\"source\":\"android\",\"lines\":[\""
                    + jsonEscape(bodyText) + "\"]}").getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload);
            }
            int code = conn.getResponseCode();
            try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
                byte[] buf = new byte[1024];
                while (is != null && is.read(buf) != -1) {
                    // drain
                }
            }
            Log.d(TAG, "report code=" + code);
        } finally {
            conn.disconnect();
        }
    }
}
