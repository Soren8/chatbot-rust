package com.chatbot.app.util;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class FileLogger {
    private static final String TAG = "FileLogger";
    private static volatile File logFile;
    private static final Object lock = new Object();
    /** Recent lines for the debug-build crash/log reporter (ClientLogReporter). */
    private static final int RING_MAX_LINES = 150;
    private static final ArrayDeque<String> ring = new ArrayDeque<>();

    public static void init(Context context) {
        if (context == null) {
            return;
        }
        synchronized (lock) {
            try {
                File dir = context.getExternalFilesDir(null);
                if (dir == null) {
                    dir = context.getFilesDir();
                }
                if (dir == null) {
                    return;
                }
                File logsDir = new File(dir, "logs");
                if (!logsDir.exists()) {
                    logsDir.mkdirs();
                }
                logFile = new File(logsDir, "chatbot_auto.log");
            } catch (Throwable t) {
                Log.e(TAG, "Failed to initialize FileLogger", t);
                return;
            }
        }
        log("FileLogger", "=== Logger initialized ===");
    }

    public static void log(String tag, String msg) {
        String line = timestamp() + " [" + tag + "] " + msg;
        try {
            Log.d(tag, msg != null ? msg : "null");
        } catch (Throwable ignored) {
        }
        synchronized (lock) {
            ring.addLast(line);
            while (ring.size() > RING_MAX_LINES) {
                ring.removeFirst();
            }
            if (logFile == null) {
                return;
            }
            try (FileWriter fw = new FileWriter(logFile, true)) {
                fw.write(line + "\n");
            } catch (Throwable e) {
                Log.e(TAG, "Failed to write log", e);
            }
        }
    }

    /** Snapshot of the most recent log lines, oldest first. */
    public static List<String> snapshotLines() {
        synchronized (lock) {
            return new ArrayList<>(ring);
        }
    }

    public static void log(String tag, String msg, Throwable t) {
        String trace = t != null ? Log.getStackTraceString(t) : "";
        log(tag, (msg != null ? msg : "") + " | " + trace);
    }

    private static String timestamp() {
        try {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(new Date());
        } catch (Throwable t) {
            return "";
        }
    }
}
