package com.chatbot.app.util;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class FileLogger {
    private static final String TAG = "FileLogger";
    private static File logFile;
    private static final Object lock = new Object();

    public static void init(Context context) {
        File dir = new File(context.getExternalFilesDir(null), "logs");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        logFile = new File(dir, "chatbot_auto.log");
        log("FileLogger", "=== Logger initialized ===");
    }

    public static void log(String tag, String msg) {
        String line = timestamp() + " [" + tag + "] " + msg;
        Log.d(tag, msg);
        synchronized (lock) {
            try (FileWriter fw = new FileWriter(logFile, true)) {
                fw.write(line + "\n");
            } catch (IOException e) {
                Log.e(TAG, "Failed to write log", e);
            }
        }
    }

    public static void log(String tag, String msg, Throwable t) {
        log(tag, msg + " | " + Log.getStackTraceString(t));
    }

    private static String timestamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(new Date());
    }
}
