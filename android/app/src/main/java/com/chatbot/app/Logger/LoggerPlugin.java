package com.chatbot.app.Logger;

import android.util.Log;
import com.chatbot.app.util.ClientLogReporter;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "Logger")
public class LoggerPlugin extends Plugin {
    private static final String TAG = "VAD";

    @PluginMethod
    public void log(PluginCall call) {
        String tag = call.getString("tag", "VAD");
        String message = call.getString("message", "");
        Log.d(tag, message);
        call.resolve();
    }

    /** Upload an error report to the webserver (debug builds only; no-op otherwise). */
    @PluginMethod
    public void report(PluginCall call) {
        String level = call.getString("level", "ERROR");
        String message = call.getString("message", "");
        ClientLogReporter.report(level, message);
        call.resolve();
    }
}
