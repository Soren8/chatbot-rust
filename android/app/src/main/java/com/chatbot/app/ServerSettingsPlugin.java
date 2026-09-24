package com.chatbot.app;

import android.app.Activity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Web entry point for the native server-selection screen. The WebView hosts
 * the online Server controls (settings panel + login); this bridge delegates to
 * {@link MainActivity#openServerSettings} so the validated purge-then-persist
 * plus activity-result recreate path stays in one place.
 */
@CapacitorPlugin(name = "ServerSettings")
public class ServerSettingsPlugin extends Plugin {
    @PluginMethod
    public void open(PluginCall call) {
        Activity activity = getActivity();
        if (!(activity instanceof MainActivity)) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            try {
                ((MainActivity) activity).openServerSettings();
            } catch (Exception e) {
                android.util.Log.w("ServerSettings", "failed to open server settings", e);
            }
        });
        JSObject result = new JSObject();
        result.put("opened", true);
        call.resolve(result);
    }
}
