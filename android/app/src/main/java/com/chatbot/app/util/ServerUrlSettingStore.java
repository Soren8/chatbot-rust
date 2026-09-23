package com.chatbot.app.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import android.util.Log;

import com.chatbot.app.CredentialCookies;
import com.chatbot.app.R;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Android glue for {@link ServerUrlSetting}: resolves the flavor default,
 * binds the persisted override to SharedPreferences, executes an origin
 * change with its scoped-cookie purge and exposes the selected origin for
 * every native consumer.
 */
public final class ServerUrlSettingStore {
    private static final String TAG = "ServerSetting";
    public static final String PREFS_NAME = "chatbot_server_setting";
    public static final String PREF_OVERRIDE = "server_url_override";
    private static final String INVALID_MESSAGE =
            "Enter a valid https:// address (host[:port] only, no path, userinfo, query or fragment)";
    /** Fallback delay bounding the async purge; expiry reports failure. */
    private static final long PURGE_FALLBACK_MS = 2500;

    /** Outcome of an attempted selection change. */
    public static final class Change {
        public final boolean applied;
        public final boolean success;
        public final String error;
        /** Old origin whose switch cookies were purged, or null if none. */
        public final String purgedOrigin;
        /** New origin when applied (else null). */
        public final String value;

        Change(boolean applied, boolean success, String error, String purgedOrigin,
                String value) {
            this.applied = applied;
            this.success = success;
            this.error = error;
            this.purgedOrigin = purgedOrigin;
            this.value = value;
        }
    }

    /** Async selection-change delivery; always invoked on the main thread. */
    public interface ChangeCallback {
        void onChange(Change change);
    }

    private ServerUrlSettingStore() {
    }

    private static SharedPreferences prefs(Context appContext) {
        return appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Persistence handle over the given context's application prefs. */
    public static ServerUrlSetting.Store store(final Context context) {
        if (context == null) {
            return null;
        }
        final Context app = context.getApplicationContext();
        return new ServerUrlSetting.Store() {
            @Override
            public String saved() {
                try {
                    return prefs(app).getString(PREF_OVERRIDE, null);
                } catch (RuntimeException e) {
                    return null;
                }
            }

            @Override
            public void save(String value) {
                if (!commitSave(app, value)) {
                    Log.w(TAG, "failed to persist server url override");
                }
            }
        };
    }

    /** Flavor-default origin (resource) with resolver + fallback semantics. */
    public static String flavorDefault(Context context) {
        if (context == null) {
            return null;
        }
        try {
            return ServerUrlResolver.resolveCanonical(context.getString(R.string.server_url));
        } catch (RuntimeException ignored) {}
        return ServerUrlResolver.FALLBACK_URL;
    }

    /** Currently selected origin for any context (activity, car, plugin). */
    public static String selected(Context context) {
        return ServerUrlSetting.selected(store(context), flavorDefault(context));
    }

    /** Async purge delivery; always invoked on the main thread. */
    public interface PurgeCallback {
        void onDone(boolean ok);
    }

    /**
     * Validate and persist a raw user entry. Validation errors and no-ops
     * report synchronously on the calling thread; a real change purges first
     * and reports via the callback, persisting only on purge success. Any
     * failure reports {@code success=false} with an inline retry message and
     * the caller must not reload.
     */
    public static void setAsync(final Context context, String raw,
            final ChangeCallback callback) {
        if (context == null || callback == null) {
            return;
        }
        String valid = ServerUrlSetting.validate(raw);
        if (valid == null) {
            callback.onChange(new Change(false, false, INVALID_MESSAGE, null, null));
            return;
        }
        String prev = selected(context);
        if (valid.equals(prev)) {
            callback.onChange(new Change(false, true, null, null, valid));
            return;
        }
        applyValidatedAsync(context, prev, valid, valid, callback);
    }

    /**
     * Reset to the build-flavor default. Already-default reports
     * synchronously as a no-op; otherwise the same purge-then-persist path
     * as {@link #setAsync} applies.
     */
    public static void resetAsync(final Context context, final ChangeCallback callback) {
        if (context == null || callback == null) {
            return;
        }
        String prev = selected(context);
        String defaultValue = flavorDefault(context);
        if (prev != null && prev.equals(defaultValue)) {
            callback.onChange(new Change(false, true, null, null, defaultValue));
            return;
        }
        applyValidatedAsync(context, prev, defaultValue, null, callback);
    }

    /**
     * Shared switch path: purge the old origin, then persist only on purge
     * success. The outcome mapping reuses the pure
     * {@link ServerUrlSetting#executeSwitch} ordering so behavior stays
     * identical to the unit-tested policy.
     */
    private static void applyValidatedAsync(final Context context, final String oldOrigin,
            final String next, final String saveValue, final ChangeCallback callback) {
        final Context app = context.getApplicationContext();
        if (app == null) {
            callback.onChange(new Change(false, false,
                    ServerUrlSetting.SAVE_RETRY_MESSAGE, oldOrigin, null));
            return;
        }
        if (oldOrigin == null) {
            finishPurge(true, app, oldOrigin, next, saveValue, callback);
            return;
        }
        purgeSwitchCookiesAsync(oldOrigin,
                purgeOk -> finishPurge(purgeOk, app, oldOrigin, next, saveValue, callback));
    }

    private static void finishPurge(final boolean purgeOk, final Context app,
            final String oldOrigin, final String next, final String saveValue,
            final ChangeCallback callback) {
        // Same ordering the fixture unit-tests: purge failure never reaches
        // persistence, and any failure reports success=false with no reload.
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                oldOrigin, next, saveValue,
                new ServerUrlSetting.SwitchBoundary() {
                    @Override
                    public boolean purgeOld(String old) {
                        return purgeOk;
                    }

                    @Override
                    public boolean persistNew(String value) {
                        return commitSave(app, value);
                    }
                });
        if (!outcome.success) {
            callback.onChange(new Change(false, false, outcome.error, oldOrigin, null));
        } else if (!outcome.applied) {
            callback.onChange(new Change(false, true, null, null, next));
        } else {
            callback.onChange(new Change(true, true, null, oldOrigin, next));
        }
    }

    /** Synchronous persist reporting commit failure (tiny prefs file). */
    private static boolean commitSave(Context appContext, String value) {
        SharedPreferences.Editor editor =
                appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        if (value == null || value.isEmpty()) {
            editor.remove(PREF_OVERRIDE);
        } else {
            editor.putString(PREF_OVERRIDE, value);
        }
        return editor.commit();
    }

    /**
     * Switch-cookie names currently in the jar for one origin: the server
     * session bearer plus the sealed-credential cookies, per
     * {@link ServerUrlSetting#isServerSwitchCookie}. Unrelated cookies are
     * never touched (no broad domain clear). CookieManager failures
     * propagate so the caller reports them instead of succeeding empty.
     */
    private static List<String> switchCookieNames(String origin) {
        List<String> names = new ArrayList<>();
        String header = CookieManager.getInstance().getCookie(origin);
        if (header == null || header.isEmpty()) {
            return names;
        }
        for (String part : header.split(";")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length >= 1) {
                String name = kv[0].trim();
                if (!name.isEmpty()
                        && ServerUrlSetting.isServerSwitchCookie(name)
                        && !names.contains(name)) {
                    names.add(name);
                }
            }
        }
        return names;
    }

    /**
     * Fail-closed switch-cookie purge for one origin. Every expiry uses the
     * callback {@code setCookie} variant and {@code done} reports false on
     * any failure: scan exception, rejected expiry, or the bounding delay
     * expiring first. Delivery is always posted to the main thread. Callers
     * persist and reload only on {@code true}.
     */
    public static void purgeSwitchCookiesAsync(String origin, final PurgeCallback done) {
        final Handler main = new Handler(Looper.getMainLooper());
        final List<String> names;
        try {
            names = switchCookieNames(origin);
        } catch (RuntimeException e) {
            Log.w(TAG, "switch cookie scan failed", e);
            main.post(() -> done.onDone(false));
            return;
        }
        if (names.isEmpty()) {
            main.post(() -> done.onDone(true));
            return;
        }
        final AtomicBoolean settled = new AtomicBoolean(false);
        final AtomicBoolean failed = new AtomicBoolean(false);
        final AtomicInteger pending = new AtomicInteger(names.size());
        final Runnable[] finishBox = new Runnable[1];
        finishBox[0] = () -> {
            if (!settled.compareAndSet(false, true)) {
                return;
            }
            CookieManager.getInstance().removeExpiredCookie();
            CookieManager.getInstance().flush();
            final boolean ok = !failed.get();
            main.post(() -> done.onDone(ok));
        };
        ValueCallback<Boolean> one = value -> {
            if (value == null || !value) {
                failed.set(true);
            }
            if (pending.decrementAndGet() == 0) {
                finishBox[0].run();
            }
        };
        for (String name : names) {
            try {
                CookieManager.getInstance().setCookie(
                        origin, CredentialCookies.expiredCookieValue(name), one);
            } catch (RuntimeException e) {
                Log.w(TAG, "switch cookie expiry failed", e);
                one.onReceiveValue(false);
            }
        }
        // Bounding delay: unacknowledged expiries fail closed so the caller
        // retries instead of reloading onto a dirty jar.
        main.postDelayed(() -> {
            failed.set(true);
            finishBox[0].run();
        }, PURGE_FALLBACK_MS);
    }
}
