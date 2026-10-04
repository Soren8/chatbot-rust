import java.util.concurrent.Executor;
import com.chatbot.app.util.NativeUnlockGate;

public class Phase4ResumeLockTest {
    static final int MODE_PRIVATE = 0;
    static final String PREF_NATIVE_BACKGROUND_ELAPSED = "native_backgrounded_elapsed";
    static final String PREF_NATIVE_UNLOCK_REQUIRED = "native_unlock_required";
    boolean isLocked = true;
    long backgroundedAt = 99;
    final Preferences preferences = new Preferences();
    FrameLayout lockOverlay;
    FrameLayout root = new FrameLayout();
    Bridge bridge = new Bridge();
    static final String TAG = "resume";

    Phase4ResumeLockTest() {
        preferences.values.put(PREF_NATIVE_BACKGROUND_ELAPSED, backgroundedAt);
        preferences.values.put(PREF_NATIVE_UNLOCK_REQUIRED, true);
        ensureLockOverlay();
    }

    void tapSwitch() { button("Switch Account").click(); }
    void tapUnlock() { button("Unlock").click(); }
    Button button(String label) {
        for (View child : lockOverlay.children) {
            for (View candidate : ((LinearLayout) child).children) {
                if (candidate instanceof Button && label.equals(((Button) candidate).text)) return (Button) candidate;
            }
        }
        throw new AssertionError("missing overlay button: " + label);
    }
    FrameLayout findViewById(int id) { return root; }
    Bridge getBridge() { return bridge; }
    Preferences getPreferences(int mode) { return preferences; }
    String resolveServerUrl() { return "https://server.example"; }
    boolean hasWindowFocus() { return true; }
    void updateWindowSecurity(boolean focused) {}

    /* SHIPPED_METHODS */

    static void expectLocked(Phase4ResumeLockTest app, String scenario) {
        if (!app.isLocked || app.backgroundedAt != 99 || !app.lockOverlay.visible || !app.bridge.webView.urls.isEmpty()
                || !app.preferences.getBoolean(PREF_NATIVE_UNLOCK_REQUIRED, false))
            throw new AssertionError(scenario + " unlocked or navigated without authentication");
    }
    static void scenario(String name, int status, int result, boolean switchAccount, boolean authenticated) {
        BiometricManager.status = status;
        BiometricPrompt.mode = result;
        BiometricPrompt.pending = null;
        Phase4ResumeLockTest app = new Phase4ResumeLockTest();
        if (switchAccount) app.tapSwitch(); else app.tapUnlock();
        expectLocked(app, name + " before callback");
        if (status == BiometricManager.BIOMETRIC_SUCCESS) {
            if (BiometricPrompt.pending == null) throw new AssertionError(name + " did not prompt");
            BiometricPrompt.complete();
        } else if (BiometricPrompt.pending != null) throw new AssertionError(name + " prompted while unavailable");
        if (authenticated) {
            if (app.isLocked || app.lockOverlay.visible || app.backgroundedAt != 0)
                throw new AssertionError(name + " did not unlock on success");
            if (app.preferences.getBoolean(PREF_NATIVE_UNLOCK_REQUIRED, true)
                    || app.preferences.values.containsKey(PREF_NATIVE_BACKGROUND_ELAPSED))
                throw new AssertionError(name + " did not persist successful unlock state");
            java.util.List<String> expected = switchAccount ? java.util.List.of("https://server.example/login") : java.util.List.of();
            if (!expected.equals(app.bridge.webView.urls)) throw new AssertionError(name + " navigation: " + app.bridge.webView.urls);
        } else expectLocked(app, name + " after callback");
        System.out.println("PASS " + name);
    }
    public static void main(String[] args) {
        scenario("switch_unavailable", 12, 0, true, false);
        scenario("switch_cancelled", 0, 1, true, false);
        scenario("switch_failed", 0, 2, true, false);
        scenario("switch_authenticated", 0, 0, true, true);
        scenario("unlock_authenticated", 0, 0, false, true);
    }
    static class android { static class R { static class id { static final int content = 1; } } }
    static class Preferences {
        final java.util.Map<String, Object> values = new java.util.HashMap<>();
        boolean getBoolean(String key, boolean fallback) {
            Object value = values.get(key);
            return value instanceof Boolean ? (Boolean) value : fallback;
        }
        Editor edit() { return new Editor(this); }
        static class Editor {
            final Preferences owner;
            Editor(Preferences owner) { this.owner = owner; }
            Editor remove(String key) { owner.values.remove(key); return this; }
            Editor putBoolean(String key, boolean value) { owner.values.put(key, value); return this; }
            void apply() {}
        }
    }
    static class View {
        static final int VISIBLE = 0, GONE = 8;
        boolean visible = true;
        void setVisibility(int visibility) { visible = visibility != GONE; }
        void setLayoutParams(Object params) {}
        void setBackgroundColor(int color) {}
        void setClickable(boolean value) {}
        void setFocusable(boolean value) {}
    }
    static class ViewGroup extends View {
        static class LayoutParams { static final int MATCH_PARENT = -1, WRAP_CONTENT = -2; LayoutParams(int width, int height) {} }
        java.util.List<View> children = new java.util.ArrayList<>();
        void addView(View view) { children.add(view); }
    }
    static class FrameLayout extends ViewGroup {
        FrameLayout() {}
        FrameLayout(Phase4ResumeLockTest app) {}
        static class LayoutParams extends ViewGroup.LayoutParams { int gravity; LayoutParams(int width, int height) { super(width, height); } }
    }
    static class LinearLayout extends ViewGroup {
        static final int VERTICAL = 1;
        LinearLayout(Phase4ResumeLockTest app) {}
        void setOrientation(int orientation) {}
        void setGravity(int gravity) {}
    }
    static class Gravity { static final int CENTER = 1; }
    static class TextView extends View {
        String text;
        TextView(Phase4ResumeLockTest app) {}
        void setText(String text) { this.text = text; }
        void setTextColor(int color) {}
        void setTextSize(float size) {}
        void setGravity(int gravity) {}
        void setPadding(int left, int top, int right, int bottom) {}
    }
    static class Button extends TextView {
        Button(Phase4ResumeLockTest app) { super(app); }
        java.util.function.Consumer<View> listener;
        void setOnClickListener(java.util.function.Consumer<View> action) { listener = action; }
        void click() { listener.accept(new View()); }
    }
    static class WebView {
        java.util.List<String> urls = new java.util.ArrayList<>();
        int visibility = View.VISIBLE;
        void setVisibility(int value) { visibility = value; }
        void loadUrl(String url) { urls.add(url); }
    }
    static class Bridge { WebView webView = new WebView(); WebView getWebView() { return webView; } }
    static class Build {
        static class VERSION { static int SDK_INT = 30; }
        static class VERSION_CODES { static final int R = 30, Q = 29; }
    }
    static class BiometricManager {
        static final int BIOMETRIC_SUCCESS = 0;
        static int status;
        static BiometricManager from(Phase4ResumeLockTest app) { return new BiometricManager(); }
        int canAuthenticate(int authenticators) { return status; }
        static class Authenticators { static final int BIOMETRIC_STRONG = 1, BIOMETRIC_WEAK = 2, DEVICE_CREDENTIAL = 4; }
    }
    static class ContextCompat { static Executor getMainExecutor(Phase4ResumeLockTest app) { return Runnable::run; } }
    static class Log { static void w(String tag, String message) {} }
    static class BiometricPrompt {
        static int mode;
        static AuthenticationCallback pending;
        BiometricPrompt(Phase4ResumeLockTest app, Executor executor, AuthenticationCallback callback) { pending = callback; }
        void authenticate(PromptInfo info) {}
        static void complete() {
            AuthenticationCallback callback = pending;
            pending = null;
            if (mode == 0) callback.onAuthenticationSucceeded(new AuthenticationResult());
            if (mode == 1) callback.onAuthenticationError(5, "cancelled");
            if (mode == 2) callback.onAuthenticationFailed();
        }
        static class AuthenticationResult {}
        static class AuthenticationCallback {
            public void onAuthenticationSucceeded(AuthenticationResult result) {}
            public void onAuthenticationError(int error, CharSequence message) {}
            public void onAuthenticationFailed() {}
        }
        static class PromptInfo {
            static class Builder {
                Builder setTitle(String text) { return this; }
                Builder setSubtitle(String text) { return this; }
                Builder setAllowedAuthenticators(int authenticators) { return this; }
                Builder setDeviceCredentialAllowed(boolean allowed) { return this; }
                PromptInfo build() { return new PromptInfo(); }
            }
        }
    }
}
