package com.chatbot.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import android.webkit.CookieManager;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

@CapacitorPlugin(name = "NativeSecureKey")
public class NativeSecureKeyPlugin extends Plugin {
    private static final String TAG = "NativeSecureKey";
    private static final String PREFS = "chatbot_secure_key";
    private static final String PREF_IV = "wrapped_iv";
    private static final String PREF_DATA = "wrapped_data";
    private static final String PREF_CREDS_IV = "wrapped_creds_iv";
    private static final String PREF_CREDS_DATA = "wrapped_creds_data";
    private static final String KEY_ALIAS = "chatbot_native_secure_key_v3";
    private static final String LEGACY_KEY_ALIAS_V2 = "chatbot_native_secure_key_v2";
    private static final String LEGACY_KEY_ALIAS = "chatbot_native_secure_key";
    private static final int KEYSTORE_AUTH_VALIDITY_SECONDS = 86400;
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int PBKDF2_KEY_BITS = 256;

    /**
     * Keys returned by getKey for this app-process lifetime, keyed by account.
     * Lets one biometric unlock cover a whole login flow (keyauth call plus
     * the chat page that follows) and keeps password logins prompt-free,
     * since storeKey primes the cache. Cleared on clearKey / process death.
     */
    private final Map<String, String> unlockedKeys = new ConcurrentHashMap<>();

    private static String accountSlot(String account) {
        if (account == null || account.isEmpty()) {
            return "";
        }
        return ":" + account.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private String prefKey(String base, String account) {
        return base + accountSlot(account);
    }

    private String resolveServerUrl() {
        String url = null;
        try {
            if (getBridge() != null && getBridge().getServerUrl() != null && !getBridge().getServerUrl().isEmpty()) {
                url = getBridge().getServerUrl();
            }
        } catch (Exception ignored) {}
        if (url == null || url.isEmpty()) {
            try {
                url = getContext().getString(R.string.server_url);
            } catch (Exception ignored) {}
        }
        if (url == null || url.isEmpty()) {
            url = "http://localhost";
        }
        return url;
    }

    @PluginMethod
    public void deriveKeyFromPassword(PluginCall call) {
        String password = call.getString("password");
        String saltB64 = call.getString("salt");
        if (password == null || password.isEmpty()) {
            call.reject("password is required");
            return;
        }
        if (saltB64 == null || saltB64.isEmpty()) {
            call.reject("salt is required");
            return;
        }
        char[] passwordChars = password.toCharArray();
        try {
            byte[] salt = Base64.decode(saltB64, Base64.DEFAULT);
            PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derived = factory.generateSecret(spec).getEncoded();
            JSObject result = new JSObject();
            result.put("key", Base64.encodeToString(derived, Base64.NO_WRAP));
            call.resolve(result);
        } catch (Exception e) {
            Log.e(TAG, "failed to derive key", e);
            call.reject("failed to derive key", e);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    @PluginMethod
    public void storeKey(PluginCall call) {
        String key = call.getString("key");
        String account = call.getString("account");
        if (key == null || key.isEmpty()) {
            call.reject("key is required");
            return;
        }
        try {
            removeLegacyKeyIfPresent();
            migrateFromV2IfNeeded();
            SecretKey secretKey = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] encrypted = cipher.doFinal(key.getBytes(StandardCharsets.UTF_8));
            boolean perAccount = account != null && !account.isEmpty();
            SharedPreferences.Editor editor = prefs().edit();
            if (perAccount) {
                // One-time cleanup of the pre-multi-account single slot.
                editor.remove(PREF_IV).remove(PREF_DATA);
            }
            editor.putString(prefKey(PREF_IV, account), Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString(prefKey(PREF_DATA, account), Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    .apply();
            if (perAccount) {
                unlockedKeys.put(account, key);
            }
            Log.i(TAG, "stored wrapped encryption key (account=" + account + ", cached=" + perAccount + ")");
            JSObject result = new JSObject();
            result.put("stored", true);
            call.resolve(result);
        } catch (Exception e) {
            Log.e(TAG, "failed to store key", e);
            call.reject("failed to store key", e);
        }
    }

    @PluginMethod
    public void getKey(PluginCall call) {
        String account = call.getString("account");
        if (account != null && !account.isEmpty()) {
            String cached = unlockedKeys.get(account);
            if (cached != null) {
                JSObject result = new JSObject();
                result.put("key", cached);
                call.resolve(result);
                return;
            }
        }
        String ivPref = prefKey(PREF_IV, account);
        String dataPref = prefKey(PREF_DATA, account);
        call.setKeepAlive(true);
        FragmentActivity activity = getActivity();
        if (activity == null) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            try {
                SharedPreferences prefs = prefs();
                String ivB64 = prefs.getString(ivPref, null);
                String dataB64 = prefs.getString(dataPref, null);
                if (ivB64 == null || dataB64 == null) {
                    call.setKeepAlive(false);
                    call.resolve(new JSObject());
                    return;
                }
                Runnable decryptAndResolve = () -> {
                    try {
                        removeLegacyKeyIfPresent();
                        migrateFromV2IfNeeded();
                        SecretKey secretKey = getOrCreateKey();
                        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                        byte[] decrypted = cipher.doFinal(Base64.decode(dataB64, Base64.NO_WRAP));
                        String key = new String(decrypted, StandardCharsets.UTF_8);
                        if (account != null && !account.isEmpty()) {
                            unlockedKeys.put(account, key);
                        }
                        Log.i(TAG, "unlocked encryption key (account=" + account + ", prompted=true)");
                        JSObject result = new JSObject();
                        result.put("key", key);
                        call.setKeepAlive(false);
                        call.resolve(result);
                    } catch (Exception e) {
                        Log.e(TAG, "failed to read key", e);
                        call.setKeepAlive(false);
                        call.reject("failed to read key", e);
                    }
                };
                if (!canPromptForBiometric()) {
                    Log.i(TAG, "biometric unlock unavailable; using keystore-only decrypt");
                    decryptAndResolve.run();
                    return;
                }
                promptForUnlock(activity, () -> decryptAndResolve.run(), call);
            } catch (Exception e) {
                Log.e(TAG, "failed to prepare key read", e);
                call.setKeepAlive(false);
                call.reject("failed to read key", e);
            }
        });
    }

    @PluginMethod
    public void sealCachedCredentials(PluginCall call) {
        String account = call.getString("account");
        if (account == null || account.isEmpty()) {
            call.reject("account is required");
            return;
        }
        try {
            removeLegacyKeyIfPresent();
            migrateFromV2IfNeeded();
            String serverUrl = resolveServerUrl();
            CookieManager cm = CookieManager.getInstance();
            String cookieHeader = cm.getCookie(serverUrl);
            String rememberVal = null;
            String encKeyVal = null;
            if (cookieHeader != null) {
                String rememberKey = "remember-" + account;
                String encKeyName = "enc_key-" + account;
                for (String part : cookieHeader.split(";")) {
                    String[] kv = part.trim().split("=", 2);
                    if (kv.length == 2) {
                        String k = kv[0].trim();
                        String v = kv[1].trim();
                        if (k.equals(rememberKey) || (rememberVal == null && k.equals("remember"))) {
                            rememberVal = v;
                        }
                        if (k.equals(encKeyName) || (encKeyVal == null && k.equals("enc_key"))) {
                            encKeyVal = v;
                        }
                    }
                }
            }
            if (encKeyVal == null) {
                encKeyVal = unlockedKeys.get(account);
            }
            if (rememberVal == null && encKeyVal == null) {
                Log.w(TAG, "no credentials found in CookieManager to seal for " + account);
                JSObject result = new JSObject();
                result.put("sealed", false);
                call.resolve(result);
                return;
            }
            JSONObject payload = new JSONObject();
            payload.put("account", account);
            payload.put("remember", rememberVal != null ? rememberVal : "");
            payload.put("enc_key", encKeyVal != null ? encKeyVal : "");

            SecretKey secretKey = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] encrypted = cipher.doFinal(payload.toString().getBytes(StandardCharsets.UTF_8));

            prefs().edit()
                    .putString(prefKey(PREF_CREDS_IV, account), Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString(prefKey(PREF_CREDS_DATA, account), Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    .apply();

            Log.i(TAG, "sealed cached credentials into keystore for account=" + account);
            JSObject result = new JSObject();
            result.put("sealed", true);
            call.resolve(result);
        } catch (Exception e) {
            Log.e(TAG, "failed to seal cached credentials", e);
            call.reject("failed to seal cached credentials", e);
        }
    }

    @PluginMethod
    public void unlockCachedLogin(PluginCall call) {
        String account = call.getString("account");
        if (account == null || account.isEmpty()) {
            call.reject("account is required");
            return;
        }
        String ivPref = prefKey(PREF_CREDS_IV, account);
        String dataPref = prefKey(PREF_CREDS_DATA, account);
        SharedPreferences prefs = prefs();
        String ivB64 = prefs.getString(ivPref, null);
        String dataB64 = prefs.getString(dataPref, null);
        if (ivB64 == null || dataB64 == null) {
            Log.i(TAG, "no sealed credentials for account=" + account);
            JSObject result = new JSObject();
            result.put("unlocked", false);
            result.put("reason", "no_credentials");
            call.resolve(result);
            return;
        }
        call.setKeepAlive(true);
        FragmentActivity activity = getActivity();
        if (activity == null) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            Runnable decryptAndInject = () -> {
                try {
                    removeLegacyKeyIfPresent();
                    migrateFromV2IfNeeded();
                    SecretKey secretKey = getOrCreateKey();
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                    byte[] decrypted = cipher.doFinal(Base64.decode(dataB64, Base64.NO_WRAP));
                    JSONObject payload = new JSONObject(new String(decrypted, StandardCharsets.UTF_8));
                    String rememberVal = payload.optString("remember", "");
                    String encKeyVal = payload.optString("enc_key", "");

                    String serverUrl = resolveServerUrl();
                    CookieManager cm = CookieManager.getInstance();
                    if (!rememberVal.isEmpty()) {
                        cm.setCookie(serverUrl, "remember-" + account + "=" + rememberVal + "; Path=/; SameSite=Strict; HttpOnly");
                        cm.setCookie(serverUrl, "remember=" + rememberVal + "; Path=/; SameSite=Strict; HttpOnly");
                    }
                    if (!encKeyVal.isEmpty()) {
                        cm.setCookie(serverUrl, "enc_key-" + account + "=" + encKeyVal + "; Path=/; SameSite=Strict; HttpOnly");
                        cm.setCookie(serverUrl, "enc_key=" + encKeyVal + "; Path=/; SameSite=Strict; HttpOnly");
                        unlockedKeys.put(account, encKeyVal);
                    }
                    cm.flush();

                    Log.i(TAG, "unlocked and injected cached credentials for account=" + account);
                    JSObject result = new JSObject();
                    result.put("unlocked", true);
                    call.setKeepAlive(false);
                    call.resolve(result);
                } catch (Exception e) {
                    Log.e(TAG, "failed to decrypt cached credentials", e);
                    call.setKeepAlive(false);
                    call.reject("failed to decrypt cached credentials", e);
                }
            };

            if (!canPromptForBiometric()) {
                Log.i(TAG, "biometric prompt unavailable; performing keystore-only unlock");
                decryptAndInject.run();
                return;
            }
            promptForUnlock(activity, () -> decryptAndInject.run(), call);
        });
    }

    @PluginMethod
    public void purgeCachedCookies(PluginCall call) {
        try {
            CookieManager cm = CookieManager.getInstance();
            String serverUrl = resolveServerUrl();
            String cookieHeader = cm.getCookie(serverUrl);
            if (cookieHeader != null) {
                for (String part : cookieHeader.split(";")) {
                    String[] kv = part.trim().split("=", 2);
                    if (kv.length >= 1) {
                        String name = kv[0].trim();
                        if (name.startsWith("remember") || name.startsWith("enc_key")) {
                            cm.setCookie(serverUrl, name + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
                        }
                    }
                }
                cm.flush();
            }
            JSObject res = new JSObject();
            res.put("purged", true);
            call.resolve(res);
        } catch (Exception e) {
            Log.w(TAG, "failed to purge cached cookies", e);
            call.reject("failed to purge cached cookies", e);
        }
    }

    @PluginMethod
    public void clearKey(PluginCall call) {
        String account = call.getString("account");
        if (account != null && !account.isEmpty()) {
            prefs().edit()
                    .remove(prefKey(PREF_IV, account))
                    .remove(prefKey(PREF_DATA, account))
                    .remove(prefKey(PREF_CREDS_IV, account))
                    .remove(prefKey(PREF_CREDS_DATA, account))
                    .apply();
            unlockedKeys.remove(account);
            try {
                CookieManager cm = CookieManager.getInstance();
                String serverUrl = resolveServerUrl();
                cm.setCookie(serverUrl, "remember-" + account + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
                cm.setCookie(serverUrl, "enc_key-" + account + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
                cm.flush();
            } catch (Exception ignored) {}
            call.resolve(new JSObject());
            return;
        }
        // Full wipe: every account slot plus the keystore wrapping key.
        prefs().edit().clear().apply();
        unlockedKeys.clear();
        try {
            CookieManager cm = CookieManager.getInstance();
            String serverUrl = resolveServerUrl();
            String cookieHeader = cm.getCookie(serverUrl);
            if (cookieHeader != null) {
                for (String part : cookieHeader.split(";")) {
                    String[] kv = part.trim().split("=", 2);
                    if (kv.length >= 1) {
                        String name = kv[0].trim();
                        if (name.startsWith("remember") || name.startsWith("enc_key")) {
                            cm.setCookie(serverUrl, name + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
                        }
                    }
                }
                cm.flush();
            }
        } catch (Exception ignored) {}
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
            }
            if (keyStore.containsAlias(LEGACY_KEY_ALIAS_V2)) {
                keyStore.deleteEntry(LEGACY_KEY_ALIAS_V2);
            }
            if (keyStore.containsAlias(LEGACY_KEY_ALIAS)) {
                keyStore.deleteEntry(LEGACY_KEY_ALIAS);
            }
        } catch (Exception e) {
            call.reject("failed to clear key", e);
            return;
        }
        call.resolve(new JSObject());
    }

    private interface UnlockAction {
        void run() throws Exception;
    }

    private void promptForUnlock(FragmentActivity activity, UnlockAction action, PluginCall call) {
        Executor executor = ContextCompat.getMainExecutor(getContext());
        BiometricPrompt prompt = new BiometricPrompt(
                activity,
                executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        try {
                            action.run();
                        } catch (Exception e) {
                            Log.e(TAG, "secure key operation failed after auth", e);
                            call.setKeepAlive(false);
                            call.reject("secure key operation failed", e);
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        Log.w(TAG, "authentication error: " + errString);
                        call.setKeepAlive(false);
                        call.reject("authentication cancelled: " + errString);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        // Keep prompt open for retry.
                    }
                }
        );

        BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock encryption key")
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

    private boolean canPromptForBiometric() {
        BiometricManager biometricManager = BiometricManager.from(getContext());
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
        return biometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS;
    }

    private SharedPreferences prefs() {
        Context context = getContext().getApplicationContext();
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private void removeLegacyKeyIfPresent() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(LEGACY_KEY_ALIAS)) {
            keyStore.deleteEntry(LEGACY_KEY_ALIAS);
            prefs().edit().remove(PREF_IV).remove(PREF_DATA).apply();
        }
    }

    private void migrateFromV2IfNeeded() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias(LEGACY_KEY_ALIAS_V2)) {
                return;
            }
            SecretKey oldKey = (SecretKey) keyStore.getKey(LEGACY_KEY_ALIAS_V2, null);
            if (oldKey == null) {
                keyStore.deleteEntry(LEGACY_KEY_ALIAS_V2);
                return;
            }
            SecretKey newKey = getOrCreateKey();
            SharedPreferences prefs = prefs();
            SharedPreferences.Editor editor = prefs.edit();
            boolean migrated = false;
            for (String key : prefs.getAll().keySet()) {
                if (!key.startsWith(PREF_IV)) {
                    continue;
                }
                String suffix = key.substring(PREF_IV.length());
                String dataKey = PREF_DATA + suffix;
                String ivB64 = prefs.getString(key, null);
                String dataB64 = prefs.getString(dataKey, null);
                if (ivB64 == null || dataB64 == null) {
                    continue;
                }
                try {
                    Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
                    decrypt.init(Cipher.DECRYPT_MODE, oldKey, new GCMParameterSpec(128, iv));
                    byte[] plain = decrypt.doFinal(Base64.decode(dataB64, Base64.NO_WRAP));
                    Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, newKey);
                    byte[] newIv = encrypt.getIV();
                    byte[] encrypted = encrypt.doFinal(plain);
                    editor.putString(key, Base64.encodeToString(newIv, Base64.NO_WRAP));
                    editor.putString(dataKey, Base64.encodeToString(encrypted, Base64.NO_WRAP));
                    migrated = true;
                } catch (Exception e) {
                    Log.w(TAG, "failed to migrate wrap for " + key, e);
                }
            }
            if (migrated) {
                editor.apply();
            }
            keyStore.deleteEntry(LEGACY_KEY_ALIAS_V2);
        } catch (Exception e) {
            Log.w(TAG, "v2 keystore migration skipped", e);
        }
    }

    private void generateWrapKey(boolean requireAuth) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
        );
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(requireAuth);
        if (requireAuth) {
            builder.setUserAuthenticationValidityDurationSeconds(KEYSTORE_AUTH_VALIDITY_SECONDS);
        }
        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            try {
                generateWrapKey(true);
            } catch (Exception e) {
                Log.w(TAG, "auth-bound keystore key unavailable; using software-gated key", e);
                try {
                    if (keyStore.containsAlias(KEY_ALIAS)) {
                        keyStore.deleteEntry(KEY_ALIAS);
                    }
                } catch (Exception ignored) {
                }
                generateWrapKey(false);
            }
        }
        return ((SecretKey) keyStore.getKey(KEY_ALIAS, null));
    }
}
