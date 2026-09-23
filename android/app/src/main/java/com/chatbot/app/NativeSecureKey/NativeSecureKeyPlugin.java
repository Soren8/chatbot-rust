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

import com.chatbot.app.util.ServerUrlResolver;
import com.chatbot.app.util.ServerUrlSetting;
import com.chatbot.app.util.ServerUrlSettingStore;

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
     * since storeKey primes the cache. Cleared on clearKey / process death and
     * whenever the server selection changes.
     */
    private static final Map<String, String> unlockedKeys = new ConcurrentHashMap<>();

    private static String accountSlot(String account) {
        if (account == null || account.isEmpty()) {
            return "";
        }
        return ":" + account.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private String prefKey(String base, String account) {
        return base + accountSlot(account);
    }

    /**
     * Origin-scoped prefs slot: key/credential wraps are bound to the origin
     * they were sealed against, so an unlock on another server can never
     * read them. Legacy untagged slots remain readable only while the
     * selected origin equals the flavor default (pre-feature installs).
     */
    private boolean legacySlotAllowed() {
        try {
            Context ctx = getContext();
            return ServerUrlSettingStore.selected(ctx).equals(
                    ServerUrlSettingStore.flavorDefault(ctx));
        } catch (Exception e) {
            return false;
        }
    }

    private String originPrefKey(String base, String account) {
        return base + ServerUrlSetting.credentialSlot(resolveServerUrl(), account);
    }

    /** Legacy (pre-namespace) slot key; readable only at the flavor default. */
    private String legacyPrefKey(String base, String account) {
        return base + accountSlot(account);
    }

    /** Remove every slot (any origin token plus the legacy format). */
    private void removeAccountSlots(String base, String account) {
        String suffix = ":" + (account == null ? ""
                : account.replaceAll("[^A-Za-z0-9_-]", "_"));
        SharedPreferences.Editor editor = prefs().edit();
        boolean any = false;
        for (String key : prefs().getAll().keySet()) {
            if (key.startsWith(base) && key.endsWith(suffix)) {
                editor.remove(key);
                any = true;
            }
        }
        if (any) {
            editor.apply();
        }
    }

    // Canonical native origin (selected origin: flavor resource + persisted
    // override); the pure-value authority stays in ServerUrlResolver for the
    // flavor default.
    private String resolveServerUrl() {
        Context ctx = getContext();
        String resourceUrl = null;
        try {
            resourceUrl = ctx.getString(R.string.server_url);
        } catch (Exception ignored) {}
        try {
            return ServerUrlSetting.selected(
                    ServerUrlSettingStore.store(ctx),
                    ServerUrlResolver.resolveCanonical(resourceUrl));
        } catch (Exception e) {
            return ServerUrlResolver.resolveCanonical(resourceUrl);
        }
    }

    /** Selection moved: no fragment of the old origin stays unlockable. */
    public static void onServerSelectionChanged() {
        unlockedKeys.clear();
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
            editor.putString(originPrefKey(PREF_IV, account), Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString(originPrefKey(PREF_DATA, account), Base64.encodeToString(encrypted, Base64.NO_WRAP))
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

    /**
     * Read the wrapped data-key slot for an account: origin-scoped slot
     * first; legacy untagged slot only while the selected origin is still the
     * flavor default (pre-feature installs migrated in place).
     */
    private String[] readIvData(SharedPreferences prefs, String account) {
        String ivB64 = prefs.getString(originPrefKey(PREF_IV, account), null);
        String dataB64 = prefs.getString(originPrefKey(PREF_DATA, account), null);
        if (ivB64 == null || dataB64 == null) {
            if (legacySlotAllowed()) {
                ivB64 = prefs.getString(prefKey(PREF_IV, account), null);
                dataB64 = prefs.getString(prefKey(PREF_DATA, account), null);
            }
        }
        return new String[]{ivB64, dataB64};
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
        // Origin captured before the async decrypt: a pending biometric
        // unlock from the old server never hands key material to the
        // after-switch page.
        final String originAtSubmit = resolveServerUrl();
        SharedPreferences prefs = prefs();
        String[] ivData = readIvData(prefs, account);
        String ivB64 = ivData[0];
        String dataB64 = ivData[1];
        if (ivB64 == null || dataB64 == null) {
            call.resolve(new JSObject());
            return;
        }
        call.setKeepAlive(true);
        FragmentActivity activity = getActivity();
        if (activity == null) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            try {
                Runnable decryptAndResolve = () -> {
                    try {
                        if (!resolveServerUrl().equals(originAtSubmit)) {
                            Log.w(TAG, "server changed during key unlock; aborting injection");
                            call.setKeepAlive(false);
                            call.reject("server changed during unlock");
                            return;
                        }
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
            // Sealed-cookie storage owns per-account cookie parsing; the
            // legacy key API (storeKey/getKey/unlockedKeys) is untouched.
            CredentialCookies.ParsedCredentials parsed =
                    CredentialCookies.parseSealedCookieHeader(cookieHeader, account);
            String rememberVal = parsed.remember;
            String encKeyVal = parsed.encKey;
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
            String payload = SealedCredentialPayload.encode(account, rememberVal, encKeyVal);

            SecretKey secretKey = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] encrypted = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

            prefs().edit()
                    .putString(originPrefKey(PREF_CREDS_IV, account), Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString(originPrefKey(PREF_CREDS_DATA, account), Base64.encodeToString(encrypted, Base64.NO_WRAP))
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
        String ivPref = originPrefKey(PREF_CREDS_IV, account);
        String dataPref = originPrefKey(PREF_CREDS_DATA, account);
        SharedPreferences prefs = prefs();
        String ivB64 = prefs.getString(ivPref, null);
        String dataB64 = prefs.getString(dataPref, null);
        if (ivB64 == null || dataB64 == null) {
            // Legacy (pre-namespace) sealed slot, valid only at the flavor default.
            if (legacySlotAllowed()) {
                ivB64 = prefs.getString(prefKey(PREF_CREDS_IV, account), null);
                dataB64 = prefs.getString(prefKey(PREF_CREDS_DATA, account), null);
            }
        }
        final String originAtSubmit = resolveServerUrl();
        if (ivB64 == null || dataB64 == null) {
            Log.i(TAG, "no sealed credentials for account=" + account);
            JSObject result = new JSObject();
            result.put("unlocked", false);
            result.put("reason", "no_credentials");
            call.resolve(result);
            return;
        }
        final String pendingIv = ivB64;
        final String pendingData = dataB64;
        call.setKeepAlive(true);
        FragmentActivity activity = getActivity();
        if (activity == null) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            Runnable decryptAndInject = () -> {
                try {
                    if (!resolveServerUrl().equals(originAtSubmit)) {
                        Log.w(TAG, "server changed during credential unlock; aborting injection");
                        call.setKeepAlive(false);
                        call.reject("server changed during unlock");
                        return;
                    }
                    removeLegacyKeyIfPresent();
                    migrateFromV2IfNeeded();
                    SecretKey secretKey = getOrCreateKey();
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    byte[] iv = Base64.decode(pendingIv, Base64.NO_WRAP);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                    byte[] decrypted = cipher.doFinal(Base64.decode(pendingData, Base64.NO_WRAP));
                    SealedCredentialPayload.Decoded payload = SealedCredentialPayload.decode(
                            new String(decrypted, StandardCharsets.UTF_8));
                    String rememberVal = payload.remember;
                    String encKeyVal = payload.encKey;

                    String serverUrl = resolveServerUrl();
                    CookieManager cm = CookieManager.getInstance();
                    if (!rememberVal.isEmpty()) {
                        cm.setCookie(serverUrl, CredentialCookies.injectCookieValue(
                                CredentialCookies.rememberCookieName(account), rememberVal));
                        cm.setCookie(serverUrl, CredentialCookies.injectCookieValue("remember", rememberVal));
                    }
                    if (!encKeyVal.isEmpty()) {
                        cm.setCookie(serverUrl, CredentialCookies.injectCookieValue(
                                CredentialCookies.encKeyCookieName(account), encKeyVal));
                        cm.setCookie(serverUrl, CredentialCookies.injectCookieValue("enc_key", encKeyVal));
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
                        if (CredentialCookies.isCredentialCookie(name)) {
                            cm.setCookie(serverUrl, CredentialCookies.expiredCookieValue(name));
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
            // Remove every slot for this account: origin-scoped wraps for any
            // origin plus the legacy untagged format.
            removeAccountSlots(PREF_IV, account);
            removeAccountSlots(PREF_DATA, account);
            removeAccountSlots(PREF_CREDS_IV, account);
            removeAccountSlots(PREF_CREDS_DATA, account);
            unlockedKeys.remove(account);
            try {
                CookieManager cm = CookieManager.getInstance();
                String serverUrl = resolveServerUrl();
                cm.setCookie(serverUrl, CredentialCookies.expiredCookieValue(
                        CredentialCookies.rememberCookieName(account)));
                cm.setCookie(serverUrl, CredentialCookies.expiredCookieValue(
                        CredentialCookies.encKeyCookieName(account)));
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
                        if (CredentialCookies.isCredentialCookie(name)) {
                            cm.setCookie(serverUrl, CredentialCookies.expiredCookieValue(name));
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
