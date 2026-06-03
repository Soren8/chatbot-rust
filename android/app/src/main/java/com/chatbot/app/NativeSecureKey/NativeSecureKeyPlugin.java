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

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
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
    private static final String KEY_ALIAS = "chatbot_native_secure_key_v2";
    private static final String LEGACY_KEY_ALIAS = "chatbot_native_secure_key";
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int PBKDF2_KEY_BITS = 256;

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
        if (key == null || key.isEmpty()) {
            call.reject("key is required");
            return;
        }
        try {
            removeLegacyKeyIfPresent();
            SecretKey secretKey = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] encrypted = cipher.doFinal(key.getBytes(StandardCharsets.UTF_8));
            SharedPreferences prefs = prefs();
            prefs.edit()
                    .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                    .putString(PREF_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    .apply();
            Log.i(TAG, "stored wrapped encryption key");
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
        call.setKeepAlive(true);
        FragmentActivity activity = getActivity();
        if (activity == null) {
            call.reject("activity unavailable");
            return;
        }
        activity.runOnUiThread(() -> {
            try {
                SharedPreferences prefs = prefs();
                String ivB64 = prefs.getString(PREF_IV, null);
                String dataB64 = prefs.getString(PREF_DATA, null);
                if (ivB64 == null || dataB64 == null) {
                    call.setKeepAlive(false);
                    call.resolve(new JSObject());
                    return;
                }
                Runnable decryptAndResolve = () -> {
                    try {
                        removeLegacyKeyIfPresent();
                        SecretKey secretKey = getOrCreateKey();
                        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
                        byte[] decrypted = cipher.doFinal(Base64.decode(dataB64, Base64.NO_WRAP));
                        JSObject result = new JSObject();
                        result.put("key", new String(decrypted, StandardCharsets.UTF_8));
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
    public void clearKey(PluginCall call) {
        prefs().edit().remove(PREF_IV).remove(PREF_DATA).apply();
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
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

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore"
            );
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false)
                    .build();
            keyGenerator.init(spec);
            keyGenerator.generateKey();
        }
        return ((SecretKey) keyStore.getKey(KEY_ALIAS, null));
    }
}
