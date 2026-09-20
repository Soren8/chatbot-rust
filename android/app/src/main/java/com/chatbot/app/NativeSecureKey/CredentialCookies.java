package com.chatbot.app;

/**
 * Sealed-cookie storage cookie names and header/value builders (phase 1,
 * MOD014).
 *
 * <p>Pure {@code java.*} helpers for the sealed cached-credential flow:
 * per-account cookie names, cookie-header parsing, injection values and
 * expiry values. No platform, bridge, or wrap/unwrap access here; the
 * {@code NativeSecureKeyPlugin} platform boundary keeps biometric prompts,
 * jar access, keystore wrap/unwrap and the legacy
 * {@code getKey}/{@code storeKey} API. Parsing isolates per-account cookies
 * only and never falls back to generic last-used cookies, preserving
 * multi-account attribution.
 */
public final class CredentialCookies {
    private CredentialCookies() {}

    /** Per-account remember cookie name for sealed cached login. */
    public static String rememberCookieName(String account) {
        return "remember-" + account;
    }

    /** Per-account enc-key cookie name for sealed cached login. */
    public static String encKeyCookieName(String account) {
        return "enc_key-" + account;
    }

    /** True for cookies owned by credential storage (remember / enc_key). */
    public static boolean isCredentialCookie(String name) {
        if (name == null) {
            return false;
        }
        return name.startsWith("remember") || name.startsWith("enc_key");
    }

    /** Parsed per-account values from a cookie header; nulls when absent. */
    public static final class ParsedCredentials {
        public final String remember;
        public final String encKey;

        public ParsedCredentials(String remember, String encKey) {
            this.remember = remember;
            this.encKey = encKey;
        }
    }

    /**
     * Given a jar cookie header, when sealing for an
     * account, then return that account's per-account values only. Generic
     * last-used cookies are never read here.
     */
    public static ParsedCredentials parseSealedCookieHeader(String cookieHeader, String account) {
        String rememberKey = rememberCookieName(account);
        String encKeyName = encKeyCookieName(account);
        String rememberVal = null;
        String encKeyVal = null;
        if (cookieHeader != null) {
            for (String part : cookieHeader.split(";")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length == 2) {
                    String k = kv[0].trim();
                    String v = kv[1].trim();
                    if (k.equals(rememberKey)) {
                        rememberVal = v;
                    }
                    if (k.equals(encKeyName)) {
                        encKeyVal = v;
                    }
                }
            }
        }
        return new ParsedCredentials(rememberVal, encKeyVal);
    }

    /** Cookie value string for injecting a sealed credential into the jar. */
    public static String injectCookieValue(String name, String value) {
        return name + "=" + value + "; Path=/; SameSite=Strict; HttpOnly";
    }

    /** Cookie value string for expiring one cookie name out of the jar. */
    public static String expiredCookieValue(String name) {
        return name + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
    }
}
