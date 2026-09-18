import com.chatbot.app.CredentialCookies;

// Pure-subset behavior for sealed-cookie storage (phase 1, MOD014).
// Covers CredentialCookies only: the sealed JSON codec lives in
// SealedCredentialPayload on org.json (exact legacy behavior) and is
// verified via source pins, since plain javac lacks the Android org.json
// class. No custom JSON here.
public final class CredentialSealedStorageTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void cookieNamesArePerAccount() {
        // Given an account, when naming sealed cookies, then per-account
        // names isolate cached logins without generic fallbacks.
        check(CredentialCookies.rememberCookieName("alice").equals("remember-alice"),
                "remember cookie must be per-account");
        check(CredentialCookies.encKeyCookieName("alice").equals("enc_key-alice"),
                "enc-key cookie must be per-account");
    }

    private static void parseReadsOnlyPerAccountCookies() {
        // Given a jar header mixing per-account and generic cookies, when
        // parsing for alice, then only alice's per-account values return.
        String header = "remember-alice=A1; enc_key-alice=K1; "
                + "remember-bob=B2; enc_key-bob=K2; "
                + "remember=G; enc_key=GKEY; session=S";
        CredentialCookies.ParsedCredentials parsed =
                CredentialCookies.parseSealedCookieHeader(header, "alice");
        check("A1".equals(parsed.remember), "alice remember must parse");
        check("K1".equals(parsed.encKey), "alice enc-key must parse");

        CredentialCookies.ParsedCredentials bob =
                CredentialCookies.parseSealedCookieHeader(header, "bob");
        check("B2".equals(bob.remember), "bob remember must parse");
        check("K2".equals(bob.encKey), "bob enc-key must parse");
    }

    private static void parseIgnoresGenericCookiesWhenSealing() {
        // Given only generic last-used cookies, when sealing for an account,
        // then nothing parses (no cross-account attribution).
        String header = "remember=G; enc_key=GKEY";
        CredentialCookies.ParsedCredentials parsed =
                CredentialCookies.parseSealedCookieHeader(header, "alice");
        check(parsed.remember == null, "generic remember must not attribute");
        check(parsed.encKey == null, "generic enc-key must not attribute");
        check(CredentialCookies.parseSealedCookieHeader(null, "alice").remember == null,
                "null header must parse to nulls");
    }

    private static void credentialCookieClassification() {
        // Given cookie names, when classified, then remember/enc_key names
        // purge while session/csrf names survive.
        check(CredentialCookies.isCredentialCookie("remember-alice"), "remember purges");
        check(CredentialCookies.isCredentialCookie("enc_key-alice"), "enc_key purges");
        check(CredentialCookies.isCredentialCookie("remember"), "last-used remember purges");
        check(CredentialCookies.isCredentialCookie("enc_key"), "last-used enc_key purges");
        check(!CredentialCookies.isCredentialCookie("session"), "session survives");
        check(!CredentialCookies.isCredentialCookie("csrf_token"), "csrf survives");
        check(!CredentialCookies.isCredentialCookie(null), "null survives");
    }

    private static void injectionAndExpiryFormats() {
        // Given a name/value, when building jar strings, then injection
        // carries the strict HttpOnly value and expiry clears the slot.
        check(CredentialCookies.injectCookieValue("remember-alice", "A1")
                        .equals("remember-alice=A1; Path=/; SameSite=Strict; HttpOnly"),
                "injection format must match unlock path");
        check(CredentialCookies.expiredCookieValue("enc_key-alice")
                        .equals("enc_key-alice=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
                "expiry format must match purge path");
    }

    public static void main(String[] args) {
        cookieNamesArePerAccount();
        parseReadsOnlyPerAccountCookies();
        parseIgnoresGenericCookiesWhenSealing();
        credentialCookieClassification();
        injectionAndExpiryFormats();
        System.err.println("credential sealed storage: pure cookie contract holds");
    }
}
