package com.chatbot.app;

import org.json.JSONObject;

/**
 * Sealed cached-credential payload codec (phase 1, MOD014).
 *
 * <p>Owner of the sealed payload field names plus {@code org.json}
 * encode/decode for seal / unlock — the exact legacy {@code JSONObject}
 * behavior (puts in account, remember, enc_key order; absent values decode
 * via {@code optString} to {@code ""}). The plugin keeps the platform
 * boundary (jar access, keystore wrap/unwrap, biometric prompts) and the
 * legacy key API; pure cookie names/parsing/builders live in
 * {@code CredentialCookies}.
 */
public final class SealedCredentialPayload {
    public static final String FIELD_ACCOUNT = "account";
    public static final String FIELD_REMEMBER = "remember";
    public static final String FIELD_ENC_KEY = "enc_key";

    private SealedCredentialPayload() {}

    /** Decoded sealed payload with {@code optString}-style empty defaults. */
    public static final class Decoded {
        public final String account;
        public final String remember;
        public final String encKey;

        public Decoded(String account, String remember, String encKey) {
            this.account = account;
            this.remember = remember;
            this.encKey = encKey;
        }
    }

    /**
     * Given account credentials, when sealing, then encode the JSON payload
     * with insertion order account, remember, enc_key. Null secrets encode
     * to empty strings.
     */
    public static String encode(String account, String remember, String encKey) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put(FIELD_ACCOUNT, account);
        payload.put(FIELD_REMEMBER, remember != null ? remember : "");
        payload.put(FIELD_ENC_KEY, encKey != null ? encKey : "");
        return payload.toString();
    }

    /**
     * Given sealed JSON, when unlocking, then decode the three fields.
     * Absent remember / enc_key values decode to empty strings.
     */
    public static Decoded decode(String json) throws Exception {
        JSONObject payload = new JSONObject(json);
        return new Decoded(
                payload.optString(FIELD_ACCOUNT, ""),
                payload.optString(FIELD_REMEMBER, ""),
                payload.optString(FIELD_ENC_KEY, ""));
    }
}
