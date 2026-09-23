package com.chatbot.app.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Locale;

/**
 * Shared server-selection policy: the build flavor is the default origin,
 * a validated persisted override (if any) selects a different https origin,
 * and credential slots are namespaced per origin so nothing transfers
 * between servers on a switch.
 *
 * <p>Pure Java (no Android imports) so the behavior runs under the cargo
 * {@code javac} fixture harness; see {@code ServerSettingBehaviorTest}.
 */
public final class ServerUrlSetting {
    private ServerUrlSetting() {
    }

    /** Minimal persistence so pure behavior tests need no Android framework. */
    public interface Store {
        /** Persisted override value or null when the flavor default applies. */
        String saved();

        /** Persist the override; null/empty clears it back to the default. */
        void save(String value);
    }

    /**
     * User-overridable validation via {@link URI}: exactly the https scheme,
     * server-based authority with optional explicit port, no userinfo, no
     * path (a single trailing "/" is stripped), no query, no fragment.
     * The default HTTP emulator endpoint stays reachable via the flavor
     * authority (Reset), never by typing it.
     */
    public static String validate(String raw) {
        if (raw == null) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(raw.trim());
        } catch (URISyntaxException e) {
            return null;
        }
        if (uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase("https")
                || uri.getUserInfo() != null
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null) {
            return null;
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            return null;
        }
        String hostLower = host.toLowerCase(Locale.US);
        // URI.getHost keeps IPv6 brackets in its own variant; rebuild one
        // canonical bracketed form for the round-trip.
        String bare = (hostLower.startsWith("[") && hostLower.endsWith("]"))
                ? hostLower.substring(1, hostLower.length() - 1)
                : hostLower;
        int port = uri.getPort();
        String path = uri.getRawPath();
        String authority = bare.indexOf(':') >= 0 ? "[" + bare + "]" : bare;
        if (port != -1) {
            if (port < 1 || port > 65535) {
                return null;
            }
            if (port != 443) {
                authority += ":" + port;
            }
        }
        // The authority round-trip rejects junk the URI parser silently
        // drops (e.g. "host:443:8080" whose raw port is not numeric); the
        // explicit default :443 is accepted and canonicalized away.
        String rawAuthority = uri.getRawAuthority();
        if (!rawAuthority.equalsIgnoreCase(authority)
                && (port != 443 || !rawAuthority.equalsIgnoreCase(authority + ":443"))) {
            return null;
        }
        if (path != null && !path.isEmpty() && !path.equals("/")) {
            return null;
        }
        return "https://" + authority;
    }

    /**
     * Selected origin: valid persisted override when present, else the
     * flavor default. An invalid stored value falls back to the flavor
     * default (defensive: prefs outlive validation changes).
     */
    public static String selected(Store store, String flavorDefault) {
        String defaultValue = (flavorDefault == null || flavorDefault.isEmpty())
                ? ServerUrlResolver.FALLBACK_URL
                : flavorDefault;
        String override = store == null ? null : store.saved();
        if (override != null && !override.isEmpty()) {
            String valid = validate(override);
            if (valid != null) {
                return valid;
            }
        }
        return defaultValue;
    }

    /**
     * Session cookie name issued by the server (chatbot-core
     * {@code session_identity} {@code SESSION_COOKIE_NAME}). Cookie jars are
     * host-scoped, not (host, port, scheme)-scoped, so this bearer would
     * otherwise be sent to a newly selected origin on another port.
     */
    public static final String SESSION_COOKIE_NAME = "session";

    /**
     * True for cookies that must not survive a server-origin switch: the
     * server session bearer plus the sealed-credential cookies. Credential
     * storage callers keep using {@code CredentialCookies.isCredentialCookie}
     * (session-preserving by intent: logout/clear flows must not drop the
     * live session); only the origin-switch purge uses this policy.
     */
    public static boolean isServerSwitchCookie(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (name.equals(SESSION_COOKIE_NAME)) {
            return true;
        }
        return name.startsWith("remember") || name.startsWith("enc_key");
    }

    /** Inline retry message when the old origin's cookies cannot be cleared. */
    public static final String PURGE_RETRY_MESSAGE =
            "Couldn't clear old server cookies. Retry.";
    /** Inline retry message when the new selection cannot be persisted. */
    public static final String SAVE_RETRY_MESSAGE =
            "Couldn't save server selection. Retry.";

    /** Synchronous switch boundary, injected so the ordering is unit-testable. */
    public interface SwitchBoundary {
        /** Expire the old origin's switch cookies; false on any failure. */
        boolean purgeOld(String oldOrigin);

        /** Persist the new selection (null clears to the default); false on failure. */
        boolean persistNew(String saveValueOrNull);
    }

    /** Pure outcome of an origin switch: no Android types involved. */
    public static final class SwitchOutcome {
        public final boolean applied;
        public final boolean success;
        /** Retry message when {@code success} is false, else null. */
        public final String error;

        public SwitchOutcome(boolean applied, boolean success, String error) {
            this.applied = applied;
            this.success = success;
            this.error = error;
        }
    }

    /**
     * Fail-closed switch ordering: no-op when the selection is unchanged
     * (boundary untouched), otherwise purge first and persist only on purge
     * success. Any failure reports {@code success=false} with an inline
     * retry message and the caller must not reload.
     */
    public static SwitchOutcome executeSwitch(String prev, String next,
            String saveValueOrNull, SwitchBoundary boundary) {
        if (next != null && next.equals(prev)) {
            return new SwitchOutcome(false, true, null);
        }
        boolean purged = (prev == null) || boundary.purgeOld(prev);
        if (!purged) {
            return new SwitchOutcome(false, false, PURGE_RETRY_MESSAGE);
        }
        boolean saved = boundary.persistNew(saveValueOrNull);
        if (!saved) {
            return new SwitchOutcome(false, false, SAVE_RETRY_MESSAGE);
        }
        return new SwitchOutcome(true, true, null);
    }

    /**
     * Collision-free origin slot token: unpadded URL-safe Base64 of the
     * full origin, so distinct origins (including scheme and port) never
     * share a prefs slot.
     */
    public static String originSlotToken(String origin) {
        if (origin == null || origin.isEmpty()) {
            return "";
        }
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(origin.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Origin-scoped credential slot: "<originSlotToken>:<account>" so
     * credentials sealed under one origin can never be unlocked against
     * another origin's slot.
     */
    public static String credentialSlot(String origin, String account) {
        String acct = (account == null) ? "" : account.replaceAll("[^A-Za-z0-9_-]", "_");
        String token = originSlotToken(origin);
        return token.isEmpty() ? acct : token + ":" + acct;
    }
}
