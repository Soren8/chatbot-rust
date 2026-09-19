package com.chatbot.app.util;

/**
 * Single canonical native origin: the build-flavor {@code server_url}
 * resource.
 *
 * <p>The build flavor always has precedence. The tracked root
 * {@code capacitor.config.json} defines BOTH {@code serverUrls} entries
 * (emulator + physical) with no {@code server.url} override, and
 * {@code android/app/build.gradle} projects the matching entry per flavor
 * into {@code R.string.server_url}:
 *
 * <ul>
 *   <li>{@code emulator}: the dev-machine loopback over plain HTTP — never
 *       Tailnet.</li>
 *   <li>{@code physical}: the Tailscale Serve https origin, so the WebView
 *       stays a secure context.</li>
 * </ul>
 *
 * <p>No caller reads the Bridge URL or the CapConfig URL, so
 * the WebView origin, the cookie-jar mapping, the log reporter and the car
 * screen can never disagree (e.g. a dev override served by the Bridge while
 * the flavor resource points at production). Pure Java (no Android imports)
 * so the behavior stays portable; see {@code ServerUrlResolverTest}.
 */
public final class ServerUrlResolver {
    /** Last-resort origin when the flavor resource yields no value. */
    public static final String FALLBACK_URL = "http://localhost";

    private ServerUrlResolver() {
    }

    /** Legacy emptiness check, kept private: null or zero-length. */
    private static boolean isNonEmpty(String value) {
        return value != null && !value.isEmpty();
    }

    /**
     * Canonical origin: the flavor resource, always. Falls back to
     * {@link #FALLBACK_URL} only when the resource is missing or empty
     * (which never happens for a flavor build). Callers fetch the resource
     * inside their own exception guards; this method only applies the
     * flavor-always authority to the already-fetched value.
     */
    public static String resolveCanonical(String resourceUrl) {
        if (isNonEmpty(resourceUrl)) {
            return resourceUrl;
        }
        return FALLBACK_URL;
    }

    /**
     * Flavor-resource normalization for {@code ClientLogReporter.init}: trims
     * and strips trailing slashes. Returns null for null input; may return an
     * empty string for degenerate input (e.g. {@code "///"}) — the caller
     * keeps its pre-existing non-empty guard before storing.
     */
    public static String normalizeResource(String resourceUrl) {
        if (resourceUrl == null) {
            return null;
        }
        return resourceUrl.trim().replaceAll("/+$", "");
    }
}
