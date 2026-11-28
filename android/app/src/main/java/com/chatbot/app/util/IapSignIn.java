package com.chatbot.app.util;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Native half of the identity-aware proxy sign-in (oauth2-proxy behind nginx
 * {@code auth_request}, one instance per provider).
 *
 * <p>Google refuses OAuth inside an embedded WebView and the WebView page-load
 * proxy only keeps the final response's {@code Set-Cookie}, so the app runs
 * the {@code /oauth2/<provider>/start} and {@code /oauth2/<provider>/callback}
 * requests itself (no redirect following), keeps their cookies in the WebView
 * jar, and hands only the provider authorization URL to the system browser.
 *
 * <p>Everything is rejected by default: the server must be https, URLs must be
 * on the server's exact origin (scheme, host, effective port) without
 * userinfo, paths are compared raw and exactly, and redirect targets are
 * pinned to the provider host or the server origin. Cookie values and the
 * callback query are never logged or exposed.
 *
 * <p>Pure Java (no Android imports); see {@code IapSignInTest}.
 */
public final class IapSignIn {
    private static final String GOOGLE = "google";
    private static final String GITHUB = "github";
    private static final String GOOGLE_AUTH_HOST = "accounts.google.com";
    private static final String GITHUB_AUTH_HOST = "github.com";
    private static final int HTTPS_PORT = 443;
    private static final int FOUND = 302;

    private IapSignIn() {
    }

    /** One HTTP GET that must NOT follow redirects. */
    public interface Transport {
        /** {@code cookieHeader} may be null. */
        Response get(String url, String cookieHeader) throws IOException;
    }

    /** Status, Location and raw Set-Cookie values of one response. */
    public static final class Response {
        public final int status;
        /** Location header or null. */
        public final String location;
        /** Raw Set-Cookie header values, never null. */
        public final List<String> setCookies;

        public Response(int status, String location, List<String> setCookies) {
            this.status = status;
            this.location = location;
            this.setCookies = setCookies == null
                    ? Collections.<String>emptyList()
                    : Collections.unmodifiableList(setCookies);
        }
    }

    /** The WebView cookie jar. */
    public interface CookieJar {
        /** Cookie header value for url, or null. */
        String get(String url);

        /** Store one raw Set-Cookie value for url. */
        void set(String url, String setCookie);

        void flush();
    }

    /**
     * True when {@code url} is on serverUrl's exact origin and its path is
     * exactly {@code /oauth2/google/start} or {@code /oauth2/github/start}.
     */
    public static boolean isStartUrl(String serverUrl, String url) {
        return endpointProvider(serverUrl, url, "start") != null;
    }

    /**
     * True when {@code url} is on serverUrl's exact origin and its path is
     * exactly {@code /oauth2/google/callback} or {@code /oauth2/github/callback}.
     */
    public static boolean isCallbackUrl(String serverUrl, String url) {
        return endpointProvider(serverUrl, url, "callback") != null;
    }

    /**
     * True when {@code url} is on serverUrl's exact origin and its path is
     * {@code /oauth2} or under {@code /oauth2/} (the proxy's own pages).
     */
    public static boolean isProxyPageUrl(String serverUrl, String url) {
        Origin server = serverOrigin(serverUrl);
        URI uri = parseAbsolute(url);
        if (server == null || uri == null || !server.matches(uri)) {
            return false;
        }
        String path = uri.getRawPath();
        return "/oauth2".equals(path) || (path != null && path.startsWith("/oauth2/"));
    }

    /**
     * Runs the start request. Returns the provider authorization URL to open in
     * the system browser, or null when the response is not a usable sign-in
     * redirect. Stores the response's Set-Cookie values in the jar (for
     * serverUrl) and flushes only when it returns non-null.
     */
    public static String begin(String serverUrl, String startUrl, Transport transport, CookieJar jar)
            throws IOException {
        String provider = endpointProvider(serverUrl, startUrl, "start");
        if (provider == null) {
            return null;
        }
        Response response = transport.get(startUrl, null);
        if (response == null || response.status != FOUND || !isProviderAuthUrl(provider, response.location)) {
            return null;
        }
        store(serverUrl, response.setCookies, jar);
        return response.location;
    }

    /**
     * Runs the callback request with the jar's cookies. On a redirect to a
     * same-origin target, stores every Set-Cookie value, flushes, and returns
     * the absolute URL to load in the WebView (the server root when the target
     * is under {@code /oauth2}). Returns null (storing nothing) otherwise.
     */
    public static String complete(String serverUrl, String callbackUrl, Transport transport, CookieJar jar)
            throws IOException {
        if (endpointProvider(serverUrl, callbackUrl, "callback") == null) {
            return null;
        }
        String cookieHeader = jar.get(serverUrl);
        if (cookieHeader != null && cookieHeader.isEmpty()) {
            cookieHeader = null;
        }
        Response response = transport.get(callbackUrl, cookieHeader);
        if (response == null || response.status != FOUND) {
            return null;
        }
        String target = sameOriginTarget(serverUrl, response.location);
        if (target == null) {
            return null;
        }
        store(serverUrl, response.setCookies, jar);
        return target;
    }

    private static void store(String serverUrl, List<String> setCookies, CookieJar jar) {
        for (String setCookie : setCookies) {
            if (setCookie != null && !setCookie.isEmpty()) {
                jar.set(serverUrl, setCookie);
            }
        }
        jar.flush();
    }

    /** Provider name when {@code url} is {@code /oauth2/<provider>/<endpoint>} on the server origin. */
    private static String endpointProvider(String serverUrl, String url, String endpoint) {
        Origin server = serverOrigin(serverUrl);
        URI uri = parseAbsolute(url);
        if (server == null || uri == null || !server.matches(uri) || uri.getRawFragment() != null) {
            return null;
        }
        String path = uri.getRawPath();
        if (("/oauth2/" + GOOGLE + "/" + endpoint).equals(path)) {
            return GOOGLE;
        }
        if (("/oauth2/" + GITHUB + "/" + endpoint).equals(path)) {
            return GITHUB;
        }
        return null;
    }

    private static boolean isProviderAuthUrl(String provider, String location) {
        URI uri = parseAbsolute(location);
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }
        int port = uri.getPort();
        if (port != -1 && port != HTTPS_PORT) {
            return false;
        }
        String expectedHost = GOOGLE.equals(provider) ? GOOGLE_AUTH_HOST : GITHUB_AUTH_HOST;
        return expectedHost.equals(uri.getHost().toLowerCase(Locale.ROOT));
    }

    /**
     * Absolute URL on the server origin for a callback Location: a path
     * starting with a single "/" or an absolute same-origin URL. Targets under
     * {@code /oauth2} map to the server root. Null when unusable.
     */
    private static String sameOriginTarget(String serverUrl, String location) {
        Origin server = serverOrigin(serverUrl);
        if (server == null || location == null || location.isEmpty() || hasControlChar(location)) {
            return null;
        }
        String absolute;
        if (location.startsWith("/")) {
            if (location.startsWith("//") || location.startsWith("/\\")) {
                return null;
            }
            absolute = server.root + location.substring(1);
        } else {
            absolute = location;
        }
        URI uri = parseAbsolute(absolute);
        if (uri == null || !server.matches(uri)) {
            return null;
        }
        String path = uri.normalize().getRawPath();
        if (path == null || path.isEmpty() || path.startsWith("/oauth2")) {
            return server.root;
        }
        return absolute;
    }

    private static boolean hasControlChar(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    /** Hierarchical absolute URL with a plain server authority (no userinfo), else null. */
    private static URI parseAbsolute(String url) {
        if (url == null || url.isEmpty() || hasControlChar(url)) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return null;
        }
        if (!uri.isAbsolute() || uri.isOpaque() || uri.getRawUserInfo() != null) {
            return null;
        }
        String host = uri.getHost();
        String authority = uri.getRawAuthority();
        if (host == null || host.isEmpty() || authority == null) {
            return null;
        }
        int port = uri.getPort();
        String expected = port == -1 ? host : host + ":" + port;
        if (!authority.equalsIgnoreCase(expected)) {
            return null;
        }
        return uri;
    }

    private static Origin serverOrigin(String serverUrl) {
        URI uri = parseAbsolute(serverUrl);
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            return null;
        }
        String path = uri.getRawPath();
        if (path != null && !path.isEmpty() && !path.equals("/")) {
            return null;
        }
        return new Origin(uri.getHost().toLowerCase(Locale.ROOT), effectivePort(uri));
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1 ? HTTPS_PORT : uri.getPort();
    }

    /** https origin: lower-cased host and effective port. */
    private static final class Origin {
        final String host;
        final int port;
        /** Canonical root URL with trailing "/". */
        final String root;

        Origin(String host, int port) {
            this.host = host;
            this.port = port;
            this.root = "https://" + host + (port == HTTPS_PORT ? "" : ":" + port) + "/";
        }

        boolean matches(URI uri) {
            return "https".equalsIgnoreCase(uri.getScheme())
                    && host.equals(uri.getHost().toLowerCase(Locale.ROOT))
                    && port == effectivePort(uri);
        }
    }
}
