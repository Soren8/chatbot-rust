package com.chatbot.app.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

/**
 * Behavior tests for {@link IapSignIn}: the native half of the identity-aware
 * proxy sign-in. Hand-written fakes stand in for the HTTP transport and the
 * WebView cookie jar.
 */
public class IapSignInTest {

    private static final String SERVER = "https://chat.example.com";
    private static final String GOOGLE_START = SERVER + "/oauth2/google/start?rd=%2Fchat";
    private static final String GITHUB_START = SERVER + "/oauth2/github/start";
    private static final String GOOGLE_CALLBACK = SERVER + "/oauth2/google/callback?code=c0de&state=st4te";
    private static final String GITHUB_CALLBACK = SERVER + "/oauth2/github/callback?code=c0de&state=st4te";
    private static final String GOOGLE_AUTH =
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=s";
    private static final String GITHUB_AUTH =
            "https://github.com/login/oauth/authorize?client_id=x&state=s";

    private static final class FakeTransport implements IapSignIn.Transport {
        IapSignIn.Response response;
        final List<String> urls = new ArrayList<>();
        final List<String> cookieHeaders = new ArrayList<>();

        @Override
        public IapSignIn.Response get(String url, String cookieHeader) throws IOException {
            urls.add(url);
            cookieHeaders.add(cookieHeader);
            return response;
        }
    }

    private static final class FakeJar implements IapSignIn.CookieJar {
        String header;
        final List<String> getUrls = new ArrayList<>();
        final List<String> setUrls = new ArrayList<>();
        final List<String> setValues = new ArrayList<>();
        int flushes;

        @Override
        public String get(String url) {
            getUrls.add(url);
            return header;
        }

        @Override
        public void set(String url, String setCookie) {
            setUrls.add(url);
            setValues.add(setCookie);
        }

        @Override
        public void flush() {
            flushes++;
        }
    }

    @Test
    public void proxyPageUrlMatchesOauth2PathsOnServerOrigin() {
        assertTrue(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2"));
        assertTrue(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2/"));
        assertTrue(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2/sign_in?rd=%2Fchat"));
        assertTrue(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2/start#top"));
        assertTrue(IapSignIn.isProxyPageUrl(SERVER, GOOGLE_START));
        assertTrue(IapSignIn.isProxyPageUrl(SERVER + "/", "https://CHAT.example.com:443/oauth2/sign_in"));
        assertTrue(IapSignIn.isProxyPageUrl("https://chat.example.com:8443",
                "https://chat.example.com:8443/oauth2/sign_in"));
    }

    @Test
    public void proxyPageUrlRejectsOtherPathsAndOrigins() {
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/chat"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2x"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/oauth2-sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, SERVER + "/login?next=/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, "https://other.example.com/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, "http://chat.example.com/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, "https://chat.example.com:8443/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, "https://user@chat.example.com/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, null));
        assertFalse(IapSignIn.isProxyPageUrl(SERVER, ""));
        assertFalse(IapSignIn.isProxyPageUrl(null, SERVER + "/oauth2/sign_in"));
        assertFalse(IapSignIn.isProxyPageUrl("http://10.0.2.2:80", "http://10.0.2.2:80/oauth2/sign_in"));
    }

    private FakeTransport transport;
    private FakeJar jar;

    @Before
    public void setUp() {
        transport = new FakeTransport();
        jar = new FakeJar();
    }

    private static IapSignIn.Response redirect(int status, String location, String... cookies) {
        return new IapSignIn.Response(status, location, Arrays.asList(cookies));
    }

    private void assertNothingStored() {
        assertEquals(0, jar.setValues.size());
        assertEquals(0, jar.flushes);
    }

    // --- URL matching -------------------------------------------------------

    @Test
    public void startUrl_acceptsBothProvidersOnServerOrigin() {
        assertTrue(IapSignIn.isStartUrl(SERVER, GOOGLE_START));
        assertTrue(IapSignIn.isStartUrl(SERVER, GITHUB_START));
        assertTrue(IapSignIn.isStartUrl(SERVER + "/", SERVER + "/oauth2/google/start"));
        assertTrue(IapSignIn.isStartUrl(SERVER, "https://CHAT.Example.com/oauth2/github/start"));
        assertTrue(IapSignIn.isStartUrl(SERVER, "https://chat.example.com:443/oauth2/github/start"));
        assertTrue(IapSignIn.isStartUrl("https://chat.example.com:8443",
                "https://chat.example.com:8443/oauth2/google/start"));
    }

    @Test
    public void startUrl_rejectsOtherOrigins() {
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://evil.example.com/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://chat.example.com.evil.example/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "http://chat.example.com/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://chat.example.com:8443/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://user@chat.example.com/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://chat.example.com:443:80/oauth2/google/start"));
    }

    @Test
    public void startUrl_rejectsNonHttpsServer() {
        assertFalse(IapSignIn.isStartUrl("http://chat.example.com",
                "http://chat.example.com/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl("https://user@chat.example.com",
                "https://chat.example.com/oauth2/google/start"));
    }

    @Test
    public void startUrl_rejectsPathTricks() {
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/google/start/"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/google/start/x"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/x/oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/google/startx"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/x/../google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/google%2Fstart"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/%67oogle/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "//oauth2/google/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/OAUTH2/google/start"));
    }

    @Test
    public void startUrl_rejectsOtherProvidersAndEndpoints() {
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/gitlab/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/start"));
        assertFalse(IapSignIn.isStartUrl(SERVER, SERVER + "/oauth2/"));
        assertFalse(IapSignIn.isStartUrl(SERVER, GOOGLE_CALLBACK));
    }

    @Test
    public void startUrl_rejectsMissingOrMalformedInput() {
        assertFalse(IapSignIn.isStartUrl(null, GOOGLE_START));
        assertFalse(IapSignIn.isStartUrl(SERVER, null));
        assertFalse(IapSignIn.isStartUrl("", GOOGLE_START));
        assertFalse(IapSignIn.isStartUrl(SERVER, ""));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://chat.example.com/oauth2/google/start\\x"));
        assertFalse(IapSignIn.isStartUrl(SERVER, "https://chat.example.com/oauth2/google/start x"));
        assertFalse(IapSignIn.isStartUrl("not a url", GOOGLE_START));
        assertFalse(IapSignIn.isStartUrl(SERVER, "/oauth2/google/start"));
    }

    @Test
    public void callbackUrl_acceptsBothProvidersOnServerOrigin() {
        assertTrue(IapSignIn.isCallbackUrl(SERVER, GOOGLE_CALLBACK));
        assertTrue(IapSignIn.isCallbackUrl(SERVER, GITHUB_CALLBACK));
        assertTrue(IapSignIn.isCallbackUrl(SERVER + "/", SERVER + "/oauth2/google/callback"));
    }

    @Test
    public void callbackUrl_rejectsOtherOriginsPathsAndProviders() {
        assertFalse(IapSignIn.isCallbackUrl(SERVER, "https://evil.example.com/oauth2/google/callback?code=c"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, "http://chat.example.com/oauth2/google/callback?code=c"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, "https://chat.example.com:444/oauth2/google/callback"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, "https://a:b@chat.example.com/oauth2/google/callback"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, SERVER + "/oauth2/google/callback/"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, SERVER + "/oauth2/google/callbackx"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, SERVER + "/prefix/oauth2/google/callback"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, SERVER + "/oauth2/gitlab/callback"));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, GOOGLE_START));
        assertFalse(IapSignIn.isCallbackUrl("http://chat.example.com",
                "http://chat.example.com/oauth2/google/callback"));
        assertFalse(IapSignIn.isCallbackUrl(null, GOOGLE_CALLBACK));
        assertFalse(IapSignIn.isCallbackUrl(SERVER, null));
    }

    // --- begin --------------------------------------------------------------

    @Test
    public void begin_googleStoresCsrfCookieAndReturnsProviderUrl() throws IOException {
        transport.response = redirect(302, GOOGLE_AUTH, "__Host-iap_google_csrf=abc; Secure; HttpOnly; Path=/");
        assertEquals(GOOGLE_AUTH, IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        assertEquals(Collections.singletonList(GOOGLE_START), transport.urls);
        assertEquals(Collections.singletonList(SERVER), jar.setUrls);
        assertEquals(Collections.singletonList("__Host-iap_google_csrf=abc; Secure; HttpOnly; Path=/"),
                jar.setValues);
        assertEquals(1, jar.flushes);
    }

    @Test
    public void begin_githubStoresCookiesAndReturnsProviderUrl() throws IOException {
        transport.response = redirect(302, GITHUB_AUTH, "a=1", "b=2");
        assertEquals(GITHUB_AUTH, IapSignIn.begin(SERVER, GITHUB_START, transport, jar));
        assertEquals(Arrays.asList("a=1", "b=2"), jar.setValues);
        assertEquals(Arrays.asList(SERVER, SERVER), jar.setUrls);
        assertEquals(1, jar.flushes);
    }

    @Test
    public void begin_rejectsProviderHostMismatch() throws IOException {
        transport.response = redirect(302, GITHUB_AUTH, "a=1");
        assertNull(IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        transport.response = redirect(302, GOOGLE_AUTH, "a=1");
        assertNull(IapSignIn.begin(SERVER, GITHUB_START, transport, jar));
        assertNothingStored();
    }

    @Test
    public void begin_rejectsLookalikeAndUnsafeLocations() throws IOException {
        String[] bad = {
            "https://accounts.google.com.evil.example/o/oauth2/v2/auth",
            "https://evilaccounts.google.com/o/oauth2/v2/auth",
            "https://accounts.google.com@evil.example/o/oauth2/v2/auth",
            "https://user@accounts.google.com/o/oauth2/v2/auth",
            "http://accounts.google.com/o/oauth2/v2/auth",
            "https://accounts.google.com:8443/o/oauth2/v2/auth",
            "//accounts.google.com/o/oauth2/v2/auth",
            "/o/oauth2/v2/auth",
            "javascript:alert(1)",
            "https://accounts.google.com/o/oauth2\r\nX: y",
            "",
        };
        for (String location : bad) {
            transport.response = redirect(302, location, "a=1");
            assertNull(location, IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        }
        assertNothingStored();
    }

    @Test
    public void begin_rejectsNonRedirectStatusAndMissingLocation() throws IOException {
        int[] statuses = {200, 301, 303, 307, 308, 401, 500};
        for (int status : statuses) {
            transport.response = redirect(status, GOOGLE_AUTH, "a=1");
            assertNull("status " + status, IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        }
        transport.response = redirect(302, null, "a=1");
        assertNull(IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        transport.response = null;
        assertNull(IapSignIn.begin(SERVER, GOOGLE_START, transport, jar));
        assertNothingStored();
    }

    @Test
    public void begin_rejectsNonStartUrlWithoutRequest() throws IOException {
        transport.response = redirect(302, GOOGLE_AUTH, "a=1");
        assertNull(IapSignIn.begin(SERVER, "https://evil.example.com/oauth2/google/start", transport, jar));
        assertNull(IapSignIn.begin(SERVER, GOOGLE_CALLBACK, transport, jar));
        assertNull(IapSignIn.begin("http://chat.example.com",
                "http://chat.example.com/oauth2/google/start", transport, jar));
        assertEquals(0, transport.urls.size());
        assertNothingStored();
    }

    // --- complete -----------------------------------------------------------

    @Test
    public void complete_sendsJarCookiesStoresAllSetCookiesAndResolvesRelativeLocation()
            throws IOException {
        jar.header = "__Host-iap_google_csrf=abc";
        transport.response = redirect(302, "/chat?x=1",
                "__Host-iap_google_0=s0; Secure; HttpOnly; Path=/",
                "__Host-iap_google_1=s1; Secure; HttpOnly; Path=/",
                "__Host-iap_google_csrf=; Max-Age=0; Path=/",
                "__Host-iap_github=; Max-Age=0; Path=/");
        assertEquals(SERVER + "/chat?x=1", IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        assertEquals(Collections.singletonList(GOOGLE_CALLBACK), transport.urls);
        assertEquals(Collections.singletonList("__Host-iap_google_csrf=abc"), transport.cookieHeaders);
        assertEquals(Arrays.asList(
                "__Host-iap_google_0=s0; Secure; HttpOnly; Path=/",
                "__Host-iap_google_1=s1; Secure; HttpOnly; Path=/",
                "__Host-iap_google_csrf=; Max-Age=0; Path=/",
                "__Host-iap_github=; Max-Age=0; Path=/"), jar.setValues);
        assertEquals(Arrays.asList(SERVER, SERVER, SERVER, SERVER), jar.setUrls);
        assertEquals(1, jar.flushes);
    }

    @Test
    public void complete_rootLocationResolvesToServerRoot() throws IOException {
        transport.response = redirect(302, "/", "s=1");
        assertEquals(SERVER + "/", IapSignIn.complete(SERVER + "/", GITHUB_CALLBACK, transport, jar));
        assertEquals(1, jar.flushes);
    }

    @Test
    public void complete_acceptsAbsoluteSameOriginLocation() throws IOException {
        transport.response = redirect(302, SERVER + "/settings", "s=1");
        assertEquals(SERVER + "/settings", IapSignIn.complete(SERVER, GITHUB_CALLBACK, transport, jar));
        assertEquals(Collections.singletonList("s=1"), jar.setValues);
        assertEquals(1, jar.flushes);
    }

    @Test
    public void complete_rejectsCrossOriginAndUnsafeLocations() throws IOException {
        String[] bad = {
            "https://evil.example.com/chat",
            "https://chat.example.com.evil.example/chat",
            "http://chat.example.com/chat",
            "https://chat.example.com:8443/chat",
            "https://user@chat.example.com/chat",
            "//evil.example.com/chat",
            "/\\evil.example.com/chat",
            "\\\\evil.example.com/chat",
            "chat",
            "javascript:alert(1)",
            "/chat\r\nSet-Cookie: x=y",
            "/chat\u0000",
            "/chat path",
            "",
        };
        for (String location : bad) {
            transport.response = redirect(302, location, "s=1");
            assertNull(location, IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        }
        assertNothingStored();
    }

    @Test
    public void complete_mapsSignInLoopLocationToServerRoot() throws IOException {
        transport.response = redirect(302, "/oauth2/?rd=%2F", "s=1");
        assertEquals(SERVER + "/", IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        transport.response = redirect(302, SERVER + "/oauth2/google/start", "t=2");
        assertEquals(SERVER + "/", IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        assertEquals(Arrays.asList("s=1", "t=2"), jar.setValues);
        assertEquals(2, jar.flushes);
    }

    @Test
    public void complete_rejectsNonRedirectStatusAndMissingLocation() throws IOException {
        int[] statuses = {200, 301, 303, 307, 308, 403, 500};
        for (int status : statuses) {
            transport.response = redirect(status, "/chat", "s=1");
            assertNull("status " + status, IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        }
        transport.response = redirect(302, null, "s=1");
        assertNull(IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        transport.response = null;
        assertNull(IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        assertNothingStored();
    }

    @Test
    public void complete_rejectsNonCallbackUrlWithoutRequest() throws IOException {
        transport.response = redirect(302, "/chat", "s=1");
        assertNull(IapSignIn.complete(SERVER, "https://evil.example.com/oauth2/google/callback?code=c",
                transport, jar));
        assertNull(IapSignIn.complete(SERVER, GOOGLE_START, transport, jar));
        assertEquals(0, transport.urls.size());
        assertNothingStored();
    }

    @Test
    public void complete_passesNullCookieHeaderWhenJarEmpty() throws IOException {
        transport.response = redirect(302, "/chat", "s=1");
        assertEquals(SERVER + "/chat", IapSignIn.complete(SERVER, GOOGLE_CALLBACK, transport, jar));
        assertEquals(Collections.singletonList((String) null), transport.cookieHeaders);
    }
}
