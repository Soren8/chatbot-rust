package com.chatbot.app.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Behavior tests for {@link ServerUrlResolver}: pure helper, no Android
 * framework, no Bridge — raw strings in, canonical origin out.
 *
 * <p>Contract under test (MOD017): the build flavor is the single authority.
 * The resolver takes only the flavor {@code server_url} resource and never a
 * Bridge/Config URL, so a dev override served by the Bridge cannot split the
 * cookie jar from the log/auto endpoints.
 */
public class ServerUrlResolverTest {

    private static final String EMULATOR_URL = "http://10.0.2.2:80";
    private static final String PHYSICAL_URL = "https://desktop-1.tailfc0df0.ts.net";

    @Test
    public void canonical_returnsEmulatorFlavorResource() {
        assertEquals(EMULATOR_URL, ServerUrlResolver.resolveCanonical(EMULATOR_URL));
    }

    @Test
    public void canonical_returnsPhysicalFlavorResource() {
        assertEquals(PHYSICAL_URL, ServerUrlResolver.resolveCanonical(PHYSICAL_URL));
    }

    @Test
    public void canonical_emulatorHasNoTailscale() {
        // The emulator always runs on the dev machine: plain loopback, no Tailnet.
        assertFalse(ServerUrlResolver.resolveCanonical(EMULATOR_URL).contains("ts.net"));
    }

    @Test
    public void canonical_physicalIsHttps() {
        // The physical WebView origin must stay a secure context.
        assertTrue(ServerUrlResolver.resolveCanonical(PHYSICAL_URL).startsWith("https://"));
    }

    @Test
    public void canonical_fallsBackWhenNull() {
        assertEquals(
                ServerUrlResolver.FALLBACK_URL, ServerUrlResolver.resolveCanonical(null));
    }

    @Test
    public void canonical_fallsBackWhenEmpty() {
        assertEquals(ServerUrlResolver.FALLBACK_URL, ServerUrlResolver.resolveCanonical(""));
    }

    @Test
    public void canonical_whitespaceCountsAsNonEmpty() {
        // Legacy isEmpty (not trim) semantics are preserved: whitespace wins.
        assertEquals(" ", ServerUrlResolver.resolveCanonical(" "));
    }

    @Test
    public void fallback_isLocalhost() {
        assertEquals("http://localhost", ServerUrlResolver.FALLBACK_URL);
    }

    @Test
    public void normalizeResource_trimsAndStripsTrailingSlashes() {
        assertEquals(
                "https://example.com",
                ServerUrlResolver.normalizeResource("  https://example.com///  "));
    }

    @Test
    public void normalizeResource_nullStaysNull() {
        assertNull(ServerUrlResolver.normalizeResource(null));
    }

    @Test
    public void normalizeResource_emptyStaysEmpty() {
        // The caller keeps its non-empty guard; degenerate input is not
        // silently promoted to the fallback here.
        assertEquals("", ServerUrlResolver.normalizeResource(""));
        assertEquals("", ServerUrlResolver.normalizeResource("///"));
    }
}
