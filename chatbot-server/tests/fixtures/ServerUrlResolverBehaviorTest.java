import com.chatbot.app.util.ServerUrlResolver;

/**
 * Pure-Java behavior of the shipped {@link ServerUrlResolver} with no Android
 * framework and no Bridge: raw strings in, canonical origin out. Compiled
 * together with the production file by the cargo harness
 * (see chatbot-server/tests/distribution.rs) and executed with plain
 * {@code java}; each scenario throws on mismatch.
 */
public final class ServerUrlResolverBehaviorTest {
    private static final String EMULATOR_URL = "http://10.0.2.2:80";
    private static final String PHYSICAL_URL = "https://desktop-1.tailfc0df0.ts.net";

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void checkEquals(String expected, String actual, String scenario) {
        check(expected.equals(actual),
                scenario + ": expected <" + expected + "> but was <" + actual + ">");
    }

    private static void canonicalReturnsEmulatorFlavorResource() {
        checkEquals(EMULATOR_URL,
                ServerUrlResolver.resolveCanonical(EMULATOR_URL),
                "canonicalReturnsEmulatorFlavorResource");
    }

    private static void canonicalReturnsPhysicalFlavorResource() {
        checkEquals(PHYSICAL_URL,
                ServerUrlResolver.resolveCanonical(PHYSICAL_URL),
                "canonicalReturnsPhysicalFlavorResource");
    }

    private static void canonicalEmulatorHasNoTailscale() {
        // The emulator always runs on the dev machine: plain loopback, no Tailnet.
        check(!ServerUrlResolver.resolveCanonical(EMULATOR_URL).contains("ts.net"),
                "canonicalEmulatorHasNoTailscale");
    }

    private static void canonicalPhysicalIsHttps() {
        // The physical WebView origin must stay a secure context.
        check(ServerUrlResolver.resolveCanonical(PHYSICAL_URL).startsWith("https://"),
                "canonicalPhysicalIsHttps");
    }

    private static void canonicalFallsBackWhenNull() {
        checkEquals(ServerUrlResolver.FALLBACK_URL,
                ServerUrlResolver.resolveCanonical(null),
                "canonicalFallsBackWhenNull");
    }

    private static void canonicalFallsBackWhenEmpty() {
        checkEquals(ServerUrlResolver.FALLBACK_URL,
                ServerUrlResolver.resolveCanonical(""),
                "canonicalFallsBackWhenEmpty");
    }

    private static void canonicalWhitespaceCountsAsNonEmpty() {
        // Legacy isEmpty (not trim) semantics are preserved: whitespace wins.
        checkEquals(" ", ServerUrlResolver.resolveCanonical(" "),
                "canonicalWhitespaceCountsAsNonEmpty");
    }

    private static void fallbackIsLocalhost() {
        checkEquals("http://localhost", ServerUrlResolver.FALLBACK_URL,
                "fallbackIsLocalhost");
    }

    private static void normalizeResourceTrimsAndStripsTrailingSlashes() {
        checkEquals("https://example.com",
                ServerUrlResolver.normalizeResource("  https://example.com///  "),
                "normalizeResourceTrimsAndStripsTrailingSlashes");
    }

    private static void normalizeResourceNullStaysNull() {
        check(ServerUrlResolver.normalizeResource(null) == null,
                "normalizeResourceNullStaysNull");
    }

    private static void normalizeResourceDegenerateStaysEmpty() {
        // The caller keeps its non-empty guard; degenerate input is not
        // silently promoted to the fallback here.
        checkEquals("", ServerUrlResolver.normalizeResource(""),
                "normalizeResourceDegenerateStaysEmpty/empty");
        checkEquals("", ServerUrlResolver.normalizeResource("///"),
                "normalizeResourceDegenerateStaysEmpty/slashes");
    }

    public static void main(String[] args) {
        canonicalReturnsEmulatorFlavorResource();
        canonicalReturnsPhysicalFlavorResource();
        canonicalEmulatorHasNoTailscale();
        canonicalPhysicalIsHttps();
        canonicalFallsBackWhenNull();
        canonicalFallsBackWhenEmpty();
        canonicalWhitespaceCountsAsNonEmpty();
        fallbackIsLocalhost();
        normalizeResourceTrimsAndStripsTrailingSlashes();
        normalizeResourceNullStaysNull();
        normalizeResourceDegenerateStaysEmpty();
        System.out.println("ServerUrlResolverBehaviorTest: all 11 behaviors passed");
    }
}
