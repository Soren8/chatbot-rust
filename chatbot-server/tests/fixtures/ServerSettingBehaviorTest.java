import com.chatbot.app.util.ServerUrlResolver;
import com.chatbot.app.util.ServerUrlSetting;
import com.chatbot.app.util.ServerUrlSetting.Store;

import java.util.ArrayList;
import java.util.List;

/**
 * Pure-Java behavior of the shipped {@link ServerUrlSetting}: override
 * selection over the flavor default, https-origin validation via java.net.URI
 * (including IPv6), collision-free origin slot tokens, and legacy fallback
 * semantics for corrupt overrides. Compiled together with the production
 * files by the cargo harness (chatbot-server/tests/distribution.rs) and run
 * with plain {@code java}; each scenario throws on mismatch.
 */
public final class ServerSettingBehaviorTest {

    private static final String FLAVOR_DEFAULT = "https://chat.staging.example.com";

    /** Read-only in-memory store fixture: same contract as the prefs store. */
    private static final class EmptyStore implements Store {
        public String saved() { return null; }
        public void save(String value) { throw new AssertionError("read-only fixture"); }
    }

    private static final class ValueStore implements Store {
        private String value;
        ValueStore(String initial) { this.value = initial; }
        public String saved() { return value; }
        public void save(String v) { value = v; }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void checkEquals(Object expected, Object actual, String scenario) {
        if (!expected.equals(actual)) {
            throw new AssertionError(
                    scenario + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void selectedFallsBackToFlavorDefault() {
        checkEquals(FLAVOR_DEFAULT,
                ServerUrlSetting.selected(new EmptyStore(), FLAVOR_DEFAULT),
                "selectedFallsBackToFlavorDefault");
    }

    private static void selectedFallsBackToResolverFallbackWhenEverythingNull() {
        checkEquals(ServerUrlResolver.FALLBACK_URL,
                ServerUrlSetting.selected(null, null),
                "selectedFallsBackWhenStoreNull");
    }

    private static void validOverrideWinsOverFlavorDefault() {
        checkEquals("https://chat.example.net",
                ServerUrlSetting.selected(new ValueStore("https://chat.example.net"),
                        FLAVOR_DEFAULT),
                "validOverrideWinsOverFlavorDefault");
    }

    private static void corruptStoredOverrideFallsBackToDefault() {
        // Prefs outlive validation changes; corrupt values must not break the app.
        checkEquals(FLAVOR_DEFAULT,
                ServerUrlSetting.selected(new ValueStore("not a url"), FLAVOR_DEFAULT),
                "corruptStoredOverrideFallsBackToDefault");
        checkEquals(FLAVOR_DEFAULT,
                ServerUrlSetting.selected(new ValueStore(""), FLAVOR_DEFAULT),
                "emptyStoredOverrideFallsBackToDefault");
    }

    private static void validOverrideAccepted() {
        checkEquals("https://chat.example.net",
                ServerUrlSetting.validate("  https://chat.example.net  "),
                "whitespaceTrimmedOverride");
        checkEquals("https://chat.example.net",
                ServerUrlSetting.validate("https://CHAT.Example.NET/"),
                "hostNormalizedAndTrailingSlashStripped");
        checkEquals("https://chat.example.net",
                ServerUrlSetting.validate("https://chat.example.net:443"),
                "defaultPortCollapsed");
        checkEquals("https://chat.example.net:8443",
                ServerUrlSetting.validate("https://chat.example.net:8443"),
                "hostPortOverrideAccepted");
        checkEquals("https://[2001:db8::1]:8443",
                ServerUrlSetting.validate("https://[2001:db8::1]:8443"),
                "ipv6WithPortAccepted");
        checkEquals("https://[2001:db8::1]",
                ServerUrlSetting.validate("https://[2001:db8::1]/"),
                "ipv6WithoutPortAccepted");
    }

    private static void rejectedInputsAreNotApplied() {
        for (String bad : new String[]{
                null, "", "   ", "http://chat.example.net", "https://",
                "https://user:pass@chat.example.net", "https://chat.example.net?q=1",
                "https://chat.example.net#frag", "https://chat.example.net/set",
                "https://chat.example.net/set/x", "https://chat.example.net:0",
                "https://chat.example.net:99999", "https://chat.example.net:80x",
                "https://chat.example.net:443:8080", "https://chat.example.net:0808",
                "https://chat.example.net:", "https://chat example.net",
                "chat.example.net", "https:///chat",
        }) {
            check(ServerUrlSetting.validate(bad) == null, "rejected: " + bad);
        }
    }

    private static void originSlotTokenIsCollisionFree() {
        String token = ServerUrlSetting.originSlotToken("https://a.example.com:8443");
        check(token.matches("[A-Za-z0-9_-]+"), "tokenIsUrlSafeBase64");

        // Distinct scheme, port, and host each get a distinct token.
        check(!ServerUrlSetting.originSlotToken("http://a.example.com:80")
                        .equals(ServerUrlSetting.originSlotToken("https://a.example.com:80")),
                "schemeChangesToken");
        check(!ServerUrlSetting.originSlotToken("https://a.example.com:80")
                        .equals(ServerUrlSetting.originSlotToken("https://a.example.com:8080")),
                "portChangesToken");
        check(!ServerUrlSetting.originSlotToken("https://a.example.com")
                        .equals(ServerUrlSetting.originSlotToken("https://b.example.com")),
                "hostChangesToken");
        // Same origin maps stably.
        checkEquals(ServerUrlSetting.originSlotToken("https://a.example.com:8443"),
                ServerUrlSetting.originSlotToken("https://a.example.com:8443"),
                "sameOriginSameToken");
    }

    private static void credentialSlotBindsOrigin() {
        checkEquals("demo_user",
                ServerUrlSetting.credentialSlot(null, "demo_user"),
                "credentialSlotNullOrigin");
        String slotA = ServerUrlSetting.credentialSlot("https://chat.example.com", "user");
        String slotB = ServerUrlSetting.credentialSlot("https://chat.example.com:8443", "user");
        String slotC = ServerUrlSetting.credentialSlot("http://chat.example.com", "user");
        check(!slotA.equals(slotB), "portChangeMovesSlot");
        check(!slotA.equals(slotC), "schemeChangeMovesSlot");
        // Legacy-format "::"-style slots cannot collide with token slots:
        // legacy keys start with ":" for the account, new tokens never do.
        check(!ServerUrlSetting.credentialSlot("https://chat.example.com", "user")
                        .startsWith(":"),
                "noLegacyCollision");
    }

    /**
     * Switch-purge policy: the server session bearer must expire alongside
     * the sealed-credential cookies. Cookie jars are host-scoped, so an old
     * "session" cookie would otherwise be sent to a newly selected origin on
     * another port (e.g. :443 to :8443). The credential-storage helper keeps
     * its session-preserving semantics for its own callers; only the switch
     * path uses this policy.
     */
    private static void switchPurgeCoversSessionAndCredentials() {
        check(ServerUrlSetting.isServerSwitchCookie("session"), "sessionPurgedOnSwitch");
        check(ServerUrlSetting.isServerSwitchCookie("remember"), "rememberPurgedOnSwitch");
        check(ServerUrlSetting.isServerSwitchCookie("remember-demo_user"),
                "perAccountRememberPurgedOnSwitch");
        check(ServerUrlSetting.isServerSwitchCookie("enc_key"), "encKeyPurgedOnSwitch");
        check(ServerUrlSetting.isServerSwitchCookie("enc_key-demo_user"),
                "perAccountEncKeyPurgedOnSwitch");
    }

    /** Switch-purge policy expires nothing but the switch cookies. */
    private static void switchPurgePreservesUnrelated() {
        for (String keep : new String[]{
                null, "", "other", "csrf", "preferences",
                "sessionid", "sessions", "session_token", "Session",
        }) {
            check(!ServerUrlSetting.isServerSwitchCookie(keep), "preserved: " + keep);
        }
    }

    /** Recording switch boundary: proves purge/save call order in the tests below. */
    private static final class RecordingBoundary implements ServerUrlSetting.SwitchBoundary {
        final boolean purgeResult;
        final boolean saveResult;
        final List<String> order = new ArrayList<>();
        String savedValue = "unset";

        RecordingBoundary(boolean purgeResult, boolean saveResult) {
            this.purgeResult = purgeResult;
            this.saveResult = saveResult;
        }

        public boolean purgeOld(String oldOrigin) {
            order.add("purge:" + oldOrigin);
            return purgeResult;
        }

        public boolean persistNew(String value) {
            order.add("save");
            savedValue = value;
            return saveResult;
        }
    }

    private static void switchNoopLeavesBoundaryUntouched() {
        RecordingBoundary boundary = new RecordingBoundary(true, true);
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                "https://chat.example.com", "https://chat.example.com",
                "https://chat.example.com", boundary);
        check(!outcome.applied && outcome.success && outcome.error == null,
                "noopSucceedsWithoutApplying");
        check(boundary.order.isEmpty(), "noopTouchesNoBoundary");
    }

    private static void switchPurgeFailureBlocksSave() {
        RecordingBoundary boundary = new RecordingBoundary(false, true);
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                "https://old.example.com", "https://new.example.com",
                "https://new.example.com", boundary);
        check(!outcome.success && !outcome.applied, "purgeFailureFails");
        check(outcome.error != null && !outcome.error.isEmpty(), "purgeFailureExplainsRetry");
        for (String call : boundary.order) {
            check(!call.equals("save"), "saveBlockedAfterPurgeFailure");
        }
        checkEquals(1, boundary.order.size(), "purgeAttemptedOnce");
    }

    private static void switchSuccessOrdersPurgeBeforeSave() {
        RecordingBoundary boundary = new RecordingBoundary(true, true);
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                "https://old.example.com", "https://new.example.com",
                "https://new.example.com", boundary);
        check(outcome.success && outcome.applied, "switchApplies");
        checkEquals(2, boundary.order.size(), "purgeThenSave");
        check(boundary.order.get(0).startsWith("purge:"), "purgeBeforeSave");
        check(boundary.order.get(1).equals("save"), "saveAfterPurge");
        checkEquals("https://new.example.com", boundary.savedValue, "savesNewSelection");
    }

    private static void switchSaveFailureReportsWithoutApplying() {
        RecordingBoundary boundary = new RecordingBoundary(true, false);
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                "https://old.example.com", "https://new.example.com",
                "https://new.example.com", boundary);
        check(!outcome.success && !outcome.applied, "saveFailureFails");
        check(outcome.error != null && !outcome.error.isEmpty(), "saveFailureExplainsRetry");
        checkEquals(2, boundary.order.size(), "purgeRanSaveRan");
    }

    private static void switchResetClearsOverrideOnSuccess() {
        RecordingBoundary boundary = new RecordingBoundary(true, true);
        ServerUrlSetting.SwitchOutcome outcome = ServerUrlSetting.executeSwitch(
                "https://old.example.com", "https://chat.example.com", null, boundary);
        check(outcome.success && outcome.applied, "resetApplies");
        check(boundary.savedValue == null, "resetClearsOverride");
    }

    public static void main(String[] args) {
        selectedFallsBackToFlavorDefault();
        selectedFallsBackToResolverFallbackWhenEverythingNull();
        validOverrideWinsOverFlavorDefault();
        corruptStoredOverrideFallsBackToDefault();
        validOverrideAccepted();
        rejectedInputsAreNotApplied();
        originSlotTokenIsCollisionFree();
        credentialSlotBindsOrigin();
        switchPurgeCoversSessionAndCredentials();
        switchPurgePreservesUnrelated();
        switchNoopLeavesBoundaryUntouched();
        switchPurgeFailureBlocksSave();
        switchSuccessOrdersPurgeBeforeSave();
        switchSaveFailureReportsWithoutApplying();
        switchResetClearsOverrideOnSuccess();
        System.out.println("ServerSettingBehaviorTest: all behaviors passed");
    }
}
