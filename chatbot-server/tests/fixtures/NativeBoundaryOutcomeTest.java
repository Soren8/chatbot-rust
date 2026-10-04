import com.chatbot.app.audio.TtsClipOutcome;
import com.chatbot.app.util.NativeUnlockGate;

public final class NativeBoundaryOutcomeTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(NativeUnlockGate.shouldLockEntry(false, true, false, true),
                "persistent credentials must gate a cold process entry");
        check(!NativeUnlockGate.shouldLockEntry(false, true, false, false),
                "guest entry must not prompt");
        check(NativeUnlockGate.shouldLockResume(true, 60_000, 60_000, false),
                "resume locks at the grace boundary");
        check(!NativeUnlockGate.shouldLockResume(true, 59_999, 60_000, false),
                "one-minute resume grace remains intact");
        check(!NativeUnlockGate.shouldLockResume(true, 120_000, 60_000, true),
                "only confirmed background voice is exempt");
        check(!NativeUnlockGate.shouldLockResume(false, 120_000, 60_000, false),
                "guest resume remains unlocked");
        check(!NativeUnlockGate.shouldLockEntry(false, true, true, true),
                "confirmed background voice remains exempt on cold entry");
        check(NativeUnlockGate.shouldLockEntry(true, false, true, false),
                "an unresolved lock survives Activity recreation even during voice");
        long restoredElapsed = NativeUnlockGate.elapsedSinceBackground(10_000, 71_000);
        check(NativeUnlockGate.shouldLockResume(true, restoredElapsed, 60_000, false),
                "persisted resume timestamp still locks at one minute after recreation");
        check(!NativeUnlockGate.shouldLockResume(true,
                        NativeUnlockGate.elapsedSinceBackground(10_000, 69_999), 60_000, false),
                "persisted timestamp preserves the sub-minute grace after recreation");
        check(NativeUnlockGate.canPrompt(0, 0) && !NativeUnlockGate.canPrompt(12, 0),
                "unavailable biometric hardware must not authorize the gate");

        check(TtsClipOutcome.forFailure(new TtsClipOutcome.ExpiredToken())
                        .equals(TtsClipOutcome.EXPIRED),
                "404 token expiry must remain distinguishable from clip failure");
        check(TtsClipOutcome.forFailure(new java.io.IOException("offline"))
                        .equals(TtsClipOutcome.FAILED),
                "transport failure must not masquerade as played");
        check(TtsClipOutcome.isExpiredHttpStatus(404), "404 status maps to expired");
        check(!TtsClipOutcome.isExpiredHttpStatus(401)
                        && !TtsClipOutcome.isExpiredHttpStatus(403),
                "authentication/authorization failures remain permanent failures");
        System.out.println("Native cold/resume gates and TTS outcomes passed");
    }
}
