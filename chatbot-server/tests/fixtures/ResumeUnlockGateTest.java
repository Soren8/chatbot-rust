import androidx.biometric.BiometricManager;
import com.chatbot.app.util.NativeUnlockGate;

public final class ResumeUnlockGateTest {
    private static final class LockedSession {
        boolean locked = true;
        boolean overlayVisible = true;
        boolean promptShown;

        void retry(BiometricManager manager, String outcome) {
            if (!NativeUnlockGate.canPrompt(manager.canAuthenticate(3), BiometricManager.BIOMETRIC_SUCCESS)) {
                return;
            }
            promptShown = true;
            if ("success".equals(outcome)) {
                locked = false;
                overlayVisible = false;
            }
        }
    }

    private static void check(boolean condition, String caseName) {
        if (!condition) throw new AssertionError(caseName);
    }

    public static void main(String[] args) {
        BiometricManager manager = new BiometricManager();
        LockedSession session = new LockedSession();
        BiometricManager.status = BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
        session.retry(manager, "success");
        check(session.locked && session.overlayVisible && !session.promptShown, "unavailable must remain locked without prompt");

        BiometricManager.status = BiometricManager.BIOMETRIC_SUCCESS;
        session.retry(manager, "cancelled");
        check(session.locked && session.overlayVisible && session.promptShown, "cancelled must remain locked");
        session.retry(manager, "failed");
        check(session.locked && session.overlayVisible, "failed must remain locked");
        session.retry(manager, "success");
        check(!session.locked && !session.overlayVisible, "successful authentication must unlock");
        System.out.println("4 resume lock cases passed (unavailable, cancelled, failed, success)");
    }
}
