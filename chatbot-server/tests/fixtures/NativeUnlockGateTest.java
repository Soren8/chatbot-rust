import com.chatbot.app.util.NativeUnlockGate;

public final class NativeUnlockGateTest {
    public static void main(String[] args) {
        int success = 0;
        if (!NativeUnlockGate.canPrompt(success, success)) {
            throw new AssertionError("available biometric gate must permit prompt");
        }
        for (int unavailable : new int[]{-1, 1, 11, 12, 15}) {
            if (NativeUnlockGate.canPrompt(unavailable, success)) {
                throw new AssertionError("unavailable biometric gate must reject: " + unavailable);
            }
        }
    }
}
