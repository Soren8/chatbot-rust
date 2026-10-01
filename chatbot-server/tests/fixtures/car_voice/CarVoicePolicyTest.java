import com.chatbot.app.car.CarVoicePolicy;

public final class CarVoicePolicyTest {
    public static void main(String[] args) {
        CarVoicePolicy.CaptureReads reads = new CarVoicePolicy.CaptureReads();
        if (reads.onRead(320) != CarVoicePolicy.CaptureReads.PROCESS) throw new AssertionError("frame processed");
        for (int error : new int[]{-1, -2, -3, -6}) {
            if (reads.onRead(error) != CarVoicePolicy.CaptureReads.STOP) throw new AssertionError("read error " + error + " stops capture");
        }
        CarVoicePolicy.CaptureReads idle = new CarVoicePolicy.CaptureReads();
        int logged = 0;
        for (int i = 0; i < 10000; i++) {
            if (idle.onRead(0) != CarVoicePolicy.CaptureReads.BACK_OFF) throw new AssertionError("empty read backs off");
            if (idle.logIdle()) logged++;
        }
        if (logged < 1 || logged > 50) throw new AssertionError("idle read logging must be rate-bounded, logged " + logged);
        idle.onRead(320);
        idle.onRead(0);
        if (!idle.logIdle()) throw new AssertionError("a new idle run logs its first read");

        CarVoicePolicy.TurnSlot<String> turns = new CarVoicePolicy.TurnSlot<>();
        if (!"first".equals(turns.offer("first"))) throw new AssertionError("idle slot starts the turn");
        if (turns.offer("second") != null) throw new AssertionError("in-flight turn holds the next utterance");
        if (turns.offer("third") != null) throw new AssertionError("in-flight turn holds the next utterance");
        if (!"third".equals(turns.finish())) throw new AssertionError("only the newest pending utterance runs next");
        if (turns.finish() != null) throw new AssertionError("at most one utterance pending");
        if (!"fourth".equals(turns.offer("fourth"))) throw new AssertionError("finished slot starts the next turn");

        if (CarVoicePolicy.drainMs(48000, 1024 * 1024, 24000) != 1000) throw new AssertionError("short clip drains its own length");
        if (CarVoicePolicy.drainMs(10L * 1024 * 1024, 1024 * 1024, 24000) != 21845) throw new AssertionError("blocking writes already played beyond the buffer");
        if (CarVoicePolicy.drainMs(0, 1024 * 1024, 24000) != 0) throw new AssertionError("nothing written drains nothing");
    }
}
