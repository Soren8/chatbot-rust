import com.chatbot.app.car.DurableVoiceProtocol;

public final class DurableVoiceProtocolTest {
    public static void main(String[] args) throws Exception {
        DurableVoiceProtocol protocol = new DurableVoiceProtocol("generation-1");
        if (!protocol.apply(1, "delta", "First sentence.")) throw new AssertionError("new delta");
        if (protocol.apply(1, "delta", "First sentence.")) throw new AssertionError("duplicate delta");
        if (!protocol.eventsPath().equals("/generations/generation-1/events?after=1")) throw new AssertionError("reconnect cursor");
        try { protocol.apply(3, "delta", "gap"); throw new AssertionError("gap accepted"); }
        catch (java.io.IOException expected) {}
        protocol.apply(2, "thinking", "not spoken");
        protocol.apply(3, "delta", " Second sentence.");
        protocol.apply(4, "saved", "");
        if (!protocol.saved() || !protocol.text().equals("First sentence. Second sentence.")) throw new AssertionError("text/settlement");
        if (!protocol.stopPath().equals("/generations/generation-1/stop")) throw new AssertionError("explicit Stop");
    }
}
