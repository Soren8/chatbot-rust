import com.chatbot.app.car.DurableVoiceProtocol;

public final class DurableVoiceProtocolTest {
    public static void main(String[] args) throws Exception {
        final java.util.List<String> keys = new java.util.ArrayList<>();
        String admitted = DurableVoiceProtocol.retryAdmission("stable-key", (key) -> {
            keys.add(key);
            if (keys.size() == 1) throw new java.io.IOException("lost response");
            return "accepted";
        }, ms -> {});
        if (!admitted.equals("accepted") || !keys.equals(java.util.Arrays.asList("stable-key", "stable-key"))) throw new AssertionError("lost admission identity");
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
        DurableVoiceProtocol parser = new DurableVoiceProtocol("parsed");
        java.util.List<String> lines = new java.util.ArrayList<>();
        parser.feed("{\"type\":\"heart", lines::add);
        parser.feed("beat\"}\n\n{\"seq\":1,", lines::add);
        parser.feed("\"type\":\"delta\",\"text\":\"hello\"}\n", lines::add);
        if (lines.size() != 2 || !lines.get(0).equals("{\"type\":\"heartbeat\"}")) throw new AssertionError("partial NDJSON lines");
        parser.apply(0, "heartbeat", "");
        parser.apply(1, "unknown", "ignored");
        parser.apply(2, "delta", "hello");
        parser.apply(3, "ended", "");
        if (parser.saved()) throw new AssertionError("ended is not saved");
        parser.apply(4, "saved", "");
        if (!parser.saved() || !parser.text().equals("hello")) throw new AssertionError("settlement");
        try { new DurableVoiceProtocol("failed").apply(1, "error", "failure"); throw new AssertionError("error accepted"); }
        catch (java.io.IOException expected) {}
    }
}
