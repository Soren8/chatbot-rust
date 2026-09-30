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
        java.util.List<String> ttsKeys = new java.util.ArrayList<>();
        String renewed = DurableVoiceProtocol.openTts("sentence-key", key -> {
            ttsKeys.add(key);
            if (ttsKeys.size() == 1) throw new java.io.IOException("response body lost after admission");
            return ttsKeys.size() == 2 ? "expired" : "renewed";
        }, token -> "expired".equals(token) ? null : token, ms -> {});
        if (!"renewed".equals(renewed) || !ttsKeys.equals(java.util.Arrays.asList("sentence-key", "sentence-key", "sentence-key"))) throw new AssertionError("TTS body loss and token renewal preserve identity");
        if (DurableVoiceProtocol.selectSet(new String[]{"first", "default", "selected"}, new boolean[]{false, true, false}, "selected") != 2) throw new AssertionError("selected WebView set");
        if (DurableVoiceProtocol.selectSet(new String[]{"first", "default"}, new boolean[]{false, true}, "missing") != 1) throw new AssertionError("default fallback");
        if (!DurableVoiceProtocol.refreshRejectedVersion(409, "version_conflict") || DurableVoiceProtocol.refreshRejectedVersion(503, "version_conflict") || DurableVoiceProtocol.refreshRejectedVersion(409, "generation_active")) throw new AssertionError("only explicit version rejection changes intent");
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
