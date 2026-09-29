import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class Phase4TtsLogTest {
    static final String TAG = "NativeVoiceTts";
    static final String SECRET = "https://server.example/tts_stream/SECRET-BEARER-TOKEN";
    static final int QUEUE_POLL_MS = 100, MAX_CLIP_ATTEMPTS = 4, CLIP_RETRY_BACKOFF_MS = 1;
    boolean active = true;
    Flag endOfQueueMarked = new Flag();
    List<String> events = new ArrayList<>();
    int attempts;

    /* SHIPPED_METHODS */

    boolean isGenerationActive(long generation) { return active; }
    AudioClip playUrlToTrackOnce(String url, long generation) throws IOException {
        attempts++;
        throw new IOException("download failed for " + url);
    }
    void writePcmToTrack(int rate, byte[] pcm, long generation) {}
    void drainPlaybackBuffer() {}
    void stopPlaybackInternal(boolean notify) { active = false; }
    void releaseAudioTrack(long generation) { active = false; }
    void notifyListeners(String name, JSObject event) { events.add(event.get("type").toString()); }

    static void check(String scenario, String diagnostic) {
        for (String entry : Log.messages) {
            if (entry.contains(SECRET)) throw new AssertionError(scenario + " leaked bearer URL: " + entry);
        }
        if (Log.messages.stream().noneMatch(entry -> entry.contains(diagnostic)))
            throw new AssertionError(scenario + " lost diagnostic " + diagnostic + ": " + Log.messages);
        System.out.println("PASS " + scenario);
        Log.messages.clear();
    }
    public static void main(String[] args) throws Exception {
        Phase4TtsLogTest retry = new Phase4TtsLogTest();
        try { retry.playUrlToTrack(SECRET, 1); throw new AssertionError("retry failure must propagate"); }
        catch (IOException expected) {}
        if (retry.attempts != MAX_CLIP_ATTEMPTS) throw new AssertionError("retry count: " + retry.attempts);
        check("download_io_exception", "attempt");

        Phase4TtsLogTest failedClip = new Phase4TtsLogTest();
        failedClip.workerLoop(1, new TtsDownloadQueue<>(new ExecutionException(new IOException(SECRET))));
        if (!failedClip.events.equals(List.of("clipConsumed"))) throw new AssertionError("failed clip was not consumed");
        check("queue_execution_exception", "clip failed");

        Phase4TtsLogTest failedLoop = new Phase4TtsLogTest();
        failedLoop.workerLoop(1, new TtsDownloadQueue<>(new IllegalStateException(SECRET)));
        check("loop_runtime_exception", "playback loop error");
    }
    static class AudioClip { int sampleRate; byte[] pcm; }
    static class Flag { boolean get() { return true; } }
    static class JSObject extends java.util.HashMap<String, Object> {}
    static class ClientLogReporter { static void report(String tag, String text) {} }
    static class Log {
        static List<String> messages = new ArrayList<>();
        static void e(String tag, String message, Throwable cause) { messages.add(message + " " + cause); }
        static void e(String tag, String message) { messages.add(message); }
    }
    static class TtsDownloadQueue<T> {
        Exception failure;
        int polls;
        TtsDownloadQueue(Exception failure) { this.failure = failure; }
        Clip<T> poll(long timeout, TimeUnit unit) throws InterruptedException {
            if (polls++ == 0 && failure instanceof ExecutionException) return new Clip<>((ExecutionException) failure);
            if (failure instanceof RuntimeException) throw (RuntimeException) failure;
            return null;
        }
        boolean isIdle() { return true; }
        void complete(Clip<T> clip) {}
        static class Clip<T> {
            String id = SECRET;
            ExecutionException failure;
            Clip(ExecutionException failure) { this.failure = failure; }
            T await() throws ExecutionException { throw failure; }
        }
    }
}
