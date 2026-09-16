import com.chatbot.app.audio.TtsDownloadQueue;
import com.chatbot.app.audio.TtsBodyInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class TtsDownloadQueueTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void await(CountDownLatch latch, String message) throws InterruptedException {
        check(latch.await(5, TimeUnit.SECONDS), message);
    }

    private static void downloadsOverlapButPlaybackRemainsOrdered() throws Exception {
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondFinished = new CountDownLatch(1);
        try (TtsDownloadQueue<String> queue = new TtsDownloadQueue<>(2, 4)) {
            check(queue.offer("first", () -> {
                firstStarted.countDown();
                await(releaseFirst, "test must release first download");
                return "first audio";
            }), "first accepted");
            await(firstStarted, "first download starts");
            check(queue.offer("second", () -> {
                secondFinished.countDown();
                return "second audio";
            }), "second accepted");
            await(secondFinished, "second must download while first is blocked on the link");
            TtsDownloadQueue.Clip<String> first = queue.poll(5, TimeUnit.SECONDS);
            check(first != null && first.id.equals("first"), "ready second clip cannot overtake first");
            releaseFirst.countDown();
            check(first.await().equals("first audio"), "first plays intact");
            queue.complete(first);
            TtsDownloadQueue.Clip<String> second = queue.poll(5, TimeUnit.SECONDS);
            check(second != null && second.await().equals("second audio"), "second follows first");
            queue.complete(second);
            check(queue.isIdle(), "completed queue drains");
        } finally {
            releaseFirst.countDown();
        }
    }

    private static void lookAheadIncludesDownloadedAndPlayingClips() throws Exception {
        try (TtsDownloadQueue<String> queue = new TtsDownloadQueue<>(2, 4)) {
            check(queue.offer("one", () -> "one"), "one accepted");
            check(queue.offer("two", () -> "two"), "two accepted");
            check(queue.offer("three", () -> "three"), "three accepted");
            check(queue.offer("four", () -> "four"), "four accepted");
            TtsDownloadQueue.Clip<String> playing = queue.poll(5, TimeUnit.SECONDS);
            check(playing != null && playing.await().equals("one"), "first ready for playback");
            check(!queue.offer("five", () -> "five"), "downloading/polling must not release playback capacity");
            queue.complete(playing);
            check(queue.offer("five", () -> "five"), "consuming one clip opens one slot");
            queue.complete(playing);
            check(!queue.offer("six", () -> "six"), "duplicate completion cannot overfill look-ahead");
        }
    }

    private static void stopCancelsActiveAndQueuedDownloads() throws Exception {
        CountDownLatch started = new CountDownLatch(2);
        CountDownLatch interrupted = new CountDownLatch(2);
        AtomicInteger tailStarted = new AtomicInteger();
        TtsDownloadQueue<String> queue = new TtsDownloadQueue<>(2, 4);
        try {
            for (String id : new String[] {"one", "two"}) {
                check(queue.offer(id, () -> {
                    started.countDown();
                    try {
                        new CountDownLatch(1).await();
                        return "unreachable";
                    } catch (InterruptedException error) {
                        interrupted.countDown();
                        throw error;
                    }
                }), "active clip accepted");
            }
            await(started, "two concurrent downloads start");
            check(queue.offer("tail", () -> { tailStarted.incrementAndGet(); return "tail"; }), "tail accepted");
            TtsDownloadQueue.Clip<String> playing = queue.poll(5, TimeUnit.SECONDS);
            queue.close();
            await(interrupted, "stop interrupts both active downloads");
            check(tailStarted.get() == 0, "concurrency is bounded and stopped tail never starts");
            check(!queue.offer("stale", () -> "stale"), "stale session cannot enqueue");
            try {
                playing.await();
                throw new AssertionError("stop must cancel the clip already taken by playback");
            } catch (CancellationException expected) {
                // Cancellation releases a worker blocked waiting for audio.
            }
            try (TtsDownloadQueue<String> replacement = new TtsDownloadQueue<>(2, 4)) {
                check(replacement.offer("new", () -> "new audio"), "replacement session accepts audio");
                check(replacement.poll(5, TimeUnit.SECONDS).await().equals("new audio"), "no stale audio crosses sessions");
            }
        } finally {
            queue.close();
        }
    }

    private static void exhaustedClipDoesNotDiscardTheNextSentence() throws Exception {
        try (TtsDownloadQueue<String> queue = new TtsDownloadQueue<>(2, 4)) {
            queue.offer("broken", () -> { throw new IOException("retries exhausted"); });
            queue.offer("next", () -> "complete next sentence");
            TtsDownloadQueue.Clip<String> broken = queue.poll(5, TimeUnit.SECONDS);
            try {
                broken.await();
                throw new AssertionError("failed clip must not return partial audio");
            } catch (ExecutionException expected) {
                check(expected.getCause() instanceof IOException, "preserve failure cause");
            }
            queue.complete(broken);
            TtsDownloadQueue.Clip<String> next = queue.poll(5, TimeUnit.SECONDS);
            check(next.await().equals("complete next sentence"), "later complete sentence survives");
            queue.complete(next);
            check(queue.isIdle(), "failed sentence does not leak a slot");
        }
    }

    public static void main(String[] args) throws Exception {
        downloadsOverlapButPlaybackRemainsOrdered();
        lookAheadIncludesDownloadedAndPlayingClips();
        stopCancelsActiveAndQueuedDownloads();
        exhaustedClipDoesNotDiscardTheNextSentence();
        bodyStallDisconnectsAndRejectsPartialAudio();
    }

    private static void bodyStallDisconnectsAndRejectsPartialAudio() throws Exception {
        CountDownLatch disconnected = new CountDownLatch(1);
        InputStream link = new InputStream() {
            private boolean first = true;
            @Override public int read() throws IOException {
                if (first) { first = false; return 42; }
                try {
                    if (!disconnected.await(5, TimeUnit.SECONDS)) {
                        throw new AssertionError("body watchdog must interrupt a stalled socket");
                    }
                } catch (InterruptedException error) {
                    throw new IOException(error);
                }
                return -1;
            }
        };
        try (InputStream body = new TtsBodyInputStream(link, 100, disconnected::countDown)) {
            check(body.read() == 42, "first audio bytes arrive normally");
            try {
                body.read();
                throw new AssertionError("disconnect-induced EOF must not accept a partial clip");
            } catch (SocketTimeoutException expected) {
                check(disconnected.getCount() == 0, "body timeout disconnected the socket");
            }
        }
    }
}
