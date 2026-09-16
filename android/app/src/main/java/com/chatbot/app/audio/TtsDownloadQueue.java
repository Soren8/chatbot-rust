package com.chatbot.app.audio;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Bounded parallel downloads consumed in sentence order, including failed clips. */
public final class TtsDownloadQueue<T> implements AutoCloseable {
    public static final class Clip<T> {
        public final String id;
        private final FutureTask<T> task;

        private Clip(String id, Callable<T> download) {
            this.id = id;
            this.task = new FutureTask<>(download);
        }

        public T await() throws InterruptedException, ExecutionException {
            return task.get();
        }
    }

    private final ExecutorService downloads;
    private final BlockingQueue<Clip<T>> ordered = new LinkedBlockingQueue<>();
    private final Set<Clip<T>> outstanding = new HashSet<>();
    private final int capacity;
    private boolean closed;

    public TtsDownloadQueue(int concurrency, int capacity) {
        if (concurrency < 1 || capacity < concurrency) {
            throw new IllegalArgumentException("invalid TTS queue limits");
        }
        this.capacity = capacity;
        downloads = Executors.newFixedThreadPool(concurrency, runnable ->
                new Thread(runnable, "NativeVoiceTts-download"));
    }

    public synchronized boolean offer(String id, Callable<T> download) {
        if (closed || outstanding.size() >= capacity) {
            return false;
        }
        Clip<T> clip = new Clip<>(id, download);
        outstanding.add(clip);
        ordered.add(clip);
        downloads.execute(clip.task);
        return true;
    }

    public Clip<T> poll(long timeout, TimeUnit unit) throws InterruptedException {
        return ordered.poll(timeout, unit);
    }

    /** Release capacity only after playback consumes the clip, not after download. */
    public synchronized void complete(Clip<T> clip) {
        outstanding.remove(clip);
    }

    public synchronized boolean isIdle() {
        return outstanding.isEmpty();
    }

    @Override
    public synchronized void close() {
        closed = true;
        for (Clip<T> clip : outstanding) {
            clip.task.cancel(false);
        }
        // Publish cancellation before interrupting workers, so a read interrupted
        // by stop cannot race back as a playable result or start a queued tail.
        downloads.shutdownNow();
        outstanding.clear();
        ordered.clear();
    }
}
