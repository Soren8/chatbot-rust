package com.chatbot.app;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Voice-mode TTS: one {@link AudioTrack} per session, queued URLs, USAGE_VOICE_COMMUNICATION.
 */
@CapacitorPlugin(name = "NativeVoiceTts")
public class NativeVoiceTtsPlugin extends Plugin {
    private static final String TAG = "NativeVoiceTts";
    private static final int DEFAULT_SAMPLE_RATE = 24000;
    private static final int QUEUE_POLL_MS = 100;

    private final BlockingQueue<String> urlQueue = new LinkedBlockingQueue<>();
    private final AtomicBoolean sessionActive = new AtomicBoolean(false);
    private final AtomicBoolean endOfQueueMarked = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final AtomicBoolean playbackStartedNotified = new AtomicBoolean(false);
    private final AtomicLong bytesWritten = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile AudioTrack audioTrack;
    private volatile int trackSampleRate = DEFAULT_SAMPLE_RATE;

    private AudioManager audioManager;
    private AudioFocusRequest audioFocusRequest;
    private boolean hasAudioFocus;

    @Override
    public void load() {
        super.load();
        audioManager = (AudioManager) getContext().getSystemService(Context.AUDIO_SERVICE);
    }

    @PluginMethod
    public void beginSession(PluginCall call) {
        stopPlaybackInternal(false);
        urlQueue.clear();
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        requestAudioFocus();
        startWorker();
        call.resolve();
    }

    @PluginMethod
    public void enqueue(PluginCall call) {
        String url = call.getString("url");
        if (url == null || url.trim().isEmpty()) {
            call.reject("url required");
            return;
        }
        if (!sessionActive.get()) {
            call.reject("no active session; call beginSession first");
            return;
        }
        urlQueue.offer(url.trim());
        call.resolve();
    }

    @PluginMethod
    public void markEndOfQueue(PluginCall call) {
        endOfQueueMarked.set(true);
        call.resolve();
    }

    /** Legacy single-URL play — one-item session. */
    @PluginMethod
    public void play(PluginCall call) {
        String url = call.getString("url");
        if (url == null || url.trim().isEmpty()) {
            call.reject("url required");
            return;
        }
        stopPlaybackInternal(false);
        urlQueue.clear();
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        requestAudioFocus();
        urlQueue.offer(url.trim());
        endOfQueueMarked.set(true);
        startWorker();
        call.resolve();
    }

    @PluginMethod
    public void stop(PluginCall call) {
        stopPlaybackInternal(true);
        call.resolve();
    }

    private void requestAudioFocus() {
        if (audioManager == null || hasAudioFocus) {
            return;
        }
        audioFocusRequest = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build())
                .setOnAudioFocusChangeListener(change -> Log.d(TAG, "audio focus change: " + change))
                .build();
        int result = audioManager.requestAudioFocus(audioFocusRequest);
        hasAudioFocus = (result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
    }

    private void abandonAudioFocus() {
        if (audioManager != null && audioFocusRequest != null && hasAudioFocus) {
            audioManager.abandonAudioFocusRequest(audioFocusRequest);
            hasAudioFocus = false;
        }
    }

    private void startWorker() {
        workerThread = new Thread(this::workerLoop, "NativeVoiceTts-worker");
        workerThread.start();
    }

    private void workerLoop() {
        while (sessionActive.get() && !stopRequested.get()) {
            try {
                String url = urlQueue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                if (url != null) {
                    streamUrlToTrack(url);
                    continue;
                }
                if (endOfQueueMarked.get() && urlQueue.isEmpty()) {
                    drainPlaybackBuffer();
                    notifySessionEnded();
                    stopPlaybackInternal(false);
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                notifyError(e.getMessage() != null ? e.getMessage() : "playback failed");
                stopPlaybackInternal(false);
                return;
            }
        }
    }

    private static final int STREAMING_DATA_SIZE = 0x7FFFFFFF;

    private static final class WavDataInfo {
        final int sampleRate;
        final int dataBytes;

        WavDataInfo(int sampleRate, int dataBytes) {
            this.sampleRate = sampleRate;
            this.dataBytes = dataBytes;
        }
    }

    private void streamUrlToTrack(String urlStr) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(120000);
        conn.setRequestMethod("GET");
        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            conn.disconnect();
            throw new IOException("HTTP " + code);
        }

        try (InputStream is = conn.getInputStream()) {
            WavDataInfo wav = parseWavDataInfo(is);
            AudioTrack track = ensureTrackPlaying(wav.sampleRate);
            streamPcmData(is, track, wav.dataBytes);
        } finally {
            conn.disconnect();
        }
    }

    private WavDataInfo parseWavDataInfo(InputStream is) throws IOException {
        byte[] riff = new byte[12];
        if (readFully(is, riff, 0, 12) < 12
                || riff[0] != 'R' || riff[1] != 'I' || riff[2] != 'F' || riff[3] != 'F'
                || riff[8] != 'W' || riff[9] != 'A' || riff[10] != 'V' || riff[11] != 'E') {
            throw new IOException("not a WAV stream");
        }

        int sampleRate = DEFAULT_SAMPLE_RATE;
        while (true) {
            byte[] chunkHdr = new byte[8];
            if (readFully(is, chunkHdr, 0, 8) < 8) {
                throw new IOException("truncated WAV header");
            }
            String chunkId = new String(chunkHdr, 0, 4, StandardCharsets.US_ASCII);
            int chunkSize = ByteBuffer.wrap(chunkHdr, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0x7FFFFFFF;

            if ("fmt ".equals(chunkId)) {
                byte[] fmt = new byte[chunkSize];
                int read = readFully(is, fmt, 0, chunkSize);
                if (read >= 8) {
                    sampleRate = ByteBuffer.wrap(fmt, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                }
                if (read < chunkSize) {
                    skipFully(is, chunkSize - read);
                }
            } else if ("data".equals(chunkId)) {
                return new WavDataInfo(sampleRate, chunkSize);
            } else {
                skipFully(is, chunkSize);
            }
        }
    }

    private void streamPcmData(InputStream is, AudioTrack track, int dataBytes) throws IOException {
        byte[] buf = new byte[8192];
        long remaining = dataBytes == STREAMING_DATA_SIZE ? Long.MAX_VALUE : (dataBytes & 0xFFFFFFFFL);
        while (remaining > 0) {
            if (stopRequested.get()) {
                return;
            }
            int toRead = remaining == Long.MAX_VALUE
                    ? buf.length
                    : (int) Math.min(buf.length, remaining);
            int n = is.read(buf, 0, toRead);
            if (n < 0) {
                break;
            }
            int writeLen = n & ~1;
            if (writeLen > 0) {
                track.write(buf, 0, writeLen);
                bytesWritten.addAndGet(writeLen);
            }
            if (remaining != Long.MAX_VALUE) {
                remaining -= n;
            }
        }
    }

    private static void skipFully(InputStream is, int bytes) throws IOException {
        long remaining = bytes & 0xFFFFFFFFL;
        while (remaining > 0) {
            long skipped = is.skip(remaining);
            if (skipped <= 0) {
                if (is.read() < 0) {
                    return;
                }
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }

    private AudioTrack ensureTrackPlaying(int sampleRate) {
        AudioTrack track = audioTrack;
        if (track != null && trackSampleRate == sampleRate) {
            if (track.getPlayState() != AudioTrack.PLAYSTATE_PLAYING) {
                track.play();
            }
            return track;
        }
        if (track != null) {
            try {
                track.stop();
            } catch (Exception ignored) {
            }
            track.release();
            audioTrack = null;
        }
        trackSampleRate = sampleRate;
        AudioAttributes attrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                .build();
        AudioFormat format = new AudioFormat.Builder()
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .setSampleRate(sampleRate)
                .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                .build();
        int minBuf = AudioTrack.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT);
        track = new AudioTrack.Builder()
                .setAudioAttributes(attrs)
                .setAudioFormat(format)
                .setBufferSizeInBytes(Math.max(minBuf * 4, 1024 * 256))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build();
        track.setVolume(1.0f);
        audioTrack = track;
        track.play();
        if (playbackStartedNotified.compareAndSet(false, true)) {
            notifyStarted();
        }
        return track;
    }

    private void drainPlaybackBuffer() throws InterruptedException {
        AudioTrack track = audioTrack;
        if (track == null) {
            return;
        }
        long written = bytesWritten.get();
        if (written <= 0) {
            return;
        }
        long durationMs = (written / 2 * 1000L) / trackSampleRate;
        long deadline = System.currentTimeMillis() + Math.min(durationMs + 200, 30000);
        while (System.currentTimeMillis() < deadline) {
            if (stopRequested.get()) {
                return;
            }
            int head = track.getPlaybackHeadPosition();
            long playedBytes = (long) head * 2;
            if (playedBytes >= written - 4096) {
                break;
            }
            Thread.sleep(20);
        }
    }

    private static int readFully(InputStream is, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n = is.read(buf, off + total, len - total);
            if (n < 0) {
                return total;
            }
            total += n;
        }
        return total;
    }

    private void stopPlaybackInternal(boolean notifyStopped) {
        stopRequested.set(true);
        sessionActive.set(false);
        endOfQueueMarked.set(false);
        urlQueue.clear();

        AudioTrack track = audioTrack;
        if (track != null) {
            try {
                track.stop();
            } catch (Exception ignored) {
            }
            try {
                track.release();
            } catch (Exception ignored) {
            }
            audioTrack = null;
        }

        Thread t = workerThread;
        if (t != null) {
            try {
                t.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            workerThread = null;
        }

        abandonAudioFocus();
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        stopRequested.set(false);

        if (notifyStopped) {
            notifySessionEnded();
        }
    }

    private void notifyStarted() {
        JSObject ret = new JSObject();
        ret.put("type", "started");
        notifyListeners("playbackState", ret);
    }

    private void notifySessionEnded() {
        JSObject ret = new JSObject();
        ret.put("type", "ended");
        notifyListeners("playbackState", ret);
    }

    private void notifyError(String message) {
        JSObject ret = new JSObject();
        ret.put("type", "error");
        ret.put("message", message);
        notifyListeners("playbackState", ret);
    }

    @Override
    protected void handleOnDestroy() {
        stopPlaybackInternal(false);
        super.handleOnDestroy();
    }
}
