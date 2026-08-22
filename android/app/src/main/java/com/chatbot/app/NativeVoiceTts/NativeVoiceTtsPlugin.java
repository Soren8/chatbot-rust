package com.chatbot.app;

import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioTrack;
import android.os.Build;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.ByteArrayOutputStream;
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
 * Communication usage matches speakerphone capture so hardware AEC has a playback reference.
 * Routing is held for the whole voice-mode session by {@code NativeMic.enterVoiceRoute};
 * this plugin does not change {@link android.media.AudioManager} mode or the communication device.
 * Each {@code /tts_stream} URL is parsed incrementally and PCM is written as it arrives.
 */
@CapacitorPlugin(name = "NativeVoiceTts")
public class NativeVoiceTtsPlugin extends Plugin {
    private static final String TAG = "NativeVoiceTts";
    private static final int DEFAULT_SAMPLE_RATE = 24000;
    private static final int QUEUE_POLL_MS = 100;
    private static final int MAX_WAV_BYTES = 8 * 1024 * 1024;

    private final BlockingQueue<String> urlQueue = new LinkedBlockingQueue<>();
    private final AtomicBoolean sessionActive = new AtomicBoolean(false);
    private final AtomicBoolean endOfQueueMarked = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final AtomicBoolean playbackStartedNotified = new AtomicBoolean(false);
    private final AtomicLong bytesWritten = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile AudioTrack audioTrack;
    private volatile int trackSampleRate = DEFAULT_SAMPLE_RATE;
    private static volatile NativeVoiceTtsPlugin instance;

    @Override
    public void load() {
        super.load();
        instance = this;
    }

    public static void stopIfPresent() {
        NativeVoiceTtsPlugin plugin = instance;
        if (plugin != null) {
            plugin.stopPlaybackInternal(true);
        }
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

    private void startWorker() {
        workerThread = new Thread(this::workerLoop, "NativeVoiceTts-worker");
        workerThread.start();
    }

    private void workerLoop() {
        while (sessionActive.get() && !stopRequested.get()) {
            try {
                String url = urlQueue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                if (url != null) {
                    playUrlToTrack(url);
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
                Log.e(TAG, "playback error", e);
                notifyError(e.getMessage() != null ? e.getMessage() : "playback failed");
                stopPlaybackInternal(false);
                return;
            }
        }
    }

    private void playUrlToTrack(String urlStr) throws IOException {
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
            streamWavToTrack(is);
        } finally {
            conn.disconnect();
        }
    }

    private void streamWavToTrack(InputStream is) throws IOException {
        WavStreamDecoder decoder = new WavStreamDecoder();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = is.read(buf)) != -1) {
            if (stopRequested.get()) {
                return;
            }
            total += n;
            if (total > MAX_WAV_BYTES) {
                throw new IOException("WAV response too large");
            }
            decoder.feed(buf, n);
            flushDecodedPcm(decoder);
        }
        decoder.finish();
        flushDecodedPcm(decoder);
        if (!decoder.sawDataChunk()) {
            throw new IOException("WAV missing data chunk");
        }
        Log.d(TAG, "played pcm bytes=" + decoder.pcmBytes() + " rate=" + decoder.sampleRate());
    }

    private void flushDecodedPcm(WavStreamDecoder decoder) throws IOException {
        byte[] pcm = decoder.takePcm();
        if (pcm.length < 2) {
            return;
        }
        AudioTrack track = ensureTrackPlaying(decoder.sampleRate());
        writePcmBlocking(track, pcm);
    }

    private static final class WavStreamDecoder {
        private final ByteArrayOutputStream header = new ByteArrayOutputStream(64);
        private final ByteArrayOutputStream pcm = new ByteArrayOutputStream(8192);
        private int sampleRate = DEFAULT_SAMPLE_RATE;
        private boolean headerDone;
        private boolean sawData;
        private int dataRemaining = -1;
        private byte odd;
        private boolean hasOdd;
        private int pcmBytes;

        int sampleRate() {
            return sampleRate;
        }

        boolean sawDataChunk() {
            return sawData;
        }

        int pcmBytes() {
            return pcmBytes;
        }

        void feed(byte[] src, int len) throws IOException {
            if (!headerDone) {
                header.write(src, 0, len);
                byte[] acc = header.toByteArray();
                int dataAt = findDataChunk(acc);
                if (dataAt < 0) {
                    return;
                }
                headerDone = true;
                if (dataAt < acc.length) {
                    acceptPcm(acc, dataAt, acc.length - dataAt);
                }
                return;
            }
            acceptPcm(src, 0, len);
        }

        void finish() {
            // drop a trailing odd byte; 16-bit PCM must be even
        }

        byte[] takePcm() {
            byte[] out = pcm.toByteArray();
            pcm.reset();
            return out;
        }

        private int findDataChunk(byte[] data) throws IOException {
            if (data.length < 12) {
                return -1;
            }
            if (data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F'
                    || data[8] != 'W' || data[9] != 'A' || data[10] != 'V' || data[11] != 'E') {
                throw new IOException("not a WAV file");
            }
            int pos = 12;
            while (pos + 8 <= data.length) {
                String chunkId = new String(data, pos, 4, StandardCharsets.US_ASCII);
                int chunkSize = ByteBuffer.wrap(data, pos + 4, 4)
                        .order(ByteOrder.LITTLE_ENDIAN).getInt();
                int chunkDataStart = pos + 8;
                if ("fmt ".equals(chunkId)) {
                    if (chunkSize >= 8 && chunkDataStart + 8 <= data.length) {
                        int rate = ByteBuffer.wrap(data, chunkDataStart + 4, 4)
                                .order(ByteOrder.LITTLE_ENDIAN).getInt();
                        if (rate >= 8000 && rate <= 48000) {
                            sampleRate = rate;
                        }
                    }
                } else if ("data".equals(chunkId)) {
                    sawData = true;
                    if (chunkSize > 0 && chunkSize != Integer.MAX_VALUE) {
                        dataRemaining = chunkSize;
                    }
                    return chunkDataStart;
                }
                if (chunkSize < 0) {
                    throw new IOException("invalid WAV chunk");
                }
                int next = chunkDataStart + chunkSize + (chunkSize & 1);
                if (next > data.length) {
                    return -1;
                }
                pos = next;
            }
            return -1;
        }

        private void acceptPcm(byte[] src, int off, int len) {
            if (len <= 0) {
                return;
            }
            int remain = len;
            int pos = off;
            if (dataRemaining >= 0) {
                remain = Math.min(remain, dataRemaining);
                dataRemaining -= remain;
            }
            if (hasOdd) {
                if (remain <= 0) {
                    return;
                }
                pcm.write(odd);
                pcm.write(src[pos]);
                pcmBytes += 2;
                pos++;
                remain--;
                hasOdd = false;
            }
            int even = remain & ~1;
            if (even > 0) {
                pcm.write(src, pos, even);
                pcmBytes += even;
                pos += even;
                remain -= even;
            }
            if (remain == 1) {
                odd = src[pos];
                hasOdd = true;
            }
        }
    }

    private void writePcmBlocking(AudioTrack track, byte[] pcm) throws IOException {
        int offset = 0;
        int remaining = pcm.length & ~1;
        while (remaining > 0) {
            if (stopRequested.get()) {
                return;
            }
            int written;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                written = track.write(pcm, offset, remaining, AudioTrack.WRITE_BLOCKING);
            } else {
                written = track.write(pcm, offset, remaining);
            }
            if (written <= 0) {
                throw new IOException("AudioTrack write failed: " + written);
            }
            offset += written;
            remaining -= written;
            bytesWritten.addAndGet(written);
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
        if (instance == this) {
            instance = null;
        }
        stopPlaybackInternal(false);
        super.handleOnDestroy();
    }
}
