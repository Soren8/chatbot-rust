package com.chatbot.app;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.Build;
import android.util.Log;
import android.webkit.CookieManager;

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
 * Voice-mode TTS: one {@link AudioTrack} per session, queued URLs, USAGE_MEDIA.
 * CallStyle microphone FGS swallows USAGE_VOICE_COMMUNICATION playback (HTML Audio
 * still works because it is USAGE_MEDIA). Capture stays VOICE_COMMUNICATION.
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
    /** Jitter buffer before the first sample. Reliability over first-byte latency. */
    private static final int PREROLL_MS = 400;
    /** Backoff before each clip GET retry: a blipping link fails back-to-back attempts. */
    private static final int CLIP_RETRY_BACKOFF_MS = 700;

    private static final class AudioClip {
        final int sampleRate;
        final byte[] pcm;
        final boolean isEndOfQueue;

        AudioClip(int sampleRate, byte[] pcm) {
            this.sampleRate = sampleRate;
            this.pcm = pcm;
            this.isEndOfQueue = false;
        }

        AudioClip(boolean isEndOfQueue) {
            this.sampleRate = DEFAULT_SAMPLE_RATE;
            this.pcm = new byte[0];
            this.isEndOfQueue = isEndOfQueue;
        }
    }

    private final BlockingQueue<String> urlQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<AudioClip> audioQueue = new LinkedBlockingQueue<>();
    private final AtomicBoolean sessionActive = new AtomicBoolean(false);
    private final AtomicBoolean endOfQueueMarked = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final AtomicBoolean playbackStartedNotified = new AtomicBoolean(false);
    private final AtomicLong bytesWritten = new AtomicLong(0);
    /** Invalidates a worker that outlives a stop/restart or a WebView reload. */
    private final AtomicLong playbackGeneration = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile Thread downloaderThread;
    private volatile AudioTrack audioTrack;
    private volatile HttpURLConnection activeConnection;
    private final Object connectionLock = new Object();
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
        audioQueue.clear();
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        startWorker(playbackGeneration.incrementAndGet());
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
        audioQueue.clear();
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        urlQueue.offer(url.trim());
        endOfQueueMarked.set(true);
        startWorker(playbackGeneration.incrementAndGet());
        call.resolve();
    }

    @PluginMethod
    public void stop(PluginCall call) {
        stopPlaybackInternal(true);
        call.resolve();
    }

    private void startWorker(long generation) {
        workerThread = new Thread(() -> workerLoop(generation), "NativeVoiceTts-worker");
        downloaderThread = new Thread(() -> downloaderLoop(generation), "NativeVoiceTts-downloader");
        workerThread.start();
        downloaderThread.start();
    }

    private boolean isGenerationActive(long generation) {
        return generation == playbackGeneration.get()
                && sessionActive.get()
                && !stopRequested.get();
    }

    private void workerLoop(long generation) {
        while (isGenerationActive(generation)) {
            try {
                AudioClip clip = audioQueue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                if (clip != null) {
                    if (clip.isEndOfQueue) {
                        drainPlaybackBuffer();
                        if (!isGenerationActive(generation)) {
                            return;
                        }
                        notifySessionEnded();
                        stopPlaybackInternal(false);
                        return;
                    }
                    writePcmToTrack(clip.sampleRate, clip.pcm, generation);
                    continue;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                Log.e(TAG, "playback loop error; continuing", e);
                releaseAudioTrack(generation);
            }
        }
    }

    private void downloaderLoop(long generation) {
        while (isGenerationActive(generation)) {
            try {
                String url = urlQueue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                if (url != null) {
                    try {
                        playUrlToTrack(url, generation);
                    } catch (Exception e) {
                        Log.e(TAG, "clip failed; continuing queue", e);
                    }
                    continue;
                }
                if (isGenerationActive(generation)
                        && endOfQueueMarked.get() && urlQueue.isEmpty()) {
                    audioQueue.offer(new AudioClip(true));
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                Log.e(TAG, "downloader loop error; continuing", e);
            }
        }
    }

    private void playUrlToTrack(String urlStr, long generation) throws IOException {
        IOException last = null;
        for (int attempt = 0; isGenerationActive(generation); attempt++) {
            if (!isGenerationActive(generation)) {
                return;
            }
            if (attempt > 0) {
                // Wait out a brief connectivity blip (cell handoff, tunnel
                // reconnect) instead of burning all attempts back-to-back.
                try {
                    Thread.sleep(Math.min((long) CLIP_RETRY_BACKOFF_MS * attempt, 3000L));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw last != null ? last : new IOException("playback interrupted");
                }
                if (!isGenerationActive(generation)) {
                    return;
                }
            }
            try {
                playUrlToTrackOnce(urlStr, generation);
                return;
            } catch (IOException e) {
                last = e;
                Log.e(TAG, "playUrlToTrack attempt " + attempt + " failed", e);
            }
        }
        if (last != null) {
            throw last;
        }
    }

    private void playUrlToTrackOnce(String urlStr, long generation) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        synchronized (connectionLock) {
            if (!isGenerationActive(generation)) {
                conn.disconnect();
                return;
            }
            activeConnection = conn;
        }
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(120000);
        conn.setRequestMethod("GET");
        try {
            if (!isGenerationActive(generation)) {
                return;
            }
            String cookie = CookieManager.getInstance().getCookie(urlStr);
            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }
            int code = conn.getResponseCode();
            Log.d(TAG, "GET " + urlStr + " code=" + code);
            if (code == 404 || code == 401 || code == 403) {
                Log.e(TAG, "GET " + urlStr + " non-retryable code=" + code);
                return;
            }
            if (code < 200 || code >= 300) {
                throw new IOException("HTTP " + code);
            }
            try (InputStream is = conn.getInputStream()) {
                AudioClip clip = streamWavToTrack(is, generation);
                if (clip != null && isGenerationActive(generation)) {
                    audioQueue.put(clip);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while queueing audio clip", e);
            }
        } finally {
            synchronized (connectionLock) {
                if (activeConnection == conn) {
                    activeConnection = null;
                }
            }
            conn.disconnect();
        }
    }

    private AudioClip streamWavToTrack(InputStream is, long generation) throws IOException {
        WavStreamDecoder decoder = new WavStreamDecoder();
        ByteArrayOutputStream preroll = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        try {
            while ((n = is.read(buf)) != -1) {
                if (!isGenerationActive(generation)) {
                    return null;
                }
                total += n;
                if (total > MAX_WAV_BYTES) {
                    throw new IOException("WAV response too large");
                }
                decoder.feed(buf, n);
                byte[] pcm = decoder.takePcm();
                if (pcm.length > 0) {
                    preroll.write(pcm);
                }
            }
        } catch (IOException e) {
            // Do not report a truncated clip as successful. The caller retries
            // the complete URL, ensuring no partial sentence is queued.
            throw e;
        }
        decoder.finish();
        byte[] tail = decoder.takePcm();
        if (tail.length > 0) {
            preroll.write(tail);
        }
        if (decoder.hasIncompleteData()) {
            throw new IOException("WAV stream ended before the data chunk was complete");
        }
        if (!decoder.sawDataChunk() && preroll.size() < 2) {
            throw new IOException("WAV missing data chunk");
        }
        byte[] fullPcm = preroll.toByteArray();
        Log.d(TAG, "queued pcm bytes=" + fullPcm.length + " rate=" + decoder.sampleRate());
        return new AudioClip(decoder.sampleRate(), fullPcm);
    }

    private void writePcmToTrack(int sampleRate, byte[] pcm, long generation) throws IOException {
        if (pcm == null || pcm.length < 2) {
            return;
        }
        if (!isGenerationActive(generation)) {
            return;
        }
        AudioTrack track = ensureTrackPlaying(sampleRate);
        writePcmBlocking(track, pcm, generation);
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

        boolean hasIncompleteData() {
            return dataRemaining > 0;
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

    private void writePcmBlocking(AudioTrack track, byte[] pcm, long generation) throws IOException {
        int offset = 0;
        int remaining = pcm.length & ~1;
        while (remaining > 0) {
            if (!isGenerationActive(generation) || audioTrack != track) {
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

    private void requestAudioFocus() {
        Context ctx = getContext();
        if (ctx == null) {
            return;
        }
        AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
        if (am == null) {
            return;
        }
        int max = am.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        if (max > 0) {
            am.setStreamVolume(AudioManager.STREAM_MUSIC, max, 0);
        }
        AudioFocusRequest req = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build())
                .build();
        am.requestAudioFocus(req);
    }

    private AudioTrack ensureTrackPlaying(int sampleRate) {
        requestAudioFocus();
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
            bytesWritten.set(0);
        }
        trackSampleRate = sampleRate;
        AudioAttributes attrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_MEDIA)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                .setLegacyStreamType(AudioManager.STREAM_MUSIC)
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
        bytesWritten.set(0);
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
        long lastPlayedBytes = -1;
        int stalledTicks = 0;
        while (System.currentTimeMillis() < deadline) {
            if (stopRequested.get()) {
                return;
            }
            int head = track.getPlaybackHeadPosition();
            long playedBytes = (long) head * 2;
            if (playedBytes >= written) {
                break;
            }
            if (playedBytes == lastPlayedBytes) {
                stalledTicks++;
                if (stalledTicks >= 15 && playedBytes >= written - 512) {
                    break;
                }
            } else {
                lastPlayedBytes = playedBytes;
                stalledTicks = 0;
            }
            Thread.sleep(20);
        }
    }

    private void stopPlaybackInternal(boolean notifyStopped) {
        // Capture before teardown: an idle stop must not emit 'ended'. The
        // event dispatch is async, so a stale 'ended' from this stop can land
        // on the listener of a session begun right after it (cold app start
        // after a relaunch) and kill that session at birth.
        boolean wasActive = sessionActive.getAndSet(false);
        playbackGeneration.incrementAndGet();
        stopRequested.set(true);
        endOfQueueMarked.set(false);
        urlQueue.clear();
        audioQueue.clear();

        HttpURLConnection connection;
        synchronized (connectionLock) {
            connection = activeConnection;
        }
        if (connection != null) {
            connection.disconnect();
        }

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
        if (t != null && t != Thread.currentThread()) {
            try {
                t.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            workerThread = null;
        }

        Thread dt = downloaderThread;
        if (dt != null && dt != Thread.currentThread()) {
            try {
                dt.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            downloaderThread = null;
        }

        playbackStartedNotified.set(false);
        bytesWritten.set(0);

        if (notifyStopped && wasActive) {
            notifySessionEnded();
        }
    }

    private void releaseAudioTrack(long generation) {
        if (generation != playbackGeneration.get()) {
            return;
        }
        AudioTrack track = audioTrack;
        audioTrack = null;
        bytesWritten.set(0);
        if (track == null) {
            return;
        }
        try {
            track.stop();
        } catch (Exception ignored) {
        }
        try {
            track.release();
        } catch (Exception ignored) {
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
