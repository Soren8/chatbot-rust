package com.chatbot.app;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
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
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Voice-mode TTS: one {@link AudioTrack} per session, queued URLs, USAGE_VOICE_COMMUNICATION.
 * Each URL is downloaded fully and parsed before PCM is written (matches desktop decodeAudioData).
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

    private static final class WavPcm {
        final int sampleRate;
        final byte[] pcm;

        WavPcm(int sampleRate, byte[] pcm) {
            this.sampleRate = sampleRate;
            this.pcm = pcm;
        }
    }

    private void playUrlToTrack(String urlStr) throws IOException {
        byte[] wavBytes = downloadUrl(urlStr);
        WavPcm wav = extractPcmFromWav(wavBytes);
        if (wav.pcm.length < 2) {
            throw new IOException("empty PCM payload");
        }
        AudioTrack track = ensureTrackPlaying(wav.sampleRate);
        writePcmBlocking(track, wav.pcm);
        Log.d(TAG, "played pcm bytes=" + wav.pcm.length + " rate=" + wav.sampleRate);
    }

    private byte[] downloadUrl(String urlStr) throws IOException {
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
            return readAllBytes(is);
        } finally {
            conn.disconnect();
        }
    }

    private byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64 * 1024);
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = is.read(buf)) != -1) {
            total += n;
            if (total > MAX_WAV_BYTES) {
                throw new IOException("WAV response too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private WavPcm extractPcmFromWav(byte[] data) throws IOException {
        if (data.length < 44) {
            throw new IOException("WAV too short");
        }
        if (data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F'
                || data[8] != 'W' || data[9] != 'A' || data[10] != 'V' || data[11] != 'E') {
            throw new IOException("not a WAV file");
        }

        int sampleRate = DEFAULT_SAMPLE_RATE;
        int pos = 12;
        while (pos + 8 <= data.length) {
            String chunkId = new String(data, pos, 4, StandardCharsets.US_ASCII);
            int chunkSize = ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int chunkDataStart = pos + 8;
            if (chunkDataStart > data.length) {
                break;
            }

            if ("fmt ".equals(chunkId)) {
                if (chunkSize >= 8 && chunkDataStart + 8 <= data.length) {
                    sampleRate = ByteBuffer.wrap(data, chunkDataStart + 4, 4)
                            .order(ByteOrder.LITTLE_ENDIAN).getInt();
                }
            } else if ("data".equals(chunkId)) {
                int pcmStart = chunkDataStart;
                int pcmLen;
                if (chunkSize <= 0 || chunkSize == Integer.MAX_VALUE) {
                    pcmLen = data.length - pcmStart;
                } else {
                    pcmLen = Math.min(chunkSize, data.length - pcmStart);
                }
                if (pcmLen < 2 || (pcmLen & 1) != 0) {
                    pcmLen &= ~1;
                }
                if (pcmLen < 2) {
                    throw new IOException("invalid PCM length");
                }
                if (sampleRate < 8000 || sampleRate > 48000) {
                    sampleRate = DEFAULT_SAMPLE_RATE;
                }
                return new WavPcm(sampleRate, Arrays.copyOfRange(data, pcmStart, pcmStart + pcmLen));
            }

            pos = chunkDataStart + chunkSize + (chunkSize & 1);
        }
        throw new IOException("WAV missing data chunk");
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
