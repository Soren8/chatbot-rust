package com.chatbot.app;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioDeviceInfo;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.Build;
import android.util.Log;
import android.webkit.CookieManager;

import com.chatbot.app.audio.OggOpusStreamDecoder;
import com.chatbot.app.audio.TtsAudioPolicy;
import com.chatbot.app.audio.TtsDownloadQueue;
import com.chatbot.app.audio.TtsBodyInputStream;
import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.util.ClientLogReporter;
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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Voice-mode TTS: one {@link AudioTrack} per session, queued URLs.
 * Handheld voice mode plays USAGE_VOICE_COMMUNICATION matching capture,
 * focus and route; standalone TTS keeps USAGE_MEDIA. Capture stays
 * VOICE_COMMUNICATION. Routing is held for the whole voice-mode session by
 * {@code NativeMic.enterVoiceRoute}; this plugin does not change
 * {@link android.media.AudioManager} mode or the communication device.
 * Two downloads overlap synthesis and transfer; complete clips play in sentence order.
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
    /** Bound clip GET attempts (initial + retries) so one bad sentence skips instead of head-blocking the queue. Parity with JS MAX_TTS_SENTENCE_RETRIES. */
    private static final int MAX_CLIP_ATTEMPTS = 4;
    private static final int MAX_QUEUED_CLIPS = 4;
    private static final int DOWNLOAD_CONCURRENCY = 2;
    private static final int CLIP_BODY_STALL_MS = 15000;

    private static final class AudioClip {
        final int sampleRate;
        final byte[] pcm;

        AudioClip(int sampleRate, byte[] pcm) {
            this.sampleRate = sampleRate;
            this.pcm = pcm;
        }
    }

    private volatile TtsDownloadQueue<AudioClip> audioQueue;
    private final AtomicBoolean sessionActive = new AtomicBoolean(false);
    private final AtomicBoolean endOfQueueMarked = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final AtomicBoolean playbackStartedNotified = new AtomicBoolean(false);
    private final AtomicLong bytesWritten = new AtomicLong(0);
    /** Invalidates a worker that outlives a stop/restart or a WebView reload. */
    private final AtomicLong playbackGeneration = new AtomicLong(0);

    private volatile Thread workerThread;
    private volatile AudioTrack audioTrack;
    private final Set<HttpURLConnection> activeConnections = new HashSet<>();
    private final Object connectionLock = new Object();
    private volatile int trackSampleRate = DEFAULT_SAMPLE_RATE;
    /** Usage the live AudioTrack was built with; recreated on voice enter/exit. */
    private volatile int trackUsage = AudioAttributes.USAGE_MEDIA;
    /** Usage the held focus request was built with; -1 when none is held. */
    private volatile int focusUsage = -1;
    private static volatile NativeVoiceTtsPlugin instance;
    private AudioFocusRequest currentFocusRequest;

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

    public static boolean isSessionActive() {
        NativeVoiceTtsPlugin plugin = instance;
        return plugin != null && plugin.sessionActive.get();
    }

    @PluginMethod
    public void beginSession(PluginCall call) {
        stopPlaybackInternal(false);
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        long gen = playbackGeneration.incrementAndGet();
        startWorker(gen);
        JSObject ret = new JSObject();
        ret.put("generation", gen);
        ret.put("maxQueuedClips", MAX_QUEUED_CLIPS);
        call.resolve(ret);
    }

    @PluginMethod
    public void enqueue(PluginCall call) {
        String url = call.getString("url");
        if (url == null || url.trim().isEmpty()) {
            call.reject("url required");
            return;
        }
        TtsDownloadQueue<AudioClip> queue = audioQueue;
        long generation = playbackGeneration.get();
        if (!isGenerationActive(generation) || queue == null) {
            call.reject("no active session; call beginSession first");
            return;
        }
        if (!queue.offer(url.trim(), () -> playUrlToTrack(url.trim(), generation))) {
            call.reject("TTS queue full or stopped");
            return;
        }
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
        endOfQueueMarked.set(false);
        stopRequested.set(false);
        playbackStartedNotified.set(false);
        bytesWritten.set(0);
        sessionActive.set(true);
        long gen = playbackGeneration.incrementAndGet();
        startWorker(gen);
        audioQueue.offer(url.trim(), () -> playUrlToTrack(url.trim(), gen));
        endOfQueueMarked.set(true);
        JSObject ret = new JSObject();
        ret.put("generation", gen);
        call.resolve(ret);
    }

    @PluginMethod
    public void stop(PluginCall call) {
        stopPlaybackInternal(true);
        call.resolve();
    }

    private void startWorker(long generation) {
        TtsDownloadQueue<AudioClip> queue = new TtsDownloadQueue<>(DOWNLOAD_CONCURRENCY, MAX_QUEUED_CLIPS);
        audioQueue = queue;
        workerThread = new Thread(() -> workerLoop(generation, queue), "NativeVoiceTts-worker");
        workerThread.start();
    }

    private boolean isGenerationActive(long generation) {
        return generation == playbackGeneration.get()
                && sessionActive.get()
                && !stopRequested.get();
    }

    private void workerLoop(long generation, TtsDownloadQueue<AudioClip> queue) {
        while (isGenerationActive(generation)) {
            try {
                TtsDownloadQueue.Clip<AudioClip> pending = queue.poll(QUEUE_POLL_MS, TimeUnit.MILLISECONDS);
                if (pending != null) {
                    try {
                        AudioClip clip = pending.await();
                        if (clip != null && isGenerationActive(generation)) {
                            writePcmToTrack(clip.sampleRate, clip.pcm, generation);
                        }
                    } catch (ExecutionException e) {
                        Log.e(TAG, "clip failed; continuing queue", e.getCause());
                    } finally {
                        queue.complete(pending);
                        if (isGenerationActive(generation)) {
                            JSObject event = new JSObject();
                            event.put("type", "clipConsumed");
                            event.put("generation", generation);
                            event.put("url", pending.id);
                            notifyListeners("playbackState", event);
                        }
                    }
                    continue;
                }
                if (endOfQueueMarked.get() && queue.isIdle()) {
                    drainPlaybackBuffer();
                    if (isGenerationActive(generation)) stopPlaybackInternal(true);
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                Log.e(TAG, "playback loop error; continuing", e);
                ClientLogReporter.report("VOICE-ERROR", "voice: tts playback loop error, continuing");
                releaseAudioTrack(generation);
            }
        }
    }

    private AudioClip playUrlToTrack(String urlStr, long generation) throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < MAX_CLIP_ATTEMPTS && isGenerationActive(generation); attempt++) {
            if (!isGenerationActive(generation)) {
                return null;
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
                    return null;
                }
            }
            try {
                return playUrlToTrackOnce(urlStr, generation);
            } catch (IOException e) {
                last = e;
                Log.e(TAG, "playUrlToTrack attempt " + attempt + " failed", e);
            }
        }
        if (last != null) {
            ClientLogReporter.report("VOICE-ERROR", "voice: tts clip failed after retries");
            throw last;
        }
        return null;
    }

    private AudioClip playUrlToTrackOnce(String urlStr, long generation) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        synchronized (connectionLock) {
            if (!isGenerationActive(generation)) {
                conn.disconnect();
                return null;
            }
            activeConnections.add(conn);
        }
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(120000);
        conn.setRequestMethod("GET");
        try {
            if (!isGenerationActive(generation)) {
                return null;
            }
            String cookie = CookieManager.getInstance().getCookie(urlStr);
            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }
            int code = conn.getResponseCode();
            Log.d(TAG, "GET " + urlStr + " code=" + code);
            if (code == 404 || code == 401 || code == 403) {
                Log.e(TAG, "GET " + urlStr + " non-retryable code=" + code);
                ClientLogReporter.report("VOICE-ERROR", "voice: tts clip non-retryable code=" + code);
                return null;
            }
            if (code < 200 || code >= 300) {
                throw new IOException("HTTP " + code);
            }
            // Headers wait for synthesis; once audio exists, recover a stalled link sooner.
            conn.setReadTimeout(CLIP_BODY_STALL_MS);
            try (InputStream is = new TtsBodyInputStream(conn.getInputStream(), CLIP_BODY_STALL_MS, conn::disconnect)) {
                String contentType = conn.getContentType();
                if (contentType != null && contentType.contains("opus")) {
                    return streamOpusToClip(is, generation);
                }
                return streamWavToTrack(is, generation);
            }
        } finally {
            synchronized (connectionLock) {
                activeConnections.remove(conn);
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

    private AudioClip streamOpusToClip(InputStream is, long generation) throws IOException {
        OggOpusStreamDecoder decoder = new OggOpusStreamDecoder();
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
                    throw new IOException("Opus response too large");
                }
                decoder.feed(buf, n);
                byte[] pcm = decoder.takePcm();
                if (pcm.length > 0) {
                    preroll.write(pcm);
                }
            }
        } catch (IOException e) {
            // Same contract as WAV: a truncated clip is never queued; the
            // caller retries the complete URL.
            throw e;
        }
        decoder.finish();
        byte[] tail = decoder.takePcm();
        if (tail.length > 0) {
            preroll.write(tail);
        }
        if (!decoder.sawOpusHead()) {
            throw new IOException("Opus stream missing identification header");
        }
        if (decoder.hasIncompleteData()) {
            throw new IOException("Opus stream ended before end-of-stream page");
        }
        byte[] fullPcm = preroll.toByteArray();
        Log.d(TAG, "queued opus pcm bytes=" + fullPcm.length + " rate=" + decoder.sampleRate());
        return new AudioClip(decoder.sampleRate(), fullPcm);
    }

    private void writePcmToTrack(int sampleRate, byte[] pcm, long generation) throws IOException {
        if (pcm == null || pcm.length < 2) {
            return;
        }
        if (!isGenerationActive(generation)) {
            return;
        }
        AudioTrack track = ensureTrackPlaying(sampleRate, generation);
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

    private boolean isVoiceRouteActive() {
        try {
            return NativeMicPlugin.isVoiceRouteActive();
        } catch (Exception ignored) {
            return false;
        }
    }

    private void requestAudioFocus(boolean inCommunication) {
        Context ctx = getContext();
        if (ctx == null) {
            return;
        }
        AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
        if (am == null) {
            return;
        }
        // Same attributes for player and focus. Never write a stream volume:
        // the user's level must survive track creation.
        int desiredUsage = TtsAudioPolicy.playbackUsage(inCommunication);
        if (!TtsAudioPolicy.shouldRefreshFocus(currentFocusRequest != null, focusUsage, desiredUsage)) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && currentFocusRequest != null) {
            try {
                am.abandonAudioFocusRequest(currentFocusRequest);
            } catch (Exception ignored) {
            }
            currentFocusRequest = null;
        }
        AudioFocusRequest req = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder()
                        .setUsage(desiredUsage)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build())
                .build();
        currentFocusRequest = req;
        focusUsage = desiredUsage;
        am.requestAudioFocus(req);
    }

    private boolean hasHeadsetOrBluetoothConnected(AudioManager am) {
        if (am == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }
        if (NativeMicPlugin.hasBluetoothAudioPresent()) {
            return true;
        }
        try {
            for (AudioDeviceInfo device : am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
                int type = device.getType();
                if (VoiceAudioRoute.isBluetoothOutputType(type)
                        || type == AudioDeviceInfo.TYPE_WIRED_HEADSET
                        || type == AudioDeviceInfo.TYPE_WIRED_HEADPHONES
                        || type == AudioDeviceInfo.TYPE_USB_HEADSET) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private AudioDeviceInfo findBuiltInSpeaker() {
        Context ctx = getContext();
        if (ctx == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return null;
        }
        AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
        if (am == null) {
            return null;
        }
        for (AudioDeviceInfo device : am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
            if (device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
                return device;
            }
        }
        return null;
    }

    private AudioTrack ensureTrackPlaying(int sampleRate, long generation) {
        boolean inCommunication = isVoiceRouteActive();
        int desiredUsage = TtsAudioPolicy.playbackUsage(inCommunication);
        AudioTrack track = audioTrack;
        if (!TtsAudioPolicy.shouldRecreateTrack(track != null,
                trackUsage, trackSampleRate, desiredUsage, sampleRate)) {
            if (track.getPlayState() != AudioTrack.PLAYSTATE_PLAYING) {
                track.play();
            }
            return track;
        }
        // New track or usage/rate change: (re)acquire matching focus once
        // here, not per sentence, so steady playback avoids per-sentence
        // binder churn and mixer ducking. The reuse path above keeps held focus.
        requestAudioFocus(inCommunication);
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
        trackUsage = desiredUsage;
        AudioAttributes.Builder attrsBuilder = new AudioAttributes.Builder()
                .setUsage(desiredUsage)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH);
        if (TtsAudioPolicy.useLegacyMusicStream(inCommunication)) {
            attrsBuilder.setLegacyStreamType(AudioManager.STREAM_MUSIC);
        }
        AudioAttributes attrs = attrsBuilder.build();
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
                .setBufferSizeInBytes(Math.max(minBuf * 4, 1024 * 64))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Context ctx = getContext();
            AudioManager am = ctx != null ? (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE) : null;
            if (am != null && TtsAudioPolicy.preferBuiltInSpeaker(
                    inCommunication, hasHeadsetOrBluetoothConnected(am))) {
                AudioDeviceInfo speaker = findBuiltInSpeaker();
                if (speaker != null) {
                    try {
                        track.setPreferredDevice(speaker);
                    } catch (Exception e) {
                        Log.w(TAG, "setPreferredDevice failed", e);
                    }
                }
            }
        }
        track.setVolume(1.0f);
        audioTrack = track;
        bytesWritten.set(0);
        track.play();
        if (playbackStartedNotified.compareAndSet(false, true)) {
            notifyStarted(generation);
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
        // Do not increment playbackGeneration until after the ended event:
        // the no-arg notify carries get, which must still be the ending
        // session's generation so the JS listener accepts it. Incrementing
        // first would send the teardown generation and the ended event would
        // be discarded, wedging TTS in playing state.
        stopRequested.set(true);
        endOfQueueMarked.set(false);
        TtsDownloadQueue<AudioClip> queue = audioQueue;
        audioQueue = null;
        if (queue != null) queue.close();

        HttpURLConnection[] connections;
        synchronized (connectionLock) {
            connections = activeConnections.toArray(new HttpURLConnection[0]);
            activeConnections.clear();
        }
        for (HttpURLConnection connection : connections) {
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
            t.interrupt();
            try {
                t.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            workerThread = null;
        }

        playbackStartedNotified.set(false);
        bytesWritten.set(0);

        if (notifyStopped) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && currentFocusRequest != null) {
                Context ctx = getContext();
                if (ctx != null) {
                    AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
                    if (am != null) {
                        am.abandonAudioFocusRequest(currentFocusRequest);
                    }
                }
                currentFocusRequest = null;
                focusUsage = -1;
            }
            NativeMicPlugin.reclaimAudioFocusIfPresent();
        }

        if (notifyStopped && wasActive) {
            notifySessionEnded();
        }
        playbackGeneration.incrementAndGet();
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

    private void notifyStarted(long generation) {
        JSObject ret = new JSObject();
        ret.put("type", "started");
        ret.put("generation", generation);
        notifyListeners("playbackState", ret);
    }

    private void notifySessionEnded() {
        notifySessionEnded(playbackGeneration.get());
    }

    private void notifySessionEnded(long generation) {
        JSObject ret = new JSObject();
        ret.put("type", "ended");
        ret.put("generation", generation);
        notifyListeners("playbackState", ret);
    }

    private void notifyError(String message, long generation) {
        JSObject ret = new JSObject();
        ret.put("type", "error");
        ret.put("message", message);
        ret.put("generation", generation);
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
