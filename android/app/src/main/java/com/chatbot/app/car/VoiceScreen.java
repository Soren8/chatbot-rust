package com.chatbot.app.car;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaRecorder;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.car.app.CarContext;
import androidx.car.app.Screen;
import androidx.car.app.model.Pane;
import androidx.car.app.model.PaneTemplate;
import androidx.car.app.model.Row;
import androidx.car.app.model.Template;
import androidx.lifecycle.DefaultLifecycleObserver;
import androidx.lifecycle.LifecycleOwner;

import com.chatbot.app.R;
import com.chatbot.app.audio.OggOpusStreamDecoder;
import com.chatbot.app.util.FileLogger;
import com.chatbot.app.util.ServerUrlResolver;
import com.chatbot.app.util.ServerUrlSettingStore;

import java.io.InputStreamReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

public class VoiceScreen extends Screen {
    private static final String TAG = "VoiceScreen";

    // Audio capture parameters
    private static final int SAMPLE_RATE = 16000;
    private static final int CHANNEL_IN_CONFIG = AudioFormat.CHANNEL_IN_MONO;
    private static final int AUDIO_ENCODING = AudioFormat.ENCODING_PCM_16BIT;
    private static final int FRAME_MS = 20; // 20ms frames -> 320 samples @ 16kHz
    private static final int FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS / 1000;

    // VAD parameters
    private static final double VAD_RMS_THRESHOLD = 800.0; // amplitude threshold (Int16 RMS)
    private static final int VAD_START_FRAMES = 3; // ~60ms above threshold to trigger start
    private static final int VAD_END_SILENCE_MS = 800; // 800ms below threshold to trigger end
    private static final int MAX_UTTERANCE_MS = 15000; // hard cap

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AudioManager audioManager;
    private final AtomicBoolean captureRunning = new AtomicBoolean(false);
    private final AtomicBoolean ttsPlaying = new AtomicBoolean(false);
    private final CarVoicePolicy.TurnSlot<byte[]> turns = new CarVoicePolicy.TurnSlot<>();

    private volatile DurableVoiceProtocol generation;
    private volatile String generationOrigin;
    private volatile AudioTrack activeTrack;
    private volatile AudioRecord audioRecord;
    private AudioFocusRequest audioFocusRequest;
    private boolean hasAudioFocus = false;
    private String statusText = "Initializing…";
    private String lastTranscription = "";

    public VoiceScreen(@NonNull CarContext carContext) {
        super(carContext);
        // Canonical native origin (flavor resource + persisted override): a
        // car context has no Capacitor Bridge and none is read.
        audioManager = (AudioManager) carContext.getSystemService(Context.AUDIO_SERVICE);
        Log.i(TAG, "VoiceScreen created with server: " + serverUrl());
        FileLogger.log(TAG, "VoiceScreen created, serverUrl=" + serverUrl());
        mainHandler.postDelayed(this::startCapture, 500);
        getLifecycle().addObserver(new DefaultLifecycleObserver() {
            @Override
            public void onDestroy(@NonNull LifecycleOwner owner) {
                FileLogger.log(TAG, "VoiceScreen destroyed");
                mainHandler.removeCallbacksAndMessages(null);
                stopCapture();
                executor.shutdown();
                captureExecutor.shutdown();
            }
        });
    }

    /**
     * Selected origin resolved at request time: a persisted override that
     * changed after the car session started must not keep this screen on an
     * obsolete server. Same authority chain as the WebView and reporter.
     */
    private String serverUrl() {
        CarContext carContext = getCarContext();
        try {
            return ServerUrlSettingStore.selected(carContext);
        } catch (Exception e) {
            String flavorUrl = null;
            try {
                flavorUrl = carContext.getString(R.string.server_url);
            } catch (Exception ignored) {}
            return ServerUrlResolver.resolveCanonical(flavorUrl);
        }
    }

    @NonNull
    @Override
    public Template onGetTemplate() {
        FileLogger.log(TAG, "onGetTemplate status=" + statusText);

        Pane.Builder paneBuilder = new Pane.Builder();
        paneBuilder.addRow(new Row.Builder()
                .setTitle("Chatbot Voice")
                .addText(statusText)
                .build());

        if (!lastTranscription.isEmpty()) {
            paneBuilder.addRow(new Row.Builder()
                    .setTitle("You said")
                    .addText(lastTranscription)
                    .build());
        }

        paneBuilder.addRow(new Row.Builder()
                .setTitle("Exit")
                .setOnClickListener(() -> {
                    Log.i(TAG, "Exit clicked");
                    FileLogger.log(TAG, "Exit clicked");
                    exitVoiceMode();
                })
                .build());

        return new PaneTemplate.Builder(paneBuilder.build())
                .setTitle("Chatbot")
                .build();
    }

    private void setStatus(String text) {
        statusText = text;
        mainHandler.post(this::invalidate);
    }

    private void startCapture() {
        if (captureRunning.get()) {
            FileLogger.log(TAG, "startCapture: already running, skip");
            return;
        }
        FileLogger.log(TAG, "=== startCapture ===");
        requestAudioFocus();

        int minBuffer = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_IN_CONFIG, AUDIO_ENCODING);
        if (minBuffer == AudioRecord.ERROR || minBuffer == AudioRecord.ERROR_BAD_VALUE) {
            FileLogger.log(TAG, "ERROR: invalid AudioRecord buffer size " + minBuffer);
            setStatus("Audio init failed");
            return;
        }
        int bufferBytes = Math.max(minBuffer * 2, FRAME_SAMPLES * 2 * 8);
        FileLogger.log(TAG, "AudioRecord minBuffer=" + minBuffer + " using=" + bufferBytes);

        try {
            audioRecord = new AudioRecord(
                    MediaRecorder.AudioSource.VOICE_RECOGNITION,
                    SAMPLE_RATE,
                    CHANNEL_IN_CONFIG,
                    AUDIO_ENCODING,
                    bufferBytes);
        } catch (SecurityException se) {
            FileLogger.log(TAG, "ERROR creating AudioRecord (permissions?)", se);
            setStatus("Mic permission missing");
            return;
        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR creating AudioRecord", e);
            setStatus("Audio init failed");
            return;
        }

        if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
            FileLogger.log(TAG, "ERROR: AudioRecord not initialized state=" + audioRecord.getState());
            try {
                audioRecord.release();
            } catch (Exception ignored) {}
            audioRecord = null;
            setStatus("Audio init failed");
            return;
        }

        try {
            audioRecord.startRecording();
        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR startRecording()", e);
            try {
                audioRecord.release();
            } catch (Exception ignored) {}
            audioRecord = null;
            setStatus("Audio recording failed");
            return;
        }
        FileLogger.log(TAG, "AudioRecord.startRecording() called, audioSource=" + audioRecord.getAudioSource());
        captureRunning.set(true);
        setStatus("Listening…");
        captureExecutor.execute(this::captureLoop);
    }

    private void stopCapture() {
        FileLogger.log(TAG, "=== stopCapture ===");
        captureRunning.set(false);
        if (audioRecord != null) {
            try {
                audioRecord.stop();
            } catch (Exception e) {
                FileLogger.log(TAG, "stopCapture stop()", e);
            }
            try {
                audioRecord.release();
            } catch (Exception e) {
                FileLogger.log(TAG, "stopCapture release()", e);
            }
            audioRecord = null;
        }
    }

    private void captureLoop() {
        FileLogger.log(TAG, "captureLoop starting");
        short[] frame = new short[FRAME_SAMPLES];
        ByteArrayOutputStream pcmBuffer = new ByteArrayOutputStream();
        int aboveCount = 0;
        int silenceMs = 0;
        boolean inSpeech = false;
        long speechStartMs = 0;
        long lastLogMs = 0;
        AudioRecord record = audioRecord;
        CarVoicePolicy.CaptureReads reads = new CarVoicePolicy.CaptureReads();

        while (captureRunning.get() && record != null) {
            int read = record.read(frame, 0, FRAME_SAMPLES);
            int action = reads.onRead(read);
            if (action == CarVoicePolicy.CaptureReads.STOP) {
                FileLogger.log(TAG, "audioRecord.read returned " + read + ", stopping capture");
                if (captureRunning.get()) {
                    setStatus("Audio recording failed");
                    mainHandler.post(this::stopCapture);
                }
                break;
            }
            if (action == CarVoicePolicy.CaptureReads.BACK_OFF) {
                if (reads.logIdle()) FileLogger.log(TAG, "audioRecord.read returned " + read);
                try { Thread.sleep(FRAME_MS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                continue;
            }
            // While TTS is playing, drain mic but don't classify (rely on AEC, but be safe)
            if (ttsPlaying.get()) {
                aboveCount = 0;
                silenceMs = 0;
                inSpeech = false;
                pcmBuffer.reset();
                continue;
            }

            double rms = computeRms(frame, read);
            long now = System.currentTimeMillis();
            if (now - lastLogMs > 2000) {
                FileLogger.log(TAG, "rms=" + (int) rms + " inSpeech=" + inSpeech + " above=" + aboveCount + " silenceMs=" + silenceMs);
                lastLogMs = now;
            }

            if (rms > VAD_RMS_THRESHOLD) {
                aboveCount++;
                silenceMs = 0;
                if (!inSpeech && aboveCount >= VAD_START_FRAMES) {
                    inSpeech = true;
                    speechStartMs = now;
                    pcmBuffer.reset();
                    FileLogger.log(TAG, "VAD: speech start (rms=" + (int) rms + ")");
                    setStatus("Listening… (heard you)");
                }
            } else {
                aboveCount = 0;
                if (inSpeech) {
                    silenceMs += FRAME_MS;
                }
            }

            if (inSpeech) {
                writeShortsLE(pcmBuffer, frame, read);
            }

            boolean utteranceTooLong = inSpeech && (now - speechStartMs) > MAX_UTTERANCE_MS;
            if (inSpeech && (silenceMs >= VAD_END_SILENCE_MS || utteranceTooLong)) {
                FileLogger.log(TAG, "VAD: speech end (silenceMs=" + silenceMs + " tooLong=" + utteranceTooLong + " bytes=" + pcmBuffer.size() + ")");
                inSpeech = false;
                silenceMs = 0;
                aboveCount = 0;
                byte[] pcm = pcmBuffer.toByteArray();
                pcmBuffer.reset();
                if (pcm.length > 4000) { // ignore very short blips (<125ms)
                    handleUtterance(pcm);
                } else {
                    FileLogger.log(TAG, "VAD: utterance too short, skipping");
                }
            }
        }
        FileLogger.log(TAG, "captureLoop exiting");
    }

    /**
     * One turn (STT → chat → TTS) runs against the origin captured when the
     * turn starts: a mid-turn selection change must not splice its requests
     * across two servers.
     */
    private void handleUtterance(byte[] pcm) {
        FileLogger.log(TAG, "handleUtterance bytes=" + pcm.length);
        byte[] start = turns.offer(pcm);
        if (start == null) {
            FileLogger.log(TAG, "turn in flight, utterance held as the pending turn");
            return;
        }
        try {
            executor.execute(() -> {
                for (byte[] next = start; next != null && captureRunning.get(); next = turns.finish()) runTurn(next);
            });
        } catch (RejectedExecutionException e) {
            FileLogger.log(TAG, "handleUtterance after screen destroyed");
        }
    }

    private void runTurn(byte[] pcm) {
        String turnUrl = serverUrl();
        try {
            setStatus("Transcribing…");
            refreshIdentity(turnUrl);
            resolveSet(turnUrl);
            String text = postStt(turnUrl, pcm);
            if (text == null || text.trim().isEmpty()) {
                setStatus("Listening…");
                return;
            }
            lastTranscription = text;
            mainHandler.post(this::invalidate);

            setStatus("Thinking…");
            String response = postChat(turnUrl, text);
            if (response == null || response.isEmpty()) {
                setStatus("Listening…");
                return;
            }

            setStatus("Speaking…");
            ttsPlaying.set(true);
            try {
                playTts(turnUrl, response);
            } finally {
                ttsPlaying.set(false);
            }
            setStatus("Listening…");
        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR handleUtterance", e);
            setStatus("Listening…");
        }
    }

    private String csrfToken = "";

    private void applyIdentity(HttpURLConnection conn, String turnUrl) {
        String cookie = android.webkit.CookieManager.getInstance().getCookie(turnUrl);
        if (cookie != null) conn.setRequestProperty("Cookie", cookie);
        if (!csrfToken.isEmpty()) conn.setRequestProperty("X-CSRF-Token", csrfToken);
    }

    private void refreshIdentity(String turnUrl) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(turnUrl + "/").openConnection();
        applyIdentity(conn, turnUrl);
        conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
        try {
            String html = readAll(conn.getInputStream());
            java.util.regex.Matcher match = java.util.regex.Pattern.compile("<meta name=\"csrf-token\" content=\"([^\"]+)\"").matcher(html);
            if (!match.find()) throw new IOException("Session unavailable");
            csrfToken = match.group(1);
            java.util.regex.Matcher preference = java.util.regex.Pattern.compile("\"lastSet\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|null)").matcher(html);
            if (preference.find()) {
                try { preferredSetName = new org.json.JSONArray("[" + preference.group(1) + "]").optString(0, ""); }
                catch (org.json.JSONException e) { throw new IOException("Invalid selected chat", e); }
            }
            java.util.Map<String, java.util.List<String>> headers = conn.getHeaderFields();
            for (java.util.Map.Entry<String, java.util.List<String>> entry : headers.entrySet()) {
                if ("Set-Cookie".equalsIgnoreCase(entry.getKey())) {
                    for (String value : entry.getValue()) android.webkit.CookieManager.getInstance().setCookie(turnUrl, value);
                }
            }
        } finally { conn.disconnect(); }
    }

    private void retryDelay(long ms) throws IOException {
        if (!captureRunning.get()) throw new IOException("Voice session stopped");
        try { Thread.sleep(ms); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("Interrupted", e); }
        if (!captureRunning.get()) throw new IOException("Voice session stopped");
    }

    private String postStt(String turnUrl, byte[] pcm) throws IOException {
        final String key = UUID.randomUUID().toString();
        return DurableVoiceProtocol.retryAdmission(key, operation -> postSttAttempt(turnUrl, pcm, operation), this::retryDelay);
    }

    private String postSttAttempt(String turnUrl, byte[] pcm, String key) throws IOException {
        byte[] wav = wrapPcmAsWav(pcm, SAMPLE_RATE, 1);
        String boundary = "----chatbotauto" + UUID.randomUUID();
        URL url = new URL(turnUrl + "/stt");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        applyIdentity(conn, turnUrl);
        conn.setRequestProperty("Idempotency-Key", key);
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);

        try {
        try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
            out.writeBytes("--" + boundary + "\r\n");
            out.writeBytes("Content-Disposition: form-data; name=\"audio\"; filename=\"capture.wav\"\r\n");
            out.writeBytes("Content-Type: audio/wav\r\n\r\n");
            out.write(wav);
            if (!activeSetId.isEmpty()) {
                out.writeBytes("\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"set_id\"\r\n\r\n" + activeSetId);
            }
            out.writeBytes("\r\n--" + boundary + "--\r\n");
        }

        int code = conn.getResponseCode();
        FileLogger.log(TAG, "postStt response code=" + code);
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String body = readAll(is);
        if (code == 408 || code == 429 || code >= 500) throw new IOException("STT temporarily unavailable");
        if (code < 200 || code >= 300) {
            return null;
        }
        try { return new org.json.JSONObject(body).optString("text"); }
        catch (org.json.JSONException e) { throw new IOException("Invalid transcript", e); }
        } finally { conn.disconnect(); }
    }

    private HttpURLConnection admitJson(String turnUrl, String path, String json, String key, boolean durable) throws IOException {
        return DurableVoiceProtocol.retryAdmission(key, operation -> {
            HttpURLConnection conn = (HttpURLConnection) new URL(turnUrl + path).openConnection();
            try {
                conn.setRequestMethod("POST");
                applyIdentity(conn, turnUrl);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Idempotency-Key", operation);
                if (durable) conn.setRequestProperty("X-Generation-Mode", "durable");
                conn.setDoOutput(true);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(60000);
                conn.getOutputStream().write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                int code = conn.getResponseCode();
                if (code == 408 || code == 429 || code >= 500) throw new IOException("Admission temporarily unavailable");
                return conn;
            } catch (IOException e) { conn.disconnect(); throw e; }
        }, this::retryDelay);
    }

    private String activeSetId = "";
    private String preferredSetName = "";
    private long activeSetVersion;

    private void resolveSet(String turnUrl) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(turnUrl + "/get_sets").openConnection();
        applyIdentity(conn, turnUrl);
        conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
        try {
            if (conn.getResponseCode() == 401) { activeSetId = ""; activeSetVersion = 0; return; }
            org.json.JSONArray sets = new org.json.JSONArray(readAll(conn.getInputStream()));
            String[] names = new String[sets.length()];
            boolean[] defaults = new boolean[sets.length()];
            for (int i = 0; i < sets.length(); i++) {
                org.json.JSONObject candidate = sets.getJSONObject(i);
                names[i] = candidate.optString("name");
                defaults[i] = candidate.optBoolean("is_default");
            }
            int index = DurableVoiceProtocol.selectSet(names, defaults, preferredSetName);
            if (index < 0) throw new IOException("No active chat");
            org.json.JSONObject selected = sets.getJSONObject(index);
            activeSetId = selected.getString("set_id");
            activeSetVersion = selected.getLong("version");
        } catch (org.json.JSONException e) { throw new IOException("Invalid chat list", e); }
        finally { conn.disconnect(); }
    }

    private String postChat(String turnUrl, String text) throws IOException {
        resolveSet(turnUrl);
        HttpURLConnection conn;
        while (true) {
            String key = UUID.randomUUID().toString();
            String json = String.format(Locale.US, "{\"message\":%s,\"set_id\":%s,\"expected_version\":%d}", escapeJson(text), escapeJson(activeSetId), activeSetVersion);
            conn = admitJson(turnUrl, "/chat", json, key, true);
            int code = conn.getResponseCode();
            if (code == 409) {
                String rejected = readAll(conn.getErrorStream());
                conn.disconnect();
                try {
                    if (DurableVoiceProtocol.refreshRejectedVersion(code, new org.json.JSONObject(rejected).optString("error"))) { resolveSet(turnUrl); continue; }
                } catch (org.json.JSONException e) { throw new IOException("Invalid admission rejection", e); }
                return null;
            }
            if (code < 200 || code >= 300) { conn.disconnect(); return null; }
            break;
        }
        DurableVoiceProtocol cursor = new DurableVoiceProtocol(conn.getHeaderField("X-Generation-Id"));
        generation = cursor;
        generationOrigin = turnUrl;
        while (!cursor.saved() && captureRunning.get()) {
            try (InputStreamReader reader = new InputStreamReader(conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8)) {
                char[] chunk = new char[2048];
                int count;
                while (!cursor.saved() && (count = reader.read(chunk)) != -1) {
                    cursor.feed(new String(chunk, 0, count), line -> {
                        try {
                            org.json.JSONObject event = new org.json.JSONObject(line);
                            cursor.apply(event.optLong("seq"), event.optString("type"), event.optString("text"));
                        } catch (org.json.JSONException e) {
                            throw new IOException("Invalid generation event", e);
                        }
                    });
                }
            } catch (IOException e) {
                if (!captureRunning.get()) break;
                if ("Generation failed".equals(e.getMessage())) throw e;
            } finally { conn.disconnect(); }
            if (!cursor.saved() && captureRunning.get()) {
                cursor.resetView();
                try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("Interrupted", e); }
                conn = (HttpURLConnection) new URL(turnUrl + cursor.eventsPath()).openConnection();
                applyIdentity(conn, turnUrl);
                conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
                if (conn.getResponseCode() == 404) { conn.disconnect(); throw new IOException("Generation interrupted"); }
            }
        }
        generation = null;
        return cursor.text();
    }

    private void playTts(String turnUrl, String text) throws IOException {
        String key = UUID.randomUUID().toString();
        String json = String.format(Locale.US, "{\"text\":%s%s}", escapeJson(text), activeSetId.isEmpty() ? "" : ",\"set_id\":" + escapeJson(activeSetId));
        HttpURLConnection conn = DurableVoiceProtocol.openTts(key, operation -> {
            HttpURLConnection admission = admitJson(turnUrl, "/tts", json, operation, false);
            try {
                if (admission.getResponseCode() != 200) return null;
                String token = admission.getHeaderField("X-TTS-Token");
                String body = readAll(admission.getInputStream());
                return token == null ? body : token;
            } finally { admission.disconnect(); }
        }, token -> {
            HttpURLConnection stream = (HttpURLConnection) new URL(turnUrl + "/tts_stream/" + token).openConnection();
            try {
                applyIdentity(stream, turnUrl);
                stream.setConnectTimeout(15000);
                stream.setReadTimeout(60000);
                int code = stream.getResponseCode();
                if (code == 404) { stream.disconnect(); return null; }
                if (code != 200) throw new IOException("TTS stream unavailable");
                return stream;
            } catch (IOException e) { stream.disconnect(); throw e; }
        }, this::retryDelay);
        if (conn == null) return;

        int sampleRate = 24000;
        AudioAttributes audioAttrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_MEDIA)
                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                .build();
        FileLogger.log(TAG, "playTts: AudioTrack USAGE=" + audioAttrs.getUsage() + " CONTENT=" + audioAttrs.getContentType());
        AudioTrack track = new AudioTrack.Builder()
                .setAudioAttributes(audioAttrs)
                .setAudioFormat(new AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .setSampleRate(sampleRate)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .build())
                .setBufferSizeInBytes(1024 * 1024)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build();
        if (track.getState() != AudioTrack.STATE_INITIALIZED) {
            FileLogger.log(TAG, "playTts: track not initialized");
            try { track.release(); } catch (Exception ignored) {}
            conn.disconnect();
            return;
        }
        try {
            track.play();
        } catch (Exception e) {
            FileLogger.log(TAG, "playTts: track.play failed", e);
            try { track.release(); } catch (Exception ignored) {}
            conn.disconnect();
            return;
        }

        activeTrack = track;
        long total = 0;
        String contentType = conn.getContentType();
        boolean isOpus = contentType != null && contentType.contains("opus");
        OggOpusStreamDecoder opusDecoder = isOpus ? new OggOpusStreamDecoder() : null;
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[2048];
            int n;
            while ((n = is.read(buf)) != -1) {
                if (opusDecoder != null) {
                    opusDecoder.feed(buf, n);
                    byte[] pcm = opusDecoder.takePcm();
                    if (pcm.length > 0) {
                        track.write(pcm, 0, pcm.length);
                        total += pcm.length;
                    }
                } else {
                    track.write(buf, 0, n);
                    total += n;
                }
            }
            if (opusDecoder != null) {
                opusDecoder.finish();
                byte[] tail = opusDecoder.takePcm();
                if (tail.length > 0) {
                    track.write(tail, 0, tail.length);
                    total += tail.length;
                }
                if (!opusDecoder.sawOpusHead() || opusDecoder.hasIncompleteData()) {
                    FileLogger.log(TAG, "playTts opus stream incomplete");
                }
            }
        } catch (IOException e) {
            FileLogger.log(TAG, "playTts stream read error", e);
        }
        FileLogger.log(TAG, "playTts wrote bytes=" + total);
        try {
            // Blocking writes return once all but the last buffer's worth has played
            long durationMs = CarVoicePolicy.drainMs(total, track.getBufferSizeInFrames() * 2, sampleRate);
            FileLogger.log(TAG, "playTts waiting drain " + durationMs + "ms");
            Thread.sleep(durationMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        try {
            track.stop();
        } catch (Exception e) {
            FileLogger.log(TAG, "playTts track.stop", e);
        }
        track.release();
        activeTrack = null;
        conn.disconnect();
        FileLogger.log(TAG, "playTts complete");
    }

    private void requestAudioFocus() {
        if (audioManager == null || hasAudioFocus) return;
        audioFocusRequest = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build())
                .setOnAudioFocusChangeListener(change -> {
                    Log.i(TAG, "Audio focus change: " + change);
                    FileLogger.log(TAG, "AudioFocusChangeListener: " + change);
                })
                .build();
        int result = audioManager.requestAudioFocus(audioFocusRequest);
        hasAudioFocus = (result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
        FileLogger.log(TAG, "requestAudioFocus result=" + result + " granted=" + hasAudioFocus);
    }

    private void abandonAudioFocus() {
        if (audioManager != null && audioFocusRequest != null && hasAudioFocus) {
            audioManager.abandonAudioFocusRequest(audioFocusRequest);
            FileLogger.log(TAG, "abandonAudioFocus");
            hasAudioFocus = false;
        }
    }

    private static double computeRms(short[] samples, int n) {
        long sum = 0;
        for (int i = 0; i < n; i++) {
            int s = samples[i];
            sum += (long) s * s;
        }
        return Math.sqrt(sum / (double) n);
    }

    private static void writeShortsLE(ByteArrayOutputStream out, short[] samples, int n) {
        ByteBuffer bb = ByteBuffer.allocate(n * 2).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < n; i++) bb.putShort(samples[i]);
        byte[] bytes = bb.array();
        out.write(bytes, 0, bytes.length);
    }

    private static byte[] wrapPcmAsWav(byte[] pcm, int sampleRate, int channels) {
        int byteRate = sampleRate * channels * 2;
        int dataLen = pcm.length;
        int totalLen = dataLen + 36;
        ByteBuffer header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN);
        header.put("RIFF".getBytes());
        header.putInt(totalLen);
        header.put("WAVE".getBytes());
        header.put("fmt ".getBytes());
        header.putInt(16);
        header.putShort((short) 1); // PCM
        header.putShort((short) channels);
        header.putInt(sampleRate);
        header.putInt(byteRate);
        header.putShort((short) (channels * 2));
        header.putShort((short) 16);
        header.put("data".getBytes());
        header.putInt(dataLen);
        byte[] out = new byte[44 + dataLen];
        System.arraycopy(header.array(), 0, out, 0, 44);
        System.arraycopy(pcm, 0, out, 44, dataLen);
        return out;
    }

    private static String readAll(InputStream is) throws IOException {
        if (is == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private void exitVoiceMode() {
        FileLogger.log(TAG, "exitVoiceMode");
        stopCapture();
        AudioTrack track = activeTrack;
        if (track != null) { try { track.pause(); track.flush(); } catch (IllegalStateException ignored) {} }
        final DurableVoiceProtocol cursor = generation;
        final String origin = generationOrigin;
        if (cursor != null) captureExecutor.execute(() -> {
            String key = UUID.randomUUID().toString();
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(origin + cursor.stopPath()).openConnection();
                conn.setRequestMethod("POST");
                applyIdentity(conn, origin);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Idempotency-Key", key);
                conn.setDoOutput(true); conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
                conn.getOutputStream().write("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                conn.getResponseCode(); conn.disconnect();
            } catch (IOException e) { FileLogger.log(TAG, "Explicit Stop failed"); }
        });
        abandonAudioFocus();
        try {
            getCarContext().finishCarApp();
        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR finishCarApp", e);
        }
    }
}
