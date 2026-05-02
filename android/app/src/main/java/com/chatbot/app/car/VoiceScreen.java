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

import com.chatbot.app.R;
import com.chatbot.app.util.FileLogger;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

    private final String serverUrl;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AudioManager audioManager;
    private final AtomicBoolean captureRunning = new AtomicBoolean(false);
    private final AtomicBoolean ttsPlaying = new AtomicBoolean(false);

    private AudioRecord audioRecord;
    private AudioFocusRequest audioFocusRequest;
    private boolean hasAudioFocus = false;
    private String statusText = "Initializing…";
    private String lastTranscription = "";

    public VoiceScreen(@NonNull CarContext carContext) {
        super(carContext);
        serverUrl = carContext.getString(R.string.server_url);
        audioManager = (AudioManager) carContext.getSystemService(Context.AUDIO_SERVICE);
        Log.i(TAG, "VoiceScreen created with server: " + serverUrl);
        FileLogger.log(TAG, "VoiceScreen created, serverUrl=" + serverUrl);
        mainHandler.postDelayed(this::startCapture, 500);
    }

    @NonNull
    @Override
    public Template onGetTemplate() {
        FileLogger.log(TAG, "onGetTemplate status=" + statusText + " last=" + lastTranscription);

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
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                    SAMPLE_RATE,
                    CHANNEL_IN_CONFIG,
                    AUDIO_ENCODING,
                    bufferBytes);
        } catch (SecurityException se) {
            FileLogger.log(TAG, "ERROR creating AudioRecord (permissions?)", se);
            setStatus("Mic permission missing");
            return;
        }

        if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
            FileLogger.log(TAG, "ERROR: AudioRecord not initialized state=" + audioRecord.getState());
            audioRecord.release();
            audioRecord = null;
            setStatus("Audio init failed");
            return;
        }

        audioRecord.startRecording();
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

        while (captureRunning.get() && audioRecord != null) {
            int read = audioRecord.read(frame, 0, FRAME_SAMPLES);
            if (read <= 0) {
                FileLogger.log(TAG, "audioRecord.read returned " + read);
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

    private void handleUtterance(byte[] pcm) {
        FileLogger.log(TAG, "handleUtterance bytes=" + pcm.length);
        executor.execute(() -> {
            try {
                setStatus("Transcribing…");
                String text = postStt(pcm);
                FileLogger.log(TAG, "STT result: " + text);
                if (text == null || text.trim().isEmpty()) {
                    setStatus("Listening…");
                    return;
                }
                lastTranscription = text;
                mainHandler.post(this::invalidate);

                setStatus("Thinking…");
                String response = postChat(text);
                FileLogger.log(TAG, "Chat response: " + (response == null ? "null" : response.substring(0, Math.min(120, response.length()))));
                if (response == null || response.isEmpty()) {
                    setStatus("Listening…");
                    return;
                }

                setStatus("Speaking…");
                ttsPlaying.set(true);
                try {
                    playTts(response);
                } finally {
                    ttsPlaying.set(false);
                }
                setStatus("Listening…");
            } catch (Exception e) {
                FileLogger.log(TAG, "ERROR handleUtterance", e);
                setStatus("Listening…");
            }
        });
    }

    private String postStt(byte[] pcm) throws IOException {
        byte[] wav = wrapPcmAsWav(pcm, SAMPLE_RATE, 1);
        String boundary = "----chatbotauto" + UUID.randomUUID();
        URL url = new URL(serverUrl + "/stt");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);

        try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
            out.writeBytes("--" + boundary + "\r\n");
            out.writeBytes("Content-Disposition: form-data; name=\"audio\"; filename=\"capture.wav\"\r\n");
            out.writeBytes("Content-Type: audio/wav\r\n\r\n");
            out.write(wav);
            out.writeBytes("\r\n--" + boundary + "--\r\n");
        }

        int code = conn.getResponseCode();
        FileLogger.log(TAG, "postStt response code=" + code);
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String body = readAll(is);
        conn.disconnect();
        FileLogger.log(TAG, "postStt body=" + body);
        if (code < 200 || code >= 300) {
            return null;
        }
        // Expect {"text":"..."}
        int idx = body.indexOf("\"text\"");
        if (idx < 0) return null;
        int colon = body.indexOf(':', idx);
        int q1 = body.indexOf('"', colon + 1);
        int q2 = body.indexOf('"', q1 + 1);
        if (q1 < 0 || q2 < 0) return null;
        return body.substring(q1 + 1, q2);
    }

    private String postChat(String text) throws IOException {
        URL url = new URL(serverUrl + "/chat");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);
        String json = String.format(Locale.US, "{\"message\":%s}", escapeJson(text));
        conn.getOutputStream().write(json.getBytes());

        int code = conn.getResponseCode();
        FileLogger.log(TAG, "postChat code=" + code);
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String body = readAll(is);
        conn.disconnect();
        if (code < 200 || code >= 300) {
            FileLogger.log(TAG, "postChat error body=" + body);
            return null;
        }
        return body;
    }

    private void playTts(String text) throws IOException {
        FileLogger.log(TAG, "playTts text=" + text.substring(0, Math.min(50, text.length())));
        // Step 1: get token
        URL url = new URL(serverUrl + "/tts");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);
        String json = String.format(Locale.US, "{\"text\":%s}", escapeJson(text));
        conn.getOutputStream().write(json.getBytes());

        int code = conn.getResponseCode();
        FileLogger.log(TAG, "playTts /tts code=" + code);
        if (code != 200) {
            String err = readAll(conn.getErrorStream());
            FileLogger.log(TAG, "playTts /tts error=" + err);
            conn.disconnect();
            return;
        }
        String token = conn.getHeaderField("X-TTS-Token");
        String body = readAll(conn.getInputStream());
        conn.disconnect();
        if (token == null) token = body;
        FileLogger.log(TAG, "playTts token=" + token);

        // Step 2: stream
        conn = (HttpURLConnection) new URL(serverUrl + "/tts_stream/" + token).openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);
        code = conn.getResponseCode();
        FileLogger.log(TAG, "playTts /tts_stream code=" + code);
        if (code != 200) {
            conn.disconnect();
            return;
        }

        int sampleRate = 24000;
        AudioAttributes audioAttrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
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
        track.play();

        long total = 0;
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[2048];
            int n;
            while ((n = is.read(buf)) != -1) {
                track.write(buf, 0, n);
                total += n;
            }
        } catch (IOException e) {
            FileLogger.log(TAG, "playTts stream read error", e);
        }
        FileLogger.log(TAG, "playTts wrote bytes=" + total);
        try {
            // Wait for buffered audio to drain — simple sleep based on bytes
            long durationMs = (total / 2 * 1000L) / sampleRate; // 16-bit mono
            FileLogger.log(TAG, "playTts waiting drain " + durationMs + "ms");
            Thread.sleep(Math.min(durationMs, 30000));
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        try {
            track.stop();
        } catch (Exception e) {
            FileLogger.log(TAG, "playTts track.stop", e);
        }
        track.release();
        conn.disconnect();
        FileLogger.log(TAG, "playTts complete");
    }

    private void requestAudioFocus() {
        if (audioManager == null || hasAudioFocus) return;
        audioFocusRequest = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
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

    private static void writeShortsLE(OutputStream out, short[] samples, int n) {
        ByteBuffer bb = ByteBuffer.allocate(n * 2).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < n; i++) bb.putShort(samples[i]);
        try {
            out.write(bb.array());
        } catch (IOException e) {
            // shouldn't happen for ByteArrayOutputStream
        }
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
        abandonAudioFocus();
        try {
            getCarContext().finishCarApp();
        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR finishCarApp", e);
        }
    }
}
