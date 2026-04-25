package com.chatbot.app.car;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.Handler;
import android.os.Looper;
import android.speech.RecognitionListener;
import android.speech.RecognizerIntent;
import android.speech.SpeechRecognizer;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.car.app.CarAppService;
import androidx.car.app.CarContext;
import androidx.car.app.Screen;
import androidx.car.app.Session;
import androidx.car.app.model.CarIcon;
import androidx.car.app.model.Pane;
import androidx.car.app.model.PaneTemplate;
import androidx.car.app.model.Row;
import androidx.car.app.model.Template;
import androidx.car.app.validation.HostValidator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class VoiceScreen extends Screen {
    private static final String TAG = "VoiceScreen";
    private static final String SERVER_URL = "http://10.0.2.2:80";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private AudioTrack audioTrack;
    private SpeechRecognizer speechRecognizer;
    private boolean isListening = false;
    private String lastTranscription = "";

    public VoiceScreen(@NonNull CarContext carContext) {
        super(carContext);
        Log.i(TAG, "VoiceScreen created");
        mainHandler.postDelayed(this::startVoiceRecognition, 500);
    }

    @NonNull
    @Override
    public Template onGetTemplate() {
        Log.i(TAG, "onGetTemplate, listening=" + isListening);

        Pane.Builder paneBuilder = new Pane.Builder();

        paneBuilder.addRow(new Row.Builder()
                .setTitle(isListening ? "Listening..." : "Chatbot Voice")
                .build());

        if (isListening) {
            paneBuilder.addRow(new Row.Builder()
                    .setTitle(lastTranscription.isEmpty() ? "Speak now" : lastTranscription)
                    .build());
        }

        paneBuilder.addRow(new Row.Builder()
                .setTitle("Exit")
                .setOnClickListener(() -> {
                    Log.i(TAG, "Exit clicked");
                    exitVoiceMode();
                })
                .build());

        Pane pane = paneBuilder.build();
        return new PaneTemplate.Builder(pane)
                .setTitle("Chatbot")
                .build();
    }

    public void startVoiceRecognition() {
        Log.i(TAG, "Starting voice recognition");
        Context context = getCarContext();

        if (!SpeechRecognizer.isRecognitionAvailable(context)) {
            Log.e(TAG, "Speech recognition not available");
            return;
        }

        isListening = true;
        invalidate();

        Intent intent = new Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH);
        intent.putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM);
        intent.putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault());
        intent.putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true);
        intent.putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1);

        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(context);
        speechRecognizer.setRecognitionListener(new RecognitionListener() {
            @Override
            public void onReadyForSpeech(android.os.Bundle params) {
                Log.i(TAG, "Ready for speech");
            }

            @Override
            public void onBeginningOfSpeech() {
                Log.i(TAG, "Beginning of speech");
            }

            @Override
            public void onRmsChanged(float rmsdB) {}

            @Override
            public void onBufferReceived(byte[] buffer) {}

            @Override
            public void onEndOfSpeech() {
                Log.i(TAG, "End of speech");
            }

            @Override
            public void onError(int error) {
                Log.e(TAG, "Recognition error: " + error);
                isListening = false;
                invalidate();
            }

            @Override
            public void onResults(android.os.Bundle results) {
                Log.i(TAG, "Got results");
                var matches = results.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION);
                if (matches != null && !matches.isEmpty()) {
                    lastTranscription = matches.get(0);
                    Log.i(TAG, "Transcribed: " + lastTranscription);
                    processVoiceInput(lastTranscription);
                }
                isListening = false;
                invalidate();
            }

            @Override
            public void onPartialResults(android.os.Bundle partialResults) {
                var matches = partialResults.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION);
                if (matches != null && !matches.isEmpty()) {
                    lastTranscription = matches.get(0);
                    invalidate();
                }
            }

            @Override
            public void onEvent(int eventType, android.os.Bundle params) {}
        });

        try {
            speechRecognizer.startListening(intent);
        } catch (Exception e) {
            Log.e(TAG, "Failed to start listening", e);
            isListening = false;
            invalidate();
        }
    }

    private void processVoiceInput(String text) {
        executor.execute(() -> {
            try {
                String response = sendToChat(text);
                if (response != null && !response.isEmpty()) {
                    playTts(response);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error processing voice input", e);
            }
        });
    }

    private String sendToChat(String text) throws IOException {
        Log.i(TAG, "Sending to chat: " + text);
        URL url = new URL(SERVER_URL + "/chat");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String json = String.format(Locale.US, "{\"message\":%s}", escapeJson(text));
        conn.getOutputStream().write(json.getBytes());

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            Log.e(TAG, "Chat API returned " + responseCode);
            return null;
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try (InputStream is = conn.getInputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                result.write(buffer, 0, len);
            }
        }
        conn.disconnect();

        String response = result.toString();
        Log.i(TAG, "Chat response: " + response);
        return response;
    }

    private void playTts(String text) {
        executor.execute(() -> {
            try {
                URL url = new URL(SERVER_URL + "/tts");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);

                String json = String.format(Locale.US, "{\"text\":%s}", escapeJson(text));
                conn.getOutputStream().write(json.getBytes());

                int responseCode = conn.getResponseCode();
                if (responseCode != 200) {
                    Log.e(TAG, "TTS API returned " + responseCode);
                    return;
                }

                String token = conn.getHeaderField("X-TTS-Token");
                String responseBody;
                try (InputStream is = conn.getInputStream()) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        bos.write(buffer, 0, len);
                    }
                    responseBody = bos.toString();
                }
                conn.disconnect();

                if (token == null) {
                    token = responseBody;
                }

                conn = (HttpURLConnection) new URL(SERVER_URL + "/tts_stream/" + token).openConnection();
                responseCode = conn.getResponseCode();
                if (responseCode != 200) {
                    Log.e(TAG, "TTS stream API returned " + responseCode);
                    return;
                }

                int sampleRate = 24000;
                AudioTrack track = new AudioTrack.Builder()
                        .setAudioAttributes(new AudioAttributes.Builder()
                                .setUsage(AudioAttributes.USAGE_MEDIA)
                                .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                                .build())
                        .setAudioFormat(new AudioFormat.Builder()
                                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                                .setSampleRate(sampleRate)
                                .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                                .build())
                        .setBufferSizeInBytes(1024 * 1024)
                        .setTransferMode(AudioTrack.MODE_STREAM)
                        .build();

                track.play();

                try (InputStream is = conn.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        track.write(buffer, 0, len);
                    }
                }

                track.stop();
                track.release();
                conn.disconnect();

                Log.i(TAG, "TTS playback complete");
            } catch (Exception e) {
                Log.e(TAG, "Error playing TTS", e);
            }
        });
    }

    private String escapeJson(String s) {
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
        Log.i(TAG, "Exiting voice mode");
        if (speechRecognizer != null) {
            try {
                speechRecognizer.destroy();
            } catch (Exception e) {
                Log.e(TAG, "Error destroying speech recognizer", e);
            }
            speechRecognizer = null;
        }
        try {
            getCarContext().finishCarApp();
        } catch (Exception e) {
            Log.e(TAG, "Error finishing", e);
        }
    }

    private void cleanup() {
        if (speechRecognizer != null) {
            try {
                speechRecognizer.destroy();
            } catch (Exception e) {
                Log.e(TAG, "Error destroying speech recognizer", e);
            }
            speechRecognizer = null;
        }
    }
}