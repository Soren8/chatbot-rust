package com.chatbot.app;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.chatbot.app.util.FileLogger;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@CapacitorPlugin(name = "NativeMic")
public class NativeMicPlugin extends Plugin {
    private static final String TAG = "NativeMicPlugin";

    public NativeMicPlugin() {
        Log.d(TAG, "NativeMicPlugin constructor called");
    }

    private static final int SAMPLE_RATE = 16000;
    private static final int CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO;
    private static final int AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT;
    private static final int PERMISSION_REQUEST_CODE = 200;

    private AudioRecord audioRecord = null;
    private boolean isRecording = false;
    private Thread recordingThread = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private PluginCall permissionCall = null;
    private AudioManager audioManager = null;
    private AudioFocusRequest audioFocusRequest = null;
    private boolean hasAudioFocus = false;

    @Override
    public void load() {
        super.load();
        FileLogger.init(getContext().getApplicationContext());
        FileLogger.log(TAG, "NativeMicPlugin.load()");
        audioManager = (AudioManager) getContext().getSystemService(Context.AUDIO_SERVICE);
    }

    @PluginMethod
    public void requestPermission(PluginCall call) {
        Log.d(TAG, "requestPermission called");
        if (ContextCompat.checkSelfPermission(getContext(), Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Permission already granted");
            JSObject result = new JSObject();
            result.put("granted", true);
            call.resolve(result);
        } else {
            Log.d(TAG, "Requesting permission");
            permissionCall = call;
            ActivityCompat.requestPermissions(
                getActivity(),
                new String[]{Manifest.permission.RECORD_AUDIO},
                PERMISSION_REQUEST_CODE
            );
        }
    }

    @PluginMethod
    public void isRecording(PluginCall call) {
        JSObject result = new JSObject();
        result.put("recording", isRecording);
        call.resolve(result);
    }

    @PluginMethod
    public void start(PluginCall call) {
        Log.d(TAG, "start called, isRecording=" + isRecording);
        FileLogger.log(TAG, "start called, isRecording=" + isRecording);
        if (isRecording) {
            call.reject("Already recording");
            return;
        }

        if (ContextCompat.checkSelfPermission(getContext(), Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "Permission not granted for recording");
            call.reject("Microphone permission not granted");
            return;
        }

        requestAudioFocus();

        int bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT);
        if (bufferSize == AudioRecord.ERROR || bufferSize == AudioRecord.ERROR_BAD_VALUE) {
            Log.e(TAG, "Invalid buffer size: " + bufferSize);
            call.reject("Unable to get minimum buffer size");
            return;
        }

        try {
            Log.d(TAG, "Creating AudioRecord...");
            audioRecord = new AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize * 2
            );

            if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
                call.reject("AudioRecord failed to initialize");
                audioRecord.release();
                audioRecord = null;
                return;
            }

            audioRecord.startRecording();
            isRecording = true;

            recordingThread = new Thread(() -> {
                short[] buffer = new short[bufferSize];
                while (isRecording && audioRecord != null) {
                    int read = audioRecord.read(buffer, 0, bufferSize);
                    if (read > 0) {
                        byte[] pcmBytes = shortArrayToByteArray(buffer, read);
                        notifyAudioData(pcmBytes);
                    }
                }
            });
            recordingThread.start();

            JSObject result = new JSObject();
            result.put("started", true);
            call.resolve(result);

        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR start: " + e.getMessage(), e);
            call.reject("Failed to start recording: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        FileLogger.log(TAG, "stop called");
        stopRecording();
        abandonAudioFocus();
        JSObject result = new JSObject();
        result.put("stopped", true);
        call.resolve(result);
    }

    private void requestAudioFocus() {
        if (audioManager == null || hasAudioFocus) {
            FileLogger.log(TAG, "requestAudioFocus skipped: audioManager=" + (audioManager != null) + " hasAudioFocus=" + hasAudioFocus);
            return;
        }
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

    private void stopRecording() {
        isRecording = false;
        if (recordingThread != null) {
            try {
                recordingThread.join(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            recordingThread = null;
        }
        if (audioRecord != null) {
            try {
                if (audioRecord.getState() == AudioRecord.STATE_INITIALIZED) {
                    audioRecord.stop();
                }
                audioRecord.release();
            } catch (Exception e) {
                // ignore
            }
            audioRecord = null;
        }
    }

    private byte[] shortArrayToByteArray(short[] shorts, int count) {
        byte[] bytes = new byte[count * 2];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(shorts, 0, count);
        return bytes;
    }

    private void notifyAudioData(byte[] pcmData) {
        mainHandler.post(() -> {
            JSObject ret = new JSObject();
            ret.put("type", "audioData");
            ret.put("data", android.util.Base64.encodeToString(pcmData, android.util.Base64.NO_WRAP));
            notifyListeners("nativeMicData", ret);
        });
    }

    @Override
    protected void handleRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.handleRequestPermissionsResult(requestCode, permissions, grantResults);
        Log.d(TAG, "handleRequestPermissionsResult: " + requestCode + " results=" + (grantResults.length > 0 ? grantResults[0] : "none"));
        if (requestCode == PERMISSION_REQUEST_CODE && permissionCall != null) {
            boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            Log.d(TAG, "Permission result: granted=" + granted);
            JSObject result = new JSObject();
            result.put("granted", granted);
            permissionCall.resolve(result);
            permissionCall = null;
        }
    }

    public void destroy() {
        stopRecording();
        abandonAudioFocus();
    }
}
