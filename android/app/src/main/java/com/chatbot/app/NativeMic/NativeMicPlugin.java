package com.chatbot.app;

import android.Manifest;
import android.content.pm.PackageManager;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Handler;
import android.os.Looper;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@CapacitorPlugin(name = "NativeMic")
public class NativeMicPlugin extends Plugin {

    private static final int SAMPLE_RATE = 16000;
    private static final int CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO;
    private static final int AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT;
    private static final int PERMISSION_REQUEST_CODE = 200;

    private AudioRecord audioRecord = null;
    private boolean isRecording = false;
    private Thread recordingThread = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private PluginCall permissionCall = null;

    @PluginMethod
    public void requestPermission(PluginCall call) {
        if (ContextCompat.checkSelfPermission(getContext(), Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED) {
            JSObject result = new JSObject();
            result.put("granted", true);
            call.resolve(result);
        } else {
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
        if (isRecording) {
            call.reject("Already recording");
            return;
        }

        if (ContextCompat.checkSelfPermission(getContext(), Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
            call.reject("Microphone permission not granted");
            return;
        }

        int bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT);
        if (bufferSize == AudioRecord.ERROR || bufferSize == AudioRecord.ERROR_BAD_VALUE) {
            call.reject("Unable to get minimum buffer size");
            return;
        }

        try {
            audioRecord = new AudioRecord(
                MediaRecorder.AudioSource.MIC,
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
            call.reject("Failed to start recording: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        stopRecording();
        JSObject result = new JSObject();
        result.put("stopped", true);
        call.resolve(result);
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
        if (requestCode == PERMISSION_REQUEST_CODE && permissionCall != null) {
            boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            JSObject result = new JSObject();
            result.put("granted", granted);
            permissionCall.resolve(result);
            permissionCall = null;
        }
    }

    public void destroy() {
        stopRecording();
    }
}
