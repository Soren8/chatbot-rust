package com.chatbot.app;

import android.Manifest;
import android.content.pm.PackageManager;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.media.audiofx.AcousticEchoCanceler;
import android.media.audiofx.AutomaticGainControl;
import android.media.audiofx.NoiseSuppressor;
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
    /** Fixed 20 ms frames for steady JS consumption (320 samples * 2 bytes). */
    private static final int CHUNK_SAMPLES = 320;
    private static final int CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO;
    private static final int AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT;
    private static final int PERMISSION_REQUEST_CODE = 200;

    private AudioRecord audioRecord = null;
    private boolean isRecording = false;
    private Thread recordingThread = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private PluginCall permissionCall = null;
    private AcousticEchoCanceler echoCanceler = null;
    private NoiseSuppressor noiseSuppressor = null;
    private AutomaticGainControl automaticGainControl = null;

    @Override
    public void load() {
        super.load();
        FileLogger.init(getContext().getApplicationContext());
        FileLogger.log(TAG, "NativeMicPlugin.load()");
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

        int bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT);
        if (bufferSize == AudioRecord.ERROR || bufferSize == AudioRecord.ERROR_BAD_VALUE) {
            Log.e(TAG, "Invalid buffer size: " + bufferSize);
            call.reject("Unable to get minimum buffer size");
            return;
        }

        try {
            Log.d(TAG, "Creating AudioRecord...");
            // VOICE_RECOGNITION: speech capture without entering call/HFP routing.
            audioRecord = new AudioRecord(
                MediaRecorder.AudioSource.VOICE_RECOGNITION,
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize * 4
            );

            if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
                call.reject("AudioRecord failed to initialize");
                audioRecord.release();
                audioRecord = null;
                return;
            }

            enableAudioEffects(audioRecord.getAudioSessionId());

            audioRecord.startRecording();
            isRecording = true;

            recordingThread = new Thread(() -> {
                short[] readBuffer = new short[bufferSize];
                short[] chunkBuffer = new short[CHUNK_SAMPLES];
                int chunkFill = 0;
                while (isRecording && audioRecord != null) {
                    int read = audioRecord.read(readBuffer, 0, bufferSize);
                    if (read <= 0) {
                        continue;
                    }
                    int offset = 0;
                    while (offset < read) {
                        int toCopy = Math.min(CHUNK_SAMPLES - chunkFill, read - offset);
                        System.arraycopy(readBuffer, offset, chunkBuffer, chunkFill, toCopy);
                        chunkFill += toCopy;
                        offset += toCopy;
                        if (chunkFill == CHUNK_SAMPLES) {
                            notifyAudioData(shortArrayToByteArray(chunkBuffer, CHUNK_SAMPLES));
                            chunkFill = 0;
                        }
                    }
                }
                if (chunkFill > 0) {
                    notifyAudioData(shortArrayToByteArray(chunkBuffer, chunkFill));
                }
            });
            recordingThread.start();

            JSObject result = new JSObject();
            result.put("started", true);
            call.resolve(result);

        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR start: " + e.getMessage(), e);
            stopRecording();
            call.reject("Failed to start recording: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        FileLogger.log(TAG, "stop called");
        stopRecording();
        JSObject result = new JSObject();
        result.put("stopped", true);
        call.resolve(result);
    }

    private void enableAudioEffects(int audioSessionId) {
        FileLogger.log(TAG, "AudioRecord sessionId=" + audioSessionId
                + " aecAvailable=" + AcousticEchoCanceler.isAvailable()
                + " nsAvailable=" + NoiseSuppressor.isAvailable()
                + " agcAvailable=" + AutomaticGainControl.isAvailable());
        if (AcousticEchoCanceler.isAvailable()) {
            echoCanceler = AcousticEchoCanceler.create(audioSessionId);
            if (echoCanceler != null) {
                int result = echoCanceler.setEnabled(true);
                FileLogger.log(TAG, "AEC enabled=" + echoCanceler.getEnabled() + " result=" + result);
            } else {
                FileLogger.log(TAG, "AEC create returned null");
            }
        }
        if (NoiseSuppressor.isAvailable()) {
            noiseSuppressor = NoiseSuppressor.create(audioSessionId);
            if (noiseSuppressor != null) {
                int result = noiseSuppressor.setEnabled(true);
                FileLogger.log(TAG, "NS enabled=" + noiseSuppressor.getEnabled() + " result=" + result);
            } else {
                FileLogger.log(TAG, "NS create returned null");
            }
        }
        if (AutomaticGainControl.isAvailable()) {
            automaticGainControl = AutomaticGainControl.create(audioSessionId);
            if (automaticGainControl != null) {
                int result = automaticGainControl.setEnabled(true);
                FileLogger.log(TAG, "AGC enabled=" + automaticGainControl.getEnabled() + " result=" + result);
            } else {
                FileLogger.log(TAG, "AGC create returned null");
            }
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
                releaseAudioEffects();
                audioRecord.release();
            } catch (Exception e) {
                // ignore
            }
            audioRecord = null;
        }
    }

    private void releaseAudioEffects() {
        if (echoCanceler != null) {
            echoCanceler.release();
            echoCanceler = null;
            FileLogger.log(TAG, "AEC released");
        }
        if (noiseSuppressor != null) {
            noiseSuppressor.release();
            noiseSuppressor = null;
            FileLogger.log(TAG, "NS released");
        }
        if (automaticGainControl != null) {
            automaticGainControl.release();
            automaticGainControl = null;
            FileLogger.log(TAG, "AGC released");
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

    @Override
    protected void handleOnDestroy() {
        stopRecording();
        super.handleOnDestroy();
    }
}
