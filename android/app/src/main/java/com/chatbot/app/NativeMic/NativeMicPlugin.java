package com.chatbot.app;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.media.AudioAttributes;
import android.media.AudioDeviceInfo;
import android.media.AudioFocusRequest;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.media.audiofx.AcousticEchoCanceler;
import android.media.audiofx.AutomaticGainControl;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import androidx.core.content.ContextCompat;

import com.chatbot.app.audio.VoiceAudioRoute;
import com.chatbot.app.audio.VoiceModeForegroundService;
import com.chatbot.app.audio.VoiceModeForegroundSession;
import com.chatbot.app.audio.VoiceModeNativeHooks;
import com.chatbot.app.audio.VoiceSessionKeepAwake;
import com.chatbot.app.util.FileLogger;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@CapacitorPlugin(
    name = "NativeMic",
    permissions = {
        @Permission(alias = "microphone", strings = { Manifest.permission.RECORD_AUDIO }),
        @Permission(alias = "notifications", strings = { Manifest.permission.POST_NOTIFICATIONS })
    }
)
public class NativeMicPlugin extends Plugin {
    private static final String TAG = "NativeMicPlugin";
    private static final String MIC_ALIAS = "microphone";
    private static final String NOTIF_ALIAS = "notifications";

    public NativeMicPlugin() {
        Log.d(TAG, "NativeMicPlugin constructor called");
    }

    private static final int SAMPLE_RATE = 16000;
    /** Fixed 20 ms frames for steady JS consumption (320 samples * 2 bytes). */
    private static final int CHUNK_SAMPLES = 320;
    private static final int CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO;
    private static final int AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT;

    private AudioRecord audioRecord = null;
    private boolean isRecording = false;
    private Thread recordingThread = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private AudioManager audioManager = null;
    private AudioFocusRequest audioFocusRequest = null;
    private boolean hasAudioFocus = false;
    private final VoiceAudioRoute voiceAudioRoute = new VoiceAudioRoute();
    private final VoiceAudioRoute.Backend voiceAudioBackend = new AudioManagerBackend();
    private final VoiceSessionKeepAwake voiceSessionKeepAwake = new VoiceSessionKeepAwake();
    private final VoiceSessionKeepAwake.Backend keepAwakeBackend = new ActivityKeepAwakeBackend();
    private final VoiceModeForegroundSession voiceForeground = VoiceModeForegroundSession.get();
    private final VoiceModeForegroundSession.Backend foregroundBackend = new ForegroundServiceBackend();
    private AcousticEchoCanceler echoCanceler = null;
    private AutomaticGainControl automaticGainControl = null;

    @Override
    public void load() {
        super.load();
        FileLogger.init(getContext().getApplicationContext());
        FileLogger.log(TAG, "NativeMicPlugin.load()");
        audioManager = (AudioManager) getContext().getSystemService(Context.AUDIO_SERVICE);
        VoiceModeNativeHooks.setHandler(this::stopFromNotification);
        VoiceModeNativeHooks.setKeepAliveHandler(this::keepVoiceWebViewRunning);
    }

    @PluginMethod
    public void requestPermission(PluginCall call) {
        Log.d(TAG, "requestPermission called");
        if (hasMicPermission()) {
            Log.d(TAG, "Permission already granted");
            resolvePermission(call, true);
            return;
        }
        Log.d(TAG, "Requesting permission");
        FileLogger.log(TAG, "requestPermission: prompting RECORD_AUDIO");
        requestPermissionForAlias(MIC_ALIAS, call, "onMicrophonePermission");
    }

    @PermissionCallback
    private void onMicrophonePermission(PluginCall call) {
        boolean granted = hasMicPermission();
        Log.d(TAG, "onMicrophonePermission granted=" + granted);
        FileLogger.log(TAG, "onMicrophonePermission granted=" + granted);
        resolvePermission(call, granted);
    }

    @PermissionCallback
    private void startAfterPermission(PluginCall call) {
        if (call == null) {
            FileLogger.log(TAG, "startAfterPermission: no saved call");
            return;
        }
        if (!hasMicPermission()) {
            FileLogger.log(TAG, "startAfterPermission: denied");
            call.reject("Microphone permission not granted");
            return;
        }
        startRecording(call);
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
        if (!hasMicPermission()) {
            FileLogger.log(TAG, "start: prompting RECORD_AUDIO");
            requestPermissionForAlias(MIC_ALIAS, call, "startAfterPermission");
            return;
        }
        startRecording(call);
    }

    private void startRecording(PluginCall call) {
        if (isRecording) {
            // Capacitor reload leaves the plugin recording after JS is gone.
            // Take ownership of a fresh session instead of rejecting.
            FileLogger.log(TAG, "start: already recording, restarting capture");
            stopRecording();
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
            // VOICE_COMMUNICATION: speakerphone/VoIP uplink with hardware AEC/AGC.
            audioRecord = new AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
                .setAudioFormat(new AudioFormat.Builder()
                    .setEncoding(AUDIO_FORMAT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(CHANNEL_CONFIG)
                    .build())
                .setBufferSizeInBytes(bufferSize * 4)
                .build();

            if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
                call.reject("AudioRecord failed to initialize");
                audioRecord.release();
                audioRecord = null;
                return;
            }

            FileLogger.log(TAG, "AudioRecord source=" + audioRecord.getAudioSource()
                    + " routeActive=" + voiceAudioRoute.isActive());
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

    /** Speakerphone routing for Capacitor voice mode. Idempotent; only the voice-mode button should call this. */
    @PluginMethod
    public void enterVoiceRoute(PluginCall call) {
        if (shouldRequestNotificationPermission()) {
            FileLogger.log(TAG, "enterVoiceRoute: prompting POST_NOTIFICATIONS");
            requestPermissionForAlias(NOTIF_ALIAS, call, "onNotificationPermissionForVoiceRoute");
            return;
        }
        completeEnterVoiceRoute(call);
    }

    @PermissionCallback
    private void onNotificationPermissionForVoiceRoute(PluginCall call) {
        FileLogger.log(TAG, "onNotificationPermissionForVoiceRoute granted="
                + hasNotificationPermission());
        completeEnterVoiceRoute(call);
    }

    private void completeEnterVoiceRoute(PluginCall call) {
        boolean bluetooth = voiceAudioBackend.hasBluetoothAudio();
        boolean applied = voiceAudioRoute.enter(voiceAudioBackend);
        boolean keepAwake = voiceSessionKeepAwake.enter(keepAwakeBackend);
        boolean foreground = voiceForeground.enter(foregroundBackend);
        keepVoiceWebViewRunning();
        FileLogger.log(TAG, "enterVoiceRoute applied=" + applied
                + " active=" + voiceAudioRoute.isActive() + " bluetooth=" + bluetooth
                + " keepAwake=" + keepAwake + " foreground=" + foreground);
        JSObject result = new JSObject();
        result.put("applied", applied);
        result.put("active", voiceAudioRoute.isActive());
        result.put("bluetooth", bluetooth);
        result.put("keepAwake", keepAwake);
        result.put("keepAwakeActive", voiceSessionKeepAwake.isActive());
        result.put("foreground", foreground);
        result.put("foregroundActive", voiceForeground.isActive());
        call.resolve(result);
    }

    /** Restore pre-voice-mode routing. Idempotent; only voice-mode teardown should call this. */
    @PluginMethod
    public void exitVoiceRoute(PluginCall call) {
        boolean applied = voiceAudioRoute.exit(voiceAudioBackend);
        boolean keepAwake = voiceSessionKeepAwake.exit(keepAwakeBackend);
        boolean foreground = voiceForeground.exit(foregroundBackend);
        FileLogger.log(TAG, "exitVoiceRoute applied=" + applied + " active=" + voiceAudioRoute.isActive()
                + " keepAwake=" + keepAwake + " foreground=" + foreground);
        JSObject result = new JSObject();
        result.put("applied", applied);
        result.put("active", voiceAudioRoute.isActive());
        result.put("keepAwake", keepAwake);
        result.put("keepAwakeActive", voiceSessionKeepAwake.isActive());
        result.put("foreground", foreground);
        result.put("foregroundActive", voiceForeground.isActive());
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

    private AudioDeviceInfo findBuiltInSpeaker() {
        if (audioManager == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null;
        }
        for (AudioDeviceInfo device : audioManager.getAvailableCommunicationDevices()) {
            if (device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
                return device;
            }
        }
        for (AudioDeviceInfo device : audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
            if (device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
                return device;
            }
        }
        return null;
    }

    private final class AudioManagerBackend implements VoiceAudioRoute.Backend {
        @Override
        public int getMode() {
            return audioManager != null ? audioManager.getMode() : AudioManager.MODE_NORMAL;
        }

        @Override
        public void setMode(int mode) {
            if (audioManager != null) {
                audioManager.setMode(mode);
                FileLogger.log(TAG, "setMode " + mode + " current=" + audioManager.getMode());
            }
        }

        @Override
        public boolean isSpeakerphoneOn() {
            return audioManager != null && audioManager.isSpeakerphoneOn();
        }

        @Override
        public void setSpeakerphoneOn(boolean on) {
            if (audioManager != null) {
                audioManager.setSpeakerphoneOn(on);
            }
        }

        @Override
        public int getVoiceCallVolume() {
            if (audioManager == null) {
                return -1;
            }
            return audioManager.getStreamVolume(AudioManager.STREAM_VOICE_CALL);
        }

        @Override
        public int getVoiceCallMaxVolume() {
            if (audioManager == null) {
                return 0;
            }
            return audioManager.getStreamMaxVolume(AudioManager.STREAM_VOICE_CALL);
        }

        @Override
        public void setVoiceCallVolume(int index) {
            if (audioManager != null && index >= 0) {
                audioManager.setStreamVolume(AudioManager.STREAM_VOICE_CALL, index, 0);
            }
        }

        @Override
        public boolean requestCommunicationFocus() {
            requestAudioFocus();
            return hasAudioFocus;
        }

        @Override
        public void abandonCommunicationFocus() {
            abandonAudioFocus();
        }

        @Override
        public boolean supportsCommunicationDevice() {
            return audioManager != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S;
        }

        @Override
        public Object getCommunicationDevice() {
            if (!supportsCommunicationDevice()) {
                return null;
            }
            return audioManager.getCommunicationDevice();
        }

        @Override
        public boolean setCommunicationDeviceToSpeaker() {
            if (!supportsCommunicationDevice()) {
                return false;
            }
            AudioDeviceInfo speaker = findBuiltInSpeaker();
            if (speaker == null) {
                FileLogger.log(TAG, "setCommunicationDevice: no TYPE_BUILTIN_SPEAKER");
                return false;
            }
            boolean ok = audioManager.setCommunicationDevice(speaker);
            FileLogger.log(TAG, "setCommunicationDevice speaker id=" + speaker.getId() + " ok=" + ok);
            return ok;
        }

        @Override
        public void restoreCommunicationDevice(Object previous) {
            if (!supportsCommunicationDevice() || !(previous instanceof AudioDeviceInfo)) {
                return;
            }
            audioManager.setCommunicationDevice((AudioDeviceInfo) previous);
        }

        @Override
        public void clearCommunicationDevice() {
            if (supportsCommunicationDevice()) {
                audioManager.clearCommunicationDevice();
            }
        }

        @Override
        public boolean hasBluetoothAudio() {
            if (audioManager == null) {
                return false;
            }
            for (AudioDeviceInfo device : audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
                if (VoiceAudioRoute.isBluetoothOutputType(device.getType())) {
                    FileLogger.log(TAG, "bluetooth output type=" + device.getType()
                            + " id=" + device.getId());
                    return true;
                }
            }
            if (supportsCommunicationDevice()) {
                AudioDeviceInfo comm = audioManager.getCommunicationDevice();
                if (comm != null && VoiceAudioRoute.isBluetoothOutputType(comm.getType())) {
                    FileLogger.log(TAG, "bluetooth communication device type=" + comm.getType());
                    return true;
                }
            }
            if (audioManager.isBluetoothScoOn() || audioManager.isBluetoothA2dpOn()) {
                FileLogger.log(TAG, "bluetooth sco/a2dp flag on");
                return true;
            }
            return false;
        }
    }

    void stopFromNotification() {
        FileLogger.log(TAG, "stopFromNotification");
        if (getBridge() != null) {
            getBridge().eval("if (window.stopVoiceMode) window.stopVoiceMode();", null);
        }
        JSObject ret = new JSObject();
        ret.put("type", "stop");
        notifyListeners("voiceModeStopRequested", ret);
        NativeVoiceTtsPlugin.stopIfPresent();
        stopRecording();
        voiceAudioRoute.exit(voiceAudioBackend);
        voiceSessionKeepAwake.exit(keepAwakeBackend);
        voiceForeground.exit(foregroundBackend);
    }

    private void keepVoiceWebViewRunning() {
        Activity activity = getActivity();
        if (activity instanceof MainActivity) {
            activity.runOnUiThread(((MainActivity) activity)::keepVoiceWebViewRunning);
        }
    }

    private final class ForegroundServiceBackend implements VoiceModeForegroundSession.Backend {
        @Override
        public boolean startForeground() {
            Context ctx = getContext();
            if (ctx == null) {
                return false;
            }
            try {
                VoiceModeForegroundService.start(ctx);
                return true;
            } catch (Exception e) {
                FileLogger.log(TAG, "startForeground failed: " + e.getMessage(), e);
                return false;
            }
        }

        @Override
        public boolean stopForeground() {
            Context ctx = getContext();
            if (ctx == null) {
                return false;
            }
            try {
                VoiceModeForegroundService.stop(ctx);
                return true;
            } catch (Exception e) {
                FileLogger.log(TAG, "stopForeground failed: " + e.getMessage(), e);
                return false;
            }
        }
    }

    private final class ActivityKeepAwakeBackend implements VoiceSessionKeepAwake.Backend {
        @Override
        public boolean setKeepScreenOn(final boolean on) {
            Activity activity = getActivity();
            if (activity == null) {
                FileLogger.log(TAG, "setKeepScreenOn(" + on + ") skipped: no activity");
                return !on;
            }
            activity.runOnUiThread(() -> {
                Window window = activity.getWindow();
                if (window == null) {
                    FileLogger.log(TAG, "setKeepScreenOn(" + on + ") skipped: no window");
                    return;
                }
                if (on) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                }
                FileLogger.log(TAG, "FLAG_KEEP_SCREEN_ON=" + on);
            });
            return true;
        }
    }

    private void enableAudioEffects(int audioSessionId) {
        FileLogger.log(TAG, "AudioRecord sessionId=" + audioSessionId
                + " aecAvailable=" + AcousticEchoCanceler.isAvailable()
                + " agcAvailable=" + AutomaticGainControl.isAvailable());
        // Hardware AEC/AGC come with VOICE_COMMUNICATION. Attach software AEC/AGC as
        // backup. Do not attach NoiseSuppressor — stacked NS treats far speech as noise.
        if (AcousticEchoCanceler.isAvailable()) {
            echoCanceler = AcousticEchoCanceler.create(audioSessionId);
            if (echoCanceler != null) {
                int result = echoCanceler.setEnabled(true);
                FileLogger.log(TAG, "AEC enabled=" + echoCanceler.getEnabled() + " result=" + result);
            } else {
                FileLogger.log(TAG, "AEC create returned null");
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

    private boolean hasMicPermission() {
        PermissionState state = getPermissionState(MIC_ALIAS);
        if (state == PermissionState.GRANTED) {
            return true;
        }
        return ContextCompat.checkSelfPermission(getContext(), Manifest.permission.RECORD_AUDIO)
                == PackageManager.PERMISSION_GRANTED;
    }

    private boolean shouldRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return false;
        }
        if (hasNotificationPermission()) {
            return false;
        }
        return getPermissionState(NOTIF_ALIAS) != PermissionState.DENIED;
    }

    private boolean hasNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return true;
        }
        return ContextCompat.checkSelfPermission(getContext(), Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void resolvePermission(PluginCall call, boolean granted) {
        JSObject result = new JSObject();
        result.put("granted", granted);
        call.resolve(result);
    }

    @Override
    protected void handleOnDestroy() {
        VoiceModeNativeHooks.setHandler(null);
        VoiceModeNativeHooks.setKeepAliveHandler(null);
        stopRecording();
        voiceAudioRoute.exit(voiceAudioBackend);
        voiceSessionKeepAwake.exit(keepAwakeBackend);
        voiceForeground.exit(foregroundBackend);
        super.handleOnDestroy();
    }
}
