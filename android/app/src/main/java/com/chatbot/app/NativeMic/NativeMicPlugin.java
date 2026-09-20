package com.chatbot.app;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.PowerManager;
import android.provider.Settings;
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
import com.chatbot.app.audio.VoiceModeSessionCoordinator;
import com.chatbot.app.audio.VoiceSessionKeepAwake;
import com.chatbot.app.util.ClientLogReporter;
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
import java.util.concurrent.atomic.AtomicLong;

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

    private volatile AudioRecord audioRecord = null;
    private volatile boolean isRecording = false;
    private Thread recordingThread = null;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private AudioManager audioManager = null;
    private AudioFocusRequest audioFocusRequest = null;
    private boolean hasAudioFocus = false;
    /** Drops PCM callbacks queued before notification Stop or a recorder restart. */
    private final AtomicLong recordingGeneration = new AtomicLong(0);
    private final VoiceAudioRoute.Backend voiceAudioBackend = new AudioManagerBackend();
    private final VoiceSessionKeepAwake.Backend keepAwakeBackend = new ActivityKeepAwakeBackend();
    private final VoiceModeForegroundSession.Backend foregroundBackend = new ForegroundServiceBackend();
    /** Owned voice-mode session: route + keep-awake + FGS + phone/notification coordination. */
    private final VoiceModeSessionCoordinator sessionCoordinator = new VoiceModeSessionCoordinator(
            voiceAudioBackend, keepAwakeBackend, foregroundBackend,
            new CoordinatorMic(), new CoordinatorTts(),
            new CoordinatorEvents(), new CoordinatorPlatform());
    private AcousticEchoCanceler echoCanceler = null;
    private AutomaticGainControl automaticGainControl = null;
    private static boolean batteryExemptionPrompted;
    private boolean modeListenerRegistered;
    private AudioManager.OnModeChangedListener modeChangedListener;
    private static volatile NativeMicPlugin instance;

    @Override
    public void load() {
        super.load();
        instance = this;
        FileLogger.init(getContext().getApplicationContext());
        FileLogger.log(TAG, "NativeMicPlugin.load()");
        audioManager = (AudioManager) getContext().getSystemService(Context.AUDIO_SERVICE);
        VoiceModeNativeHooks.setHandler(this::stopFromNotification);
        VoiceModeNativeHooks.setKeepAliveHandler(this::keepVoiceWebViewRunning);
        registerModeListener();
    }

    public static void reclaimAudioFocusIfPresent() {
        NativeMicPlugin plugin = instance;
        if (plugin != null) {
            plugin.reclaimAudioFocus();
        }
    }

    public static boolean hasBluetoothAudioPresent() {
        NativeMicPlugin plugin = instance;
        return plugin != null && plugin.voiceAudioBackend != null && plugin.voiceAudioBackend.hasBluetoothAudio();
    }

    /** Actual voice-route ownership for TTS playback selection (not foreground state). */
    public static boolean isVoiceRouteActive() {
        NativeMicPlugin plugin = instance;
        return plugin != null
                && plugin.sessionCoordinator != null
                && plugin.sessionCoordinator.isRouteActive();
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
        if (!granted) {
            ClientLogReporter.report("VOICE-ERROR", "voice: microphone permission denied");
        }
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
            ClientLogReporter.report("VOICE-ERROR", "voice: mic start rejected, no permission");
            call.reject("Microphone permission not granted");
            return;
        }

        int bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT);
        if (bufferSize == AudioRecord.ERROR || bufferSize == AudioRecord.ERROR_BAD_VALUE) {
            Log.e(TAG, "Invalid buffer size: " + bufferSize);
            ClientLogReporter.report("VOICE-ERROR", "voice: mic start rejected, bad buffer size");
            call.reject("Unable to get minimum buffer size");
            return;
        }

        try {
            Log.d(TAG, "Creating AudioRecord...");
            // VOICE_COMMUNICATION: speakerphone/VoIP uplink with hardware AEC/AGC.
            final AudioRecord recording = new AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
                .setAudioFormat(new AudioFormat.Builder()
                    .setEncoding(AUDIO_FORMAT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(CHANNEL_CONFIG)
                    .build())
                .setBufferSizeInBytes(bufferSize * 4)
                .build();
            audioRecord = recording;

            if (recording.getState() != AudioRecord.STATE_INITIALIZED) {
                ClientLogReporter.report("VOICE-ERROR", "voice: AudioRecord failed to initialize");
                call.reject("AudioRecord failed to initialize");
                recording.release();
                audioRecord = null;
                return;
            }

            FileLogger.log(TAG, "AudioRecord source=" + recording.getAudioSource()
                    + " routeActive=" + sessionCoordinator.isRouteActive());
            enableAudioEffects(recording.getAudioSessionId());

            long generation = recordingGeneration.incrementAndGet();
            recording.startRecording();
            isRecording = true;

            recordingThread = new Thread(() -> {
                short[] readBuffer = new short[bufferSize];
                short[] chunkBuffer = new short[CHUNK_SAMPLES];
                int chunkFill = 0;
                while (isRecording && audioRecord == recording) {
                    int read = recording.read(readBuffer, 0, bufferSize);
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
                            notifyAudioData(shortArrayToByteArray(chunkBuffer, CHUNK_SAMPLES), generation);
                            chunkFill = 0;
                        }
                    }
                }
                if (chunkFill > 0) {
                    notifyAudioData(shortArrayToByteArray(chunkBuffer, chunkFill), generation);
                }
            });
            recordingThread.start();

            JSObject result = new JSObject();
            result.put("started", true);
            ClientLogReporter.report("VOICE", "voice: mic capture started routeActive="
                    + sessionCoordinator.isRouteActive());
            call.resolve(result);

        } catch (Exception e) {
            FileLogger.log(TAG, "ERROR start: " + e.getMessage(), e);
            ClientLogReporter.report("VOICE-ERROR", "voice: mic start threw");
            stopRecording();
            call.reject("Failed to start recording: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        FileLogger.log(TAG, "stop called");
        ClientLogReporter.report("VOICE", "voice: mic stopped");
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
        VoiceModeSessionCoordinator.EnterResult entered =
                sessionCoordinator.enterVoiceSession();
        FileLogger.log(TAG, "enterVoiceRoute applied=" + entered.applied
                + " active=" + entered.active + " bluetooth=" + entered.bluetooth
                + " keepAwake=" + entered.keepAwake + " foreground=" + entered.foreground
                + " foregroundConfirmed=" + entered.foregroundConfirmed);
        ClientLogReporter.report("VOICE", "voice: enterVoiceRoute applied=" + entered.applied
                + " active=" + entered.active + " bluetooth=" + entered.bluetooth
                + " keepAwake=" + entered.keepAwake + " foreground=" + entered.foreground
                + " foregroundConfirmed=" + entered.foregroundConfirmed);
        JSObject result = new JSObject();
        result.put("applied", entered.applied);
        result.put("active", entered.active);
        result.put("bluetooth", entered.bluetooth);
        result.put("keepAwake", entered.keepAwake);
        result.put("keepAwakeActive", entered.keepAwakeActive);
        result.put("foreground", entered.foreground);
        result.put("foregroundActive", entered.foregroundActive);
        result.put("foregroundConfirmed", entered.foregroundConfirmed);
        call.resolve(result);
    }

    /** Restore pre-voice-mode routing. Idempotent; only voice-mode teardown should call this. */
    @PluginMethod
    public void exitVoiceRoute(PluginCall call) {
        VoiceModeSessionCoordinator.ExitResult exited = sessionCoordinator.exitVoiceSession();
        boolean applied = exited.applied;
        boolean keepAwake = exited.keepAwake;
        boolean foreground = exited.foreground;
        FileLogger.log(TAG, "exitVoiceRoute applied=" + applied + " active=" + exited.active
                + " keepAwake=" + keepAwake + " foreground=" + foreground);
        JSObject result = new JSObject();
        result.put("applied", exited.applied);
        result.put("active", exited.active);
        result.put("keepAwake", exited.keepAwake);
        result.put("keepAwakeActive", exited.keepAwakeActive);
        result.put("foreground", exited.foreground);
        result.put("foregroundActive", exited.foregroundActive);
        result.put("foregroundConfirmed", exited.foregroundConfirmed);
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
                    if (change == AudioManager.AUDIOFOCUS_LOSS
                            || change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT) {
                        hasAudioFocus = false;
                    } else if (change == AudioManager.AUDIOFOCUS_GAIN) {
                        hasAudioFocus = true;
                    }
                    if (!sessionCoordinator.isTtsSessionActive()) {
                        onAudioModeOrFocusChanged();
                    }
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
            try {
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
            } catch (Exception e) {
                FileLogger.log(TAG, "hasBluetoothAudio check failed: " + e.getMessage(), e);
            }
            return false;
        }
    }

    private void registerModeListener() {
        if (modeListenerRegistered || audioManager == null) {
            return;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return;
        }
        try {
            modeChangedListener = this::onAudioModeChanged;
            audioManager.addOnModeChangedListener(getContext().getMainExecutor(), modeChangedListener);
            modeListenerRegistered = true;
            FileLogger.log(TAG, "OnModeChangedListener registered");
        } catch (Exception e) {
            modeChangedListener = null;
            FileLogger.log(TAG, "addOnModeChangedListener failed: " + e.getMessage(), e);
        }
    }

    private void unregisterModeListener() {
        if (!modeListenerRegistered || audioManager == null || modeChangedListener == null) {
            return;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return;
        }
        try {
            audioManager.removeOnModeChangedListener(modeChangedListener);
        } catch (Exception ignored) {
        }
        modeChangedListener = null;
        modeListenerRegistered = false;
    }

    private void onAudioModeChanged(int mode) {
        FileLogger.log(TAG, "onAudioModeChanged mode=" + mode);
        onAudioModeOrFocusChanged();
    }

    private void onAudioModeOrFocusChanged() {
        boolean inCall = audioManager != null
                && audioManager.getMode() == AudioManager.MODE_IN_CALL;
        if (inCall) {
            pauseForPhoneCall();
            return;
        }
        resumeAfterPhoneCall();
        reclaimAudioFocus();
    }

    void reclaimAudioFocus() {
        if (sessionCoordinator.isPausedForPhoneCall() || !sessionCoordinator.isRouteActive()) {
            return;
        }
        if (hasAudioFocus) {
            return;
        }
        if (sessionCoordinator.isTtsSessionActive()) {
            return;
        }
        requestAudioFocus();
    }

    private void pauseForPhoneCall() {
        if (sessionCoordinator.isPausedForPhoneCall()) {
            return;
        }
        if (!sessionCoordinator.isRouteActive() && !isRecording) {
            return;
        }
        FileLogger.log(TAG, "pauseForPhoneCall");
        sessionCoordinator.pauseForPhoneCall();
    }

    private void resumeAfterPhoneCall() {
        if (!sessionCoordinator.isPausedForPhoneCall()) {
            return;
        }
        FileLogger.log(TAG, "resumeAfterPhoneCall");
        sessionCoordinator.resumeAfterPhoneCall();
    }

    void stopFromNotification() {
        FileLogger.log(TAG, "stopFromNotification");
        sessionCoordinator.notificationStop();
    }

    private void requestUnrestrictedBattery() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return;
        }
        Context ctx = getContext();
        if (ctx == null) {
            return;
        }
        PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
        if (pm == null || pm.isIgnoringBatteryOptimizations(ctx.getPackageName())) {
            return;
        }
        if (batteryExemptionPrompted) {
            return;
        }
        Activity activity = getActivity();
        if (activity == null) {
            return;
        }
        batteryExemptionPrompted = true;
        Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
        intent.setData(Uri.parse("package:" + ctx.getPackageName()));
        try {
            activity.startActivity(intent);
            FileLogger.log(TAG, "requested ignore battery optimizations");
        } catch (Exception e) {
            FileLogger.log(TAG, "battery exemption prompt failed: " + e.getMessage(), e);
        }
    }

    private void keepVoiceWebViewRunning() {
        reclaimAudioFocus();
        Activity activity = getActivity();
        if (activity instanceof MainActivity) {
            activity.runOnUiThread(((MainActivity) activity)::keepVoiceWebViewRunning);
        }
    }

    private final class ForegroundServiceBackend implements VoiceModeForegroundSession.Backend {
        @Override
        public boolean startForeground() {
            return startForeground(VoiceModeForegroundSession.get().currentGeneration());
        }

        @Override
        public boolean startForeground(long generation) {
            Context ctx = getContext();
            if (ctx == null) {
                return false;
            }
            try {
                // Honest request acceptance: true means the platform start was
                // issued for this exact generation, not that the service is
                // foregrounded. Confirmation arrives asynchronously via the
                // session generation token.
                return VoiceModeForegroundService.start(ctx, generation);
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
                return VoiceModeForegroundService.stop(ctx)
                        != VoiceModeForegroundSession.Backend.StopOutcome.FAILED;
            } catch (Exception e) {
                FileLogger.log(TAG, "stopForeground failed: " + e.getMessage(), e);
                return false;
            }
        }

        @Override
        public VoiceModeForegroundSession.Backend.StopOutcome stopForeground(
                long generation) {
            Context ctx = getContext();
            if (ctx == null) {
                return VoiceModeForegroundSession.Backend.StopOutcome.FAILED;
            }
            try {
                return VoiceModeForegroundService.stop(ctx, generation);
            } catch (Exception e) {
                FileLogger.log(TAG, "stopForeground failed: " + e.getMessage(), e);
                return VoiceModeForegroundSession.Backend.StopOutcome.FAILED;
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
        recordingGeneration.incrementAndGet();
        isRecording = false;
        AudioRecord recording = audioRecord;
        if (recording != null) {
            try {
                if (recording.getState() == AudioRecord.STATE_INITIALIZED) {
                    // Interrupt a blocking read before waiting for the worker.
                    recording.stop();
                }
            } catch (Exception ignored) {
            }
        }
        Thread worker = recordingThread;
        if (worker != null) {
            try {
                worker.join(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (recordingThread == worker) {
                recordingThread = null;
            }
        }
        if (recording != null && audioRecord == recording) {
            try {
                releaseAudioEffects();
                recording.release();
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

    private void notifyAudioData(byte[] pcmData, long generation) {
        mainHandler.post(() -> {
            if (!isRecording || generation != recordingGeneration.get()) {
                return;
            }
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

    private final class CoordinatorMic implements VoiceModeSessionCoordinator.MicControl {
        @Override
        public void stopCapture() {
            stopRecording();
        }

        @Override
        public boolean isCapturing() {
            return isRecording;
        }
    }

    /**
     * Composition-time TTS adapter: delegates to the existing
     * NativeVoiceTtsPlugin statics at call time, so mic reload while TTS
     * exists (or vice versa) cannot lose control or capture a destroyed
     * plugin instance.
     */
    private final class CoordinatorTts implements VoiceModeSessionCoordinator.TtsControl {
        @Override
        public void stopPlayback() {
            NativeVoiceTtsPlugin.stopIfPresent();
        }

        @Override
        public boolean isSessionActive() {
            return NativeVoiceTtsPlugin.isSessionActive();
        }
    }

    private final class CoordinatorEvents implements VoiceModeSessionCoordinator.SessionEvents {
        @Override
        public void notifyPhoneCall(boolean active, long transitionId) {
            JSObject ret = new JSObject();
            ret.put("type", "phoneCall");
            ret.put("active", active);
            ret.put("transitionId", transitionId);
            notifyListeners("voiceModePhoneCall", ret);
        }

        @Override
        public void notifyNotificationStop(long transitionId) {
            JSObject ret = new JSObject();
            ret.put("type", "stop");
            ret.put("transitionId", transitionId);
            notifyListeners("voiceModeStopRequested", ret);
        }

        @Override
        public void evalJs(String script) {
            if (getBridge() != null) {
                getBridge().eval(script, null);
            }
        }
    }

    private final class CoordinatorPlatform implements VoiceModeSessionCoordinator.PlatformHooks {
        @Override
        public void requestBatteryExemption() {
            requestUnrestrictedBattery();
        }

        @Override
        public void keepWebViewAlive() {
            keepVoiceWebViewRunning();
        }
    }

    @Override
    protected void handleOnDestroy() {
        VoiceModeNativeHooks.setHandler(null);
        VoiceModeNativeHooks.setKeepAliveHandler(null);
        unregisterModeListener();
        sessionCoordinator.destroy();
        super.handleOnDestroy();
    }
}
