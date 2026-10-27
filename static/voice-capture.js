(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatVoiceCapture = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Owned browser voice capture: the native Capacitor PCM utterance VAD and
  // the desktop Silero VAD factory. Chat keeps DOM/event composition
  // (voice-mode session buttons, routes, wake locks, STT upload) and wires explicit adapters here; every capture need
  // arrives as an explicit injected hook, never a generic getter bag:
  // - nativeAudio: NativeAudio module (PCM helpers + SPEECH_* timing;
  //   thresholds live there, never redefined here)
  // - voiceLifecycle: single TTS owner (noteFrameProcessed barge-in gate,
  //   hasActiveVoiceSession/isInCooldown/snapshot utterance routing)
  // - now: clock adapter (Date.now)
  // - log/report/reportThrottled: nativeLog / reportVoice /
  //   reportVoiceThrottled adapters (key, windowMs, kind, message order kept)
  // - isVoiceModeActive: () => bool (voice-mode flag adapter)
  // - onBargeIn: handleBargeIn (stop TTS only on confident speech)
  // - onUtteranceEnd: native utterance completion (chat runs STT upload)
  // - onUtteranceStartedAt/captureBinding: utterance start handoff (chat
  //   amend-window state and conversation binding)
  // - recorder.ensurePermission/start/stop/addListener: NativeMic plugin
  //   adapters (permission helper fails closed on deny)
  // - registry.isCurrent/getStopPromise/setStopPromise: bridge-ownership and
  //   stop-rendezvous adapters (a stale bridge never stops a newer recorder;
  //   a replacement waits for an in-flight native stop)
  // - desktop host: vadLib (vad.MicVAD), nativeAudio, voiceLifecycle, now,
  //   log/report, onBargeIn, onUtteranceStartedAt/captureBinding, and
  //   onSpeechEnd(audio, binding) in place of onUtteranceEnd
  // No window/document access inside. Both platforms run the same
  // SileroUtteranceGate over Silero v5 scores.

// Silero utterance gate shared by native and desktop capture. Recording
// starts after SPEECH_START_MS of >=0.3 frames, follows 0.3/0.25 hysteresis,
// ends after SPEECH_END_SILENCE_MS of <=0.25 frames, and is rejected under
// SPEECH_MIN_ACTIVE_MS of speech. Barge-in is the lifecycle's confidence gate
// (voiceLifecycle.noteFrameProcessed), never an accumulated duration.
function SileroUtteranceGate() {}

SileroUtteranceGate.prototype._initGate = function (host) {
  this._host = host;
  this.preRollBuffer = new host.nativeAudio.Pcm16RingBuffer(host.nativeAudio.SPEECH_PREROLL_SAMPLES);
  this.utteranceChunks = [];
  this.utteranceBinding = null;
  this.inSpeech = false;
  this._resetSpeechCounters();
};

SileroUtteranceGate.prototype._resetSpeechCounters = function () {
  this.speechEvidenceMs = 0;
  this.modelSpeech = false;
  this.startGateChunks = [];
  this.silenceMs = 0;
  this.speechActiveMs = 0;
};

SileroUtteranceGate.prototype._onSileroFrame = function _onSileroFrame(copy, probability, durationMs) {
  var host = this._host;
  if (host.voiceLifecycle.noteFrameProcessed(probability)) {
    host.log('VAD', 'barge-in on Silero confidence');
    host.onBargeIn();
  }
  if (this.inSpeech) {
    this._accumulateUtterance(copy, probability, durationMs);
  } else if (probability >= 0.3) {
    this.startGateChunks.push(copy);
    this.speechEvidenceMs += durationMs;
    if (this.speechEvidenceMs >= host.nativeAudio.SPEECH_START_MS) this._beginUtterance();
  } else if (probability <= 0.25) {
    this.speechEvidenceMs = 0;
    this.startGateChunks = [];
  }
};

SileroUtteranceGate.prototype._accumulateUtterance = function _accumulateUtterance(copy, probability, durationMs) {
  var host = this._host;
  this.utteranceChunks.push(copy);
  if (probability >= 0.3) this.modelSpeech = true;
  else if (probability <= 0.25) this.modelSpeech = false;
  if (this.modelSpeech) {
    this.silenceMs = 0;
    this.speechActiveMs += durationMs;
  } else if (probability <= 0.25) {
    this.silenceMs += durationMs;
    if (this.silenceMs >= host.nativeAudio.SPEECH_END_SILENCE_MS) this._endUtterance();
  }
};

SileroUtteranceGate.prototype._beginUtterance = function _beginUtterance() {
  var host = this._host;
  if (this.inSpeech) return;
  this.inSpeech = true;
  const startChunks = this.startGateChunks;
  const initialSpeechMs = this.speechEvidenceMs;
  this._resetSpeechCounters();
  this.modelSpeech = true;
  this.utteranceStartedAt = host.now();
  this.utteranceBinding = host.captureBinding ? host.captureBinding() : null;
  host.onUtteranceStartedAt(this.utteranceStartedAt);
  this.speechActiveMs = initialSpeechMs;
  const preRoll = this.preRollBuffer.snapshotChunks();
  this.utteranceChunks = preRoll.length ? preRoll : startChunks;
  host.log('VAD', 'utterance begin (startChunks=' + startChunks.length + ' preRoll=' + this.utteranceChunks.length + ')');
};

SileroUtteranceGate.prototype._endUtterance = function _endUtterance() {
  var host = this._host;
  if (!this.inSpeech) return;
  this.inSpeech = false;
  const speechActiveMs = this.speechActiveMs;
  this._resetSpeechCounters();
  if (speechActiveMs < host.nativeAudio.SPEECH_MIN_ACTIVE_MS) {
    host.log('VAD', 'utterance rejected: speechActiveMs=' + speechActiveMs
      + ' min=' + host.nativeAudio.SPEECH_MIN_ACTIVE_MS);
    host.report('VOICE', 'utterance rejected too short speechMs=' + speechActiveMs);
    this.utteranceChunks = [];
    this.utteranceBinding = null;
    return;
  }
  host.log('VAD', 'utterance end chunks=' + this.utteranceChunks.length
    + ' speechMs=' + speechActiveMs);
  host.report('VOICE', 'utterance end chunks=' + this.utteranceChunks.length
    + ' speechMs=' + speechActiveMs);
  const binding = this.utteranceBinding;
  this.utteranceBinding = null;
  this._completeUtterance(binding);
};

function NativeMicUtteranceVAD(host, onError) {
  this._initGate(host);
  this.onError = onError;
  this.completedBinding = null;
  this.nativeListener = null;
  this.nativeErrorListener = null;
  this.isRecording = false;
  this.vadFailed = false;
  this.chunkCount = 0;
  this._firstFrameReported = false;
}
NativeMicUtteranceVAD.prototype = Object.create(SileroUtteranceGate.prototype);
NativeMicUtteranceVAD.prototype.constructor = NativeMicUtteranceVAD;

NativeMicUtteranceVAD.prototype._completeUtterance = function (binding) {
  this.completedBinding = binding;
  this._host.onUtteranceEnd(binding);
};

NativeMicUtteranceVAD.prototype._onNativePcm = function _onNativePcm(pcm16, probability, durationMs) {
  var host = this._host;
  if (!this.isRecording || !host.isVoiceModeActive()) {
    host.reportThrottled('pcm-dropped', 10000, 'VOICE-ERROR',
      'dropping PCM frames isRecording=' + this.isRecording
      + ' voiceModeActive=' + !!host.isVoiceModeActive()
      + ' chunks=' + this.chunkCount);
    return;
  }
  if (durationMs !== 0 && durationMs !== 32) return this._failVad('invalid Silero frame duration');
  if (durationMs === 32 && (typeof probability !== 'number' || !Number.isFinite(probability)
      || probability < 0 || probability > 1)) return this._failVad('missing Silero probability');
  if (durationMs === 0 && probability != null) return this._failVad('probability without fresh Silero frame');
  if (!this._firstFrameReported) {
    this._firstFrameReported = true;
    host.report('VOICE', 'first PCM frame received, capture live');
  }
  const copy = pcm16.slice();
  this.preRollBuffer.push(copy);
  this.chunkCount++;
  if (durationMs === 0) {
    if (this.inSpeech) this.utteranceChunks.push(copy);
    return;
  }

  const ttsSession = host.voiceLifecycle.hasActiveVoiceSession();
  if (!ttsSession && host.voiceLifecycle.isInCooldown()) return;
  this._onSileroFrame(copy, probability, durationMs);
  if (this.chunkCount % 50 === 0) host.log('VAD', 'pcm#' + this.chunkCount
    + ' ttsSess=' + (ttsSession ? 1 : 0) + ' ttsPlay=' + host.voiceLifecycle.snapshot().playing
    + ' inSpeech=' + this.inSpeech + ' speechMs=' + this.speechActiveMs);
};

NativeMicUtteranceVAD.prototype._failVad = function _failVad(message) {
  var host = this._host;
  if (this.vadFailed || !host.registry.isCurrent(this)) return;
  this.vadFailed = true;
  this.isRecording = false;
  host.log('VAD', 'native Silero data error: ' + message);
  host.report('VOICE-ERROR', 'native Silero data error: ' + message);
  try {
    if (typeof this.onError === 'function') this.onError(message);
  } finally {
    this.stop();
  }
};

NativeMicUtteranceVAD.prototype.takeSpeechPcm16 = function () {
  var host = this._host;
  const pcm16 = host.nativeAudio.mergePcm16Chunks(this.utteranceChunks);
  this.utteranceChunks = [];
  this.completedBinding = null;
  return pcm16;
};

NativeMicUtteranceVAD.prototype.takeSpeechWavBlob = function () {
  var host = this._host;
  const pcm16 = this.takeSpeechPcm16();
  return host.nativeAudio.pcm16ToWavBlob(pcm16);
};

NativeMicUtteranceVAD.prototype.hasSpeechCapture = function () {
  return this.utteranceChunks.length > 0;
};

NativeMicUtteranceVAD.prototype.hasCompletedSpeechCapture = function () {
  return !this.inSpeech && this.utteranceChunks.length > 0;
};

NativeMicUtteranceVAD.prototype.start = async function () {
  var host = this._host;
  const self = this;
  if (!host.nativeAudio) {
    throw new Error('native-audio.js not loaded');
  }
  try {
    host.log('VAD', 'NativeMicUtteranceVAD start (native Silero)');
    this.preRollBuffer.clear();
    this.utteranceChunks = [];
    this.completedBinding = null;
    this.startGateChunks = [];
    this.inSpeech = false;
    this._resetSpeechCounters();
    this.vadFailed = false;
    this.chunkCount = 0;
    this._firstFrameReported = false;

    if (!host.registry.isCurrent(this)) {
      throw new Error('native VAD start superseded');
    }
    if (host.registry.getStopPromise()) {
      await host.registry.getStopPromise();
    }
    if (!host.registry.isCurrent(this)) {
      throw new Error('native VAD start superseded');
    }
    await host.recorder.ensurePermission();
    if (!host.registry.isCurrent(this)) {
      throw new Error('native VAD start superseded');
    }
    this.nativeListener = host.recorder.addListener('nativeMicData', function (data) {
      if (!self.isRecording || !host.isVoiceModeActive()) return;
      if (!data || !data.data) return;
      try {
        self._onNativePcm(host.nativeAudio.decodeNativePcmBase64(data.data), data.vadProbability, data.vadDurationMs);
      } catch (err) {
        host.log('VAD', 'PCM decode error: ' + err.message);
      }
    });
    this.nativeErrorListener = host.recorder.addListener('nativeMicError', function (data) {
      if (!self.isRecording || !data || data.type !== 'vadError') return;
      self._failVad(data.message || 'Native Silero inference failed');
    });
    this.isRecording = true;
    try {
      const result = await host.recorder.start({ vad: true });
      if (!result || result.vadEnabled !== true) {
        if (host.registry.isCurrent(this)) await host.recorder.stop();
        const unavailable = new Error('Native Silero VAD unavailable; update the app');
        unavailable.noRetry = true;
        throw unavailable;
      }
    } catch (first) {
      const firstMsg = first && first.message ? first.message : String(first);
      if (/permission/i.test(firstMsg) || (first && first.noRetry)) throw first;
      host.log('VAD', 'NativeMic.start retry after: ' + firstMsg);
      this.isRecording = false;
      if (!host.registry.isCurrent(this)) {
        throw new Error('native VAD start superseded');
      }
      const retryStopPromise = Promise.resolve().then(function () {
        return host.recorder.stop();
      });
      host.registry.setStopPromise(retryStopPromise);
      try {
        await retryStopPromise;
      } finally {
        if (host.registry.getStopPromise() === retryStopPromise) {
          host.registry.setStopPromise(null);
        }
      }
      if (!host.registry.isCurrent(this)) {
        throw new Error('native VAD start superseded');
      }
      this.isRecording = true;
      const result = await host.recorder.start({ vad: true });
      if (!result || result.vadEnabled !== true) {
        if (host.registry.isCurrent(this)) await host.recorder.stop();
        throw new Error('Native Silero VAD unavailable; update the app');
      }
    }

    if (!host.registry.isCurrent(this)) {
      throw new Error('native VAD start superseded');
    }
    host.report('VOICE', 'native VAD capture started');
  } catch (err) {
    this.isRecording = false;
    if (this.nativeListener) {
      this.nativeListener.remove();
      this.nativeListener = null;
    }
    if (this.nativeErrorListener) {
      this.nativeErrorListener.remove();
      this.nativeErrorListener = null;
    }
    host.log('VAD', 'NativeMicUtteranceVAD start failed: ' + (err && err.message ? err.message : err));
    host.report('VOICE-ERROR', 'native VAD start failed: ' + (err && err.message ? err.message : err));
    throw err;
  }
};

NativeMicUtteranceVAD.prototype.stop = async function () {
  var host = this._host;
  try {
    this.isRecording = false;
    this.inSpeech = false;

    if (this.nativeListener) {
      this.nativeListener.remove();
      this.nativeListener = null;
    }
    if (this.nativeErrorListener) {
      this.nativeErrorListener.remove();
      this.nativeErrorListener = null;
    }

    this.preRollBuffer.clear();
    this.utteranceChunks = [];
    this.completedBinding = null;
    this.startGateChunks = [];
    if (host.registry.isCurrent(this)) {
      const stopPromise = Promise.resolve().then(function () {
        return host.recorder.stop();
      });
      host.registry.setStopPromise(stopPromise);
      try {
        await stopPromise;
      } finally {
        if (host.registry.getStopPromise() === stopPromise) {
          host.registry.setStopPromise(null);
        }
      }
    }
  } catch (err) {
    console.error('Error stopping Voice Mode native VAD:', err);
  }
};

NativeMicUtteranceVAD.prototype.reinitialize = async function () {
  var host = this._host;
  host.log('VAD', 'reinitialize: native Silero always running');
};

NativeMicUtteranceVAD.prototype.onTtsPlaybackStarted = function () {
  this.preRollBuffer.clear();
  this.inSpeech = false;
  this.utteranceChunks = [];
  this.startGateChunks = [];
  this._resetSpeechCounters();
};

function DesktopUtteranceVAD(host) {
  this._initGate(host);
}
DesktopUtteranceVAD.prototype = Object.create(SileroUtteranceGate.prototype);
DesktopUtteranceVAD.prototype.constructor = DesktopUtteranceVAD;

DesktopUtteranceVAD.prototype.onFrame = function (frame, probability) {
  const copy = frame.slice();
  this.preRollBuffer.push(copy);
  this._onSileroFrame(copy, probability,
    frame.length * 1000 / this._host.nativeAudio.NATIVE_MIC_SAMPLE_RATE);
};

DesktopUtteranceVAD.prototype._completeUtterance = function (binding) {
  const chunks = this.utteranceChunks;
  this.utteranceChunks = [];
  const audio = new Float32Array(chunks.reduce(function (sum, c) { return sum + c.length; }, 0));
  let offset = 0;
  chunks.forEach(function (c) { audio.set(c, offset); offset += c.length; });
  this._host.onSpeechEnd(audio, binding);
};

// vad-web supplies Silero scores and 16 kHz frames; its own segmenter only
// counts >=0.3 frames and misfires on real speech, so the shared gate
// segments and barges in instead.
function createVAD(host, stream) {
  host.log('VAD', 'createVAD called with stream id: ' + stream.id);
  const gate = new DesktopUtteranceVAD(host);
  return host.vadLib.MicVAD.new({
    stream: stream,
    model: 'v5',
    baseAssetPath: '/static/deps/vad/',
    onnxWASMBasePath: '/static/deps/vad/ort/',
    getStream: async () => stream,
    onFrameProcessed: function (probs, frame) {
      gate.onFrame(frame, probs.isSpeech);
    },
  });
}

  return {
    NativeMicUtteranceVAD: NativeMicUtteranceVAD,
    createVAD: createVAD
  };
}));
