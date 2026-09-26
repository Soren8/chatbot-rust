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
  // - nativeAudio: NativeAudio module (PCM helpers + SPEECH_*/REAL_SPEECH_*
  //   thresholds; thresholds live there, never redefined here)
  // - voiceLifecycle: single TTS owner (hasActiveVoiceSession/isInCooldown/
  //   snapshot; barge-in and utterance routing use the flags-only session)
  // - now: clock adapter (Date.now)
  // - log/report/reportThrottled: nativeLog / reportVoice /
  //   reportVoiceThrottled adapters (key, windowMs, kind, message order kept)
  // - isVoiceModeActive: () => bool (voice-mode flag adapter)
  // - onBargeIn: handleBargeIn (stop TTS only on confirmed real speech)
  // - onUtteranceEnd: utterance completion (chat runs STT upload)
  // - onUtteranceStartedAt: timestamp handoff (chat amend-window state)
  // - recorder.ensurePermission/start/stop/addListener: NativeMic plugin
  //   adapters (permission helper fails closed on deny)
  // - registry.isCurrent/getStopPromise/setStopPromise: bridge-ownership and
  //   stop-rendezvous adapters (a stale bridge never stops a newer recorder;
  //   a replacement waits for an in-flight native stop)
  // - desktop host: vadLib (vad.MicVAD), log, voiceLifecycle
  //   (noteFrameProcessed), onBargeIn, onSpeechEnd, onSpeechStart,
  //   isTtsActive (message-specific active check)
  // No window/document access inside. Phase gates stay split exactly as
  // shipped: record at speech-like start, barge in only on
  // pcm16RealSpeechDetected (REAL_SPEECH_MS + voicing) — a cough or short
  // "hey" records but never stops TTS; sustained speech stops it at confirm.
  // Desktop Silero config (thresholds/paths/model) is unchanged.

function NativeMicUtteranceVAD(host, onError) {
  this._host = host;
  this.onError = onError;
  this.preRollBuffer = new host.nativeAudio.Pcm16RingBuffer(host.nativeAudio.SPEECH_PREROLL_SAMPLES);
  this.utteranceChunks = [];
  this.startGateChunks = [];
  this.inSpeech = false;
  this.speechAboveCount = 0;
  this.nonSpeechLikeCount = 0;
  this.bargeInFired = false;
  this.silenceMs = 0;
  this.speechActiveMs = 0;
  this.speechLikeMs = 0;
  this.voicedMs = 0;
  this.voicedWindow = [];
  this.nativeListener = null;
  this.isRecording = false;
  this.chunkCount = 0;
  this._firstFrameReported = false;
}

NativeMicUtteranceVAD.prototype._resetSpeechCounters = function () {
  this.speechAboveCount = 0;
  this.nonSpeechLikeCount = 0;
  this.startGateChunks = [];
  this.bargeInFired = false;
  this.silenceMs = 0;
  this.speechActiveMs = 0;
  this.speechLikeMs = 0;
  this.voicedMs = 0;
  this.voicedWindow = [];
};

/** Phase 1: start capture on speech-like energy. Does not stop TTS. */
NativeMicUtteranceVAD.prototype._maybeStartUtterance = function _maybeStartUtterance(pcm16, rms, skipPreRoll) {
  var host = this._host;
  if (this.inSpeech) return false;
  if (host.nativeAudio.pcm16IsSpeechLike(pcm16, rms)) {
    this.startGateChunks.push(pcm16.slice());
    this.speechAboveCount++;
    this.nonSpeechLikeCount = 0;
    if (this.speechAboveCount >= host.nativeAudio.SPEECH_START_FRAMES) {
      host.log('VAD', (skipPreRoll ? 'tts ' : '') + 'utterance start rms=' + Math.round(rms));
      this._beginUtterance(skipPreRoll);
      return true;
    }
  } else if (rms > host.nativeAudio.SPEECH_RMS_THRESHOLD) {
    this.nonSpeechLikeCount++;
    if (this.nonSpeechLikeCount >= host.nativeAudio.SPEECH_START_MISS_FRAMES) {
      this.speechAboveCount = 0;
      this.startGateChunks = [];
    }
  } else {
    this.speechAboveCount = 0;
    this.nonSpeechLikeCount = 0;
    this.startGateChunks = [];
  }
  return false;
};

/** Phase 2: stop TTS now if real speech is confirmed. Not called from _endUtterance. */
NativeMicUtteranceVAD.prototype._maybeBargeIn = function _maybeBargeIn() {
  var host = this._host;
  if (this.bargeInFired) return;
  if (!host.voiceLifecycle.hasActiveVoiceSession()) return;
  if (!host.nativeAudio.pcm16RealSpeechDetected(this.speechLikeMs, this.voicedMs)) return;
  this.bargeInFired = true;
  host.log('VAD', 'barge-in on real speech likeMs=' + this.speechLikeMs
    + ' voicedMs=' + this.voicedMs);
  host.onBargeIn();
};

NativeMicUtteranceVAD.prototype._noteVoicedFrame = function _noteVoicedFrame(copy, frameMs) {
  var host = this._host;
  this.voicedWindow.push(copy);
  const w = host.nativeAudio.SPEECH_VOICED_WINDOW_FRAMES;
  if (this.voicedWindow.length > w) this.voicedWindow.shift();
  if (this.voicedWindow.length >= w) {
    const win = host.nativeAudio.mergePcm16Chunks(this.voicedWindow);
    if (host.nativeAudio.pcm16IsVoicedSpeech(win)) this.voicedMs += frameMs;
  }
};

NativeMicUtteranceVAD.prototype._accumulateUtterance = function _accumulateUtterance(copy, rms, frameMs) {
  var host = this._host;
  this.utteranceChunks.push(copy);
  if (host.nativeAudio.pcm16IsSpeechLike(copy, rms)) {
    this.silenceMs = 0;
    this.speechActiveMs += frameMs;
    this.speechLikeMs += frameMs;
    this._noteVoicedFrame(copy, frameMs);
  } else {
    this.silenceMs += frameMs;
    this.voicedWindow = [];
    if (this.silenceMs >= host.nativeAudio.SPEECH_END_SILENCE_MS) {
      this._endUtterance();
      return;
    }
  }
  this._maybeBargeIn();
};

NativeMicUtteranceVAD.prototype._onNativePcm = function _onNativePcm(pcm16) {
  var host = this._host;
  if (!this.isRecording || !host.isVoiceModeActive()) {
    // Button-green-but-deaf detector: frames arrive yet the session drops
    // them (stale listener after restart, flag mismatch). Throttled.
    host.reportThrottled('pcm-dropped', 10000, 'VOICE-ERROR',
      'dropping PCM frames isRecording=' + this.isRecording
      + ' voiceModeActive=' + !!host.isVoiceModeActive()
      + ' chunks=' + this.chunkCount);
    return;
  }
  if (!this._firstFrameReported) {
    this._firstFrameReported = true;
    host.report('VOICE', 'first PCM frame received, capture live');
  }
  const copy = pcm16.slice();
  const rms = host.nativeAudio.pcm16Rms(copy);
  const frameMs = 20;

  this.preRollBuffer.push(copy);
  this.chunkCount++;

  // During TTS: record from speech-like start (Silero onSpeechStart). Barge-in
  // only after real speech (REAL_SPEECH_MS + voicing), not on cough/"hey".
  if (host.voiceLifecycle.hasActiveVoiceSession()) {
    const started = this._maybeStartUtterance(copy, rms, true);
    if (this.inSpeech && !started) {
      this._accumulateUtterance(copy, rms, frameMs);
    }
    if (this.chunkCount % 50 === 0) {
      host.log('VAD', 'pcm#' + this.chunkCount + ' ttsSess=1 ttsPlay=' + host.voiceLifecycle.snapshot().playing
        + ' inSpeech=' + this.inSpeech + ' speechMs=' + this.speechActiveMs
        + ' rms=' + Math.round(rms));
    }
    return;
  }

  if (host.voiceLifecycle.isInCooldown()) {
    return;
  }

  const started = this._maybeStartUtterance(copy, rms, false);
  if (this.inSpeech && !started) {
    this._accumulateUtterance(copy, rms, frameMs);
  }

  if (this.chunkCount % 50 === 0) {
    host.log('VAD', 'pcm#' + this.chunkCount + ' inSpeech=' + this.inSpeech
      + ' ttsPlay=' + host.voiceLifecycle.snapshot().playing + ' rms=' + Math.round(rms));
  }
};

/** Start recording. Barge-in is _maybeBargeIn, not here. */
NativeMicUtteranceVAD.prototype._beginUtterance = function _beginUtterance(skipPreRoll) {
  var host = this._host;
  if (this.inSpeech) return;
  this.inSpeech = true;
  const startChunks = this.startGateChunks;
  this.startGateChunks = [];
  this._resetSpeechCounters();
  this.utteranceStartedAt = host.now();
  this.utteranceBinding = host.captureBinding ? host.captureBinding() : null;
  host.onUtteranceStartedAt(this.utteranceStartedAt);
  this.speechActiveMs = startChunks.length * 20;
  this.speechLikeMs = startChunks.length * 20;
  this.voicedMs = host.nativeAudio.pcm16VoicedMsFromChunks(startChunks, 20);
  this.voicedWindow = startChunks.slice(-host.nativeAudio.SPEECH_VOICED_WINDOW_FRAMES);
  const preRoll = this.preRollBuffer.snapshotChunks();
  this.utteranceChunks = preRoll.length ? preRoll : startChunks;
  host.log('VAD', 'utterance begin (startChunks=' + startChunks.length + ' preRoll=' + this.utteranceChunks.length + ')');
  this._maybeBargeIn();
};

NativeMicUtteranceVAD.prototype._endUtterance = function _endUtterance() {
  var host = this._host;
  if (!this.inSpeech) return;
  this.inSpeech = false;
  this.speechAboveCount = 0;
  this.nonSpeechLikeCount = 0;
  this.silenceMs = 0;
  this.bargeInFired = false;
  this.speechLikeMs = 0;
  this.voicedMs = 0;
  this.voicedWindow = [];
  if (this.speechActiveMs < host.nativeAudio.SPEECH_MIN_ACTIVE_MS) {
    host.log('VAD', 'utterance rejected: speechActiveMs=' + this.speechActiveMs
      + ' min=' + host.nativeAudio.SPEECH_MIN_ACTIVE_MS);
    host.report('VOICE', 'utterance rejected too short speechMs=' + this.speechActiveMs);
    this.utteranceChunks = [];
    this.speechActiveMs = 0;
    return;
  }
  host.log('VAD', 'utterance end chunks=' + this.utteranceChunks.length
    + ' speechMs=' + this.speechActiveMs);
  host.report('VOICE', 'utterance end chunks=' + this.utteranceChunks.length
    + ' speechMs=' + this.speechActiveMs);
  this.completedBinding = this.utteranceBinding;
  host.onUtteranceEnd(this.completedBinding);
  this.utteranceBinding = null;
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
    host.log('VAD', 'NativeMicUtteranceVAD start (RMS v' + host.nativeAudio.VOICE_MODE_NATIVE_VAD_VERSION + ')');
    this.preRollBuffer.clear();
    this.utteranceChunks = [];
    this.completedBinding = null;
    this.startGateChunks = [];
    this.inSpeech = false;
    this._resetSpeechCounters();
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
    try {
      await host.recorder.start();
    } catch (first) {
      const firstMsg = first && first.message ? first.message : String(first);
      if (/permission/i.test(firstMsg)) throw first;
      host.log('VAD', 'NativeMic.start retry after: ' + firstMsg);
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
      await host.recorder.start();
    }

    if (!host.registry.isCurrent(this)) {
      throw new Error('native VAD start superseded');
    }
    this.nativeListener = host.recorder.addListener('nativeMicData', function (data) {
      if (!self.isRecording || !host.isVoiceModeActive()) return;
      if (!data || !data.data) return;
      try {
        self._onNativePcm(host.nativeAudio.decodeNativePcmBase64(data.data));
      } catch (err) {
        host.log('VAD', 'PCM decode error: ' + err.message);
      }
    });
    this.isRecording = true;
    host.report('VOICE', 'native VAD capture started');
  } catch (err) {
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
  host.log('VAD', 'reinitialize: native RMS VAD always running');
};

NativeMicUtteranceVAD.prototype.onTtsPlaybackStarted = function () {
  this.preRollBuffer.clear();
  this.inSpeech = false;
  this.utteranceChunks = [];
  this.startGateChunks = [];
  this._resetSpeechCounters();
};

function createVAD(host, stream, hooks) {
  hooks = hooks || {};
  host.log('VAD', 'createVAD called with stream id: ' + stream.id);
  return host.vadLib.MicVAD.new({
    stream: stream,
    model: 'v5',
    baseAssetPath: '/static/deps/vad/',
    onnxWASMBasePath: '/static/deps/vad/ort/',
    positiveSpeechThreshold: 0.7,
    negativeSpeechThreshold: 0.4,
    redemptionMs: 1500,
    minSpeechMs: 400,
    preSpeechPadFrames: 16,
    getStream: async () => stream,
    onSpeechStart: hooks.onSpeechStart || function () {
      host.log('VAD', 'onSpeechStart');
      host.onSpeechStart();
    },
    onSpeechRealStart: hooks.onSpeechRealStart || function () {
      host.log('VAD', 'onSpeechRealStart');
      if (host.isTtsActive()) {
        host.onBargeIn();
      }
    },
    onFrameProcessed: hooks.onFrameProcessed || function (probs) {
      if (host.voiceLifecycle.noteFrameProcessed(probs.isSpeech)) {
        host.onBargeIn();
      }
    },
    onSpeechEnd: hooks.onSpeechEnd || function (audio) {
      host.log('VAD', 'onSpeechEnd');
      host.onSpeechEnd(audio);
    },
  });
}

  return {
    NativeMicUtteranceVAD: NativeMicUtteranceVAD,
    createVAD: createVAD
  };
}));
