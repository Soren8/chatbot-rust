(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatVoiceLifecycle = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Owned browser voice lifecycle: desktop + native TTS playback state
  // (currentAudio/Button, desktop session/audio/abort/preloads/blob,
  // sessionActive/playing, bargeFrames, listen cooldown, native generation).
  // chat.js keeps DOM rendering, VAD/stream capture, STT upload and the
  // sentence-queue pumps; every lifecycle mutation delegates here.
  //
  // Explicit callbacks only (no window/document access):
  // now, createAudio, createAbortController, revokeUrl, resetPlayButton,
  // clearMessageUi, syncSendButton, isVoiceModeActive, stopNativePlayback.

  var TTS_LISTEN_COOLDOWN_MS = 400;
  var BARGE_IN_FRAMES_DESKTOP = 4;
  var BARGE_IN_SPEECH_PROB = 0.85;

  function createVoiceLifecycle(deps) {
    deps = deps || {};
    var nowFn = (typeof deps.now === 'function') ? deps.now : function () { return Date.now(); };
    var createAudioFn = (typeof deps.createAudio === 'function') ? deps.createAudio : function () {
      if (typeof Audio !== 'undefined') return new Audio();
      return null;
    };
    var createAbortFn = (typeof deps.createAbortController === 'function') ? deps.createAbortController : function () {
      return new AbortController();
    };
    var revokeUrlFn = (typeof deps.revokeUrl === 'function') ? deps.revokeUrl : function (url) {
      try {
        if (typeof URL !== 'undefined' && URL.revokeObjectURL) URL.revokeObjectURL(url);
      } catch (e) { /* ignore */ }
    };
    var resetPlayButtonFn = (typeof deps.resetPlayButton === 'function') ? deps.resetPlayButton : function () {};
    var clearMessageUiFn = (typeof deps.clearMessageUi === 'function') ? deps.clearMessageUi : function () {};
    var syncSendButtonFn = (typeof deps.syncSendButton === 'function') ? deps.syncSendButton : function () {};
    var isVoiceModeActiveFn = (typeof deps.isVoiceModeActive === 'function') ? deps.isVoiceModeActive : function () { return false; };
    var stopNativePlaybackFn = (typeof deps.stopNativePlayback === 'function') ? deps.stopNativePlayback : function () {};

    var currentAudio = null;
    var currentButton = null;
    var desktopSession = 0;
    var desktopAudio = null;
    var desktopAbort = null;
    var preloadCache = new Map();
    var currentBlobUrl = null;
    var sessionActive = false;
    var playing = false;
    var bargeFrames = 0;
    var cooldownUntil = 0;
    var nativeGeneration = 0;
    var stopAllBusy = false;
    var activeClips = new Set();

    function voiceModeActive() {
      return !!isVoiceModeActiveFn();
    }

    function sync() {
      syncSendButtonFn();
    }

    function resetButton(btn) {
      resetPlayButtonFn(btn);
    }

    function clearMessage() {
      clearMessageUiFn();
    }

    function stopNative() {
      stopNativePlaybackFn();
    }

    function armCooldown() {
      cooldownUntil = nowFn() + TTS_LISTEN_COOLDOWN_MS;
    }

    function clearPreloads() {
      if (currentBlobUrl) {
        try { revokeUrlFn(currentBlobUrl); } catch (e) { /* ignore */ }
        currentBlobUrl = null;
      }
      preloadCache.forEach(function (promise) {
        Promise.resolve(promise).then(function (clip) {
          if (clip && clip.cleanUp) clip.cleanUp();
        }).catch(function () {});
      });
      preloadCache.clear();
    }

    function getDesktopAudio() {
      if (!desktopAudio) {
        desktopAudio = createAudioFn();
      }
      return desktopAudio;
    }

    function registerDesktopClipCanceller(entry) {
      if (entry) activeClips.add(entry);
    }

    function unregisterDesktopClipCanceller(entry) {
      if (entry) activeClips.delete(entry);
    }

    // Session disposal: run registered clip/queue disposers before handlers clear.
    function cancelDesktopClips(sessionId) {
      var targets = [];
      activeClips.forEach(function (entry) {
        if (sessionId == null || !entry || entry.sessionId === sessionId) targets.push(entry);
      });
      targets.forEach(function (entry) {
        try { if (entry && typeof entry.cancel === 'function') entry.cancel(); } catch (e) { /* ignore */ }
      });
    }

    function resetDesktopAudioElement() {
      var audio = desktopAudio;
      if (!audio) return;
      audio.onended = null;
      audio.onerror = null;
      audio.onloadeddata = null;
      try { audio.pause(); } catch (e) { /* ignore */ }
      try {
        audio.removeAttribute('src');
        audio.src = '';
      } catch (e) { /* ignore */ }
    }

    function stopDesktopPlayback() {
      try { cancelDesktopClips(); } catch (e) { /* ignore */ }
      desktopSession += 1;
      if (desktopAbort) {
        try { desktopAbort.abort(); } catch (e) { /* ignore */ }
        desktopAbort = null;
      }
      clearPreloads();
      resetDesktopAudioElement();
      var prevBtn = currentButton;
      currentAudio = null;
      currentButton = null;
      sessionActive = false;
      playing = false;
      resetButton(prevBtn);
      clearMessage();
      sync();
    }

    function completeDesktopPlayback(button) {
      clearPreloads();
      currentAudio = null;
      currentButton = null;
      resetButton(button);
      clearMessage();
      resetDesktopAudioElement();
      sessionActive = false;
      playing = false;
      if (voiceModeActive()) {
        armCooldown();
      }
      sync();
    }

    function isLiveDesktop(sessionId) {
      return sessionId === desktopSession && !!currentAudio && currentAudio.sessionId === sessionId;
    }

    function isTtsActive() {
      return !!(currentAudio || sessionActive || playing);
    }

    // Flags-only voice session (sessionActive/playing, no currentAudio).
    // Barge-in and utterance routing use this; button UI uses isTtsActive.
    function hasActiveVoiceSession() {
      return !!(sessionActive || playing);
    }

    function getCurrentButton() {
      return currentButton;
    }

    function isCurrentButton(button) {
      return !!currentAudio && currentButton === button;
    }

    function hasCurrentAudio() {
      return !!currentAudio;
    }

    function currentDesktopSession() {
      return desktopSession;
    }

    function currentNativeGeneration() {
      return nativeGeneration;
    }

    function isLiveNativeGeneration(generation) {
      return generation === nativeGeneration;
    }

    function invalidateNativeSession() {
      nativeGeneration += 1;
    }

    // Begin a desktop play owning the current session. Caller stops first so
    // a gesture prime can run between stop and begin. abortStt runs between
    // the barge-frame reset and sessionActive, matching the original order.
    function beginDesktopPlayback(button, abortStt) {
      var sessionId = desktopSession;
      desktopAbort = createAbortFn();
      currentAudio = {
        sessionId: sessionId,
        stop: function () { stopDesktopPlayback(); }
      };
      currentButton = button;
      if (voiceModeActive()) {
        bargeFrames = 0;
        if (typeof abortStt === 'function') abortStt();
        sessionActive = true;
        sync();
      }
      return sessionId;
    }

    // Begin a native play owning the current (already invalidated)
    // generation. Queue teardown (observer, tokens, abort) stays in the
    // pump's stop closure passed here.
    function beginNativePlayback(button, stopFn) {
      var generation = nativeGeneration;
      sessionActive = true;
      playing = false;
      currentButton = button;
      currentAudio = {
        nativeGeneration: generation,
        stop: (typeof stopFn === 'function') ? stopFn : function () {}
      };
      return generation;
    }

    // Stale guard: a replaced generation never touches the new playback.
    // Order matches the original finish: guard, onEnded, clear flags/UI,
    // cleanup (listener + promise), cooldown, sync.
    function finishNativePlayback(generation, button, callbacks) {
      if (generation !== nativeGeneration) return false;
      var onEnded = callbacks && callbacks.onEnded;
      var cleanup = callbacks && callbacks.cleanup;
      if (typeof onEnded === 'function') onEnded();
      playing = false;
      sessionActive = false;
      if (currentAudio && currentAudio.nativeGeneration === generation) {
        currentAudio = null;
        currentButton = null;
        resetButton(button);
        clearMessage();
      }
      if (typeof cleanup === 'function') cleanup();
      if (voiceModeActive()) {
        armCooldown();
      }
      sync();
      return true;
    }

    function notePlaybackStarted() {
      playing = true;
    }

    function notePlaybackEnded() {
      playing = false;
    }

    // Native manual stop (CURRENT_AUDIO.stop from stop-all or toggle):
    // the pump already invalidated the generation; clear the queued-session
    // flags. UI/native-stop sequencing stays in the pump closure.
    function noteNativeManualStop() {
      sessionActive = false;
      playing = false;
    }

    // Desktop clip started/finished while voice mode is active. The pump
    // still routes through the notify adapters (bridge reset + log);
    // these notes own the playing flag transition.
    function noteDesktopClipStarted() {
      if (voiceModeActive()) {
        playing = true;
      }
    }

    function noteDesktopClipFinished() {
      if (voiceModeActive()) {
        playing = false;
      }
    }

    function resetBargeFrames() {
      bargeFrames = 0;
    }

    // High-confidence Silero frame gate (0.85 / 4 frames): true once when
    // barge-in fires (counter reset), false otherwise. Idle frames reset.
    function noteFrameProcessed(isSpeechProb) {
      if (!isTtsActive()) {
        bargeFrames = 0;
        return false;
      }
      if (isSpeechProb > BARGE_IN_SPEECH_PROB) {
        bargeFrames += 1;
        if (bargeFrames >= BARGE_IN_FRAMES_DESKTOP) {
          bargeFrames = 0;
          return true;
        }
        return false;
      }
      bargeFrames = 0;
      return false;
    }

    function armListenCooldown() {
      armCooldown();
    }

    function clearListenCooldown() {
      cooldownUntil = 0;
    }

    function isInCooldown() {
      return nowFn() < cooldownUntil;
    }

    function getDesktopAbortSignal() {
      return desktopAbort ? desktopAbort.signal : undefined;
    }

    function hasPreload(key) {
      return preloadCache.has(key);
    }

    function getPreload(key) {
      return preloadCache.get(key);
    }

    function setPreload(key, promise) {
      preloadCache.set(key, promise);
    }

    function deletePreload(key) {
      preloadCache.delete(key);
    }

    function adoptBlobUrl(url) {
      if (currentBlobUrl && currentBlobUrl !== url) {
        try { revokeUrlFn(currentBlobUrl); } catch (e) { /* ignore */ }
      }
      currentBlobUrl = url;
    }

    function releaseBlobUrlIfCurrent(url) {
      if (url && currentBlobUrl === url) {
        currentBlobUrl = null;
      }
    }

    // Stop everything: flags + cooldown, current stop, native stop,
    // desktop stop, button/message reset, sync. Keeps the original double
    // desktop bump via currentAudio.stop when desktop is current.
    function stopAllPlayback(opts) {
      opts = opts || {};
      if (stopAllBusy) return;
      stopAllBusy = true;
      try {
        playing = false;
        sessionActive = false;
        if (opts.preserveListen) {
          cooldownUntil = 0;
        } else {
          armCooldown();
        }
        var audio = currentAudio;
        if (audio && typeof audio.stop === 'function') {
          try { audio.stop(); } catch (e) { /* ignore */ }
        }
        stopNative();
        stopDesktopPlayback();
        if (currentButton) {
          resetButton(currentButton);
          currentButton = null;
        }
        clearMessage();
        sync();
      } finally {
        stopAllBusy = false;
      }
    }

    function snapshot() {
      return {
        hasAudio: !!currentAudio,
        hasButton: !!currentButton,
        desktopSession: desktopSession,
        nativeGeneration: nativeGeneration,
        sessionActive: sessionActive,
        playing: playing,
        bargeFrames: bargeFrames,
        cooldownUntil: cooldownUntil,
        preloadSize: preloadCache.size,
        hasDesktopAudio: !!desktopAudio,
        hasAbort: !!desktopAbort,
        currentBlobUrl: currentBlobUrl
      };
    }

    return {
      clearPreloads: clearPreloads,
      armListenCooldown: armListenCooldown,
      clearListenCooldown: clearListenCooldown,
      isInCooldown: isInCooldown,
      getDesktopAudio: getDesktopAudio,
      registerDesktopClipCanceller: registerDesktopClipCanceller,
      unregisterDesktopClipCanceller: unregisterDesktopClipCanceller,
      cancelDesktopClips: cancelDesktopClips,
      resetDesktopAudioElement: resetDesktopAudioElement,
      stopDesktopPlayback: stopDesktopPlayback,
      completeDesktopPlayback: completeDesktopPlayback,
      isLiveDesktop: isLiveDesktop,
      isTtsActive: isTtsActive,
      hasActiveVoiceSession: hasActiveVoiceSession,
      getCurrentButton: getCurrentButton,
      isCurrentButton: isCurrentButton,
      hasCurrentAudio: hasCurrentAudio,
      currentDesktopSession: currentDesktopSession,
      currentNativeGeneration: currentNativeGeneration,
      isLiveNativeGeneration: isLiveNativeGeneration,
      invalidateNativeSession: invalidateNativeSession,
      beginDesktopPlayback: beginDesktopPlayback,
      beginNativePlayback: beginNativePlayback,
      finishNativePlayback: finishNativePlayback,
      notePlaybackStarted: notePlaybackStarted,
      notePlaybackEnded: notePlaybackEnded,
      noteNativeManualStop: noteNativeManualStop,
      noteDesktopClipStarted: noteDesktopClipStarted,
      noteDesktopClipFinished: noteDesktopClipFinished,
      resetBargeFrames: resetBargeFrames,
      noteFrameProcessed: noteFrameProcessed,
      getDesktopAbortSignal: getDesktopAbortSignal,
      hasPreload: hasPreload,
      getPreload: getPreload,
      setPreload: setPreload,
      deletePreload: deletePreload,
      adoptBlobUrl: adoptBlobUrl,
      releaseBlobUrlIfCurrent: releaseBlobUrlIfCurrent,
      stopAllPlayback: stopAllPlayback,
      snapshot: snapshot
    };
  }

  return {
    TTS_LISTEN_COOLDOWN_MS: TTS_LISTEN_COOLDOWN_MS,
    BARGE_IN_FRAMES_DESKTOP: BARGE_IN_FRAMES_DESKTOP,
    BARGE_IN_SPEECH_PROB: BARGE_IN_SPEECH_PROB,
    createVoiceLifecycle: createVoiceLifecycle
  };
}));
