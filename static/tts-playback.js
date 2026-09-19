(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatTtsPlayback = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Owned desktop/native TTS sentence queues and desktop clip pipeline.
  // Single owner for the streaming discover/pump/retry loops; chat keeps
  // DOM/event composition (button UI, STT abort, VAD reset, text-change
  // wakeup via observeChanges) and wires explicit adapters to the shared
  // single voice lifecycle (isLive/onComplete/preload cache/adopt/release),
  // voice-text (split/sanitize/terminator) and HTTP/native/platform helpers.
  // Answer text/progress arrive ONLY through the explicit per-message source
  // (static/playback-source.js), published at chat's generation/rendering
  // transitions; queues wake on source.subscribe plus the observeChanges
  // backstop and poll fallback, and never infer progress from buttons/DOM.
  // No globals, no duplicate mutable authority, no new locks. Error strings,
  // retry bounds/backoffs, callback order and generation guards match the
  // original chat.js pumps exactly; protocols/retries are not rewritten.
  //
  // Desktop clip pipeline deps (createDesktopClipPipeline):
  // isLive(sessionId), sanitize(text), hasPreload(key), getPreload(key),
  // setPreload(key, promise), deletePreload(key), getAbortSignal(),
  // fetchVoiceRetry(url, options, attempts), withCsrf(headers),
  // getAudio(), createObjectUrl(blob), adoptBlobUrl(url),
  // releaseBlobUrl(url), isVoiceModeActive(), noteClipStarted(),
  // noteClipFinished(), notifyStarted(), notifyEnded(), logError(msg...),
  // setTimeout(fn, ms).
  //
  // Desktop queue deps (playFixedSentenceList / playMessageBodyTts):
  // isLive(sessionId), onComplete(button), source (explicit per-message
  // playback source: getText()/isGenerating()/subscribe()),
  // split(text), terminator(text), preload(sessionId, text),
  // playOne(sessionId, text), reportVoice(kind, msg), appendMessage(text, cls),
  // logError(msg...), setTimeout(fn, ms), clearTimeout(id),
  // isVoiceModeActive(), observeChanges(onChange) -> disconnect|null.
  //
  // Native queue deps (playNativeVoiceModeTts):
  // voiceLifecycle (single owner for generation guards/notes), split,
  // terminator, sanitize, source (explicit per-message playback source set by
  // initMessageContext at the original point; getText/isGenerating/subscribe
  // read the initialized source),
  // initMessageContext() (message association at the original
  // point; source reads the initialized context),
  // observeChanges(onChange),
  // fetchVoiceRetry, withCsrf, sleepMs(ms), isRetryableVoiceStatus(status),
  // getNativeBridge() -> NativeVoiceTts|null, streamUrl(token),
  // cancelToken(token), stopDesktop(), stopAll(opts), abortStt(), vadReset(),
  // resetPlayButton(btn), clearMessageUi(), syncSendButton(),
  // setButtonPlaying(button), notifyStarted(), notifyEnded(), reportVoice(),
  // appendMessage(), logError(), setTimeout(), clearTimeout(),
  // isVoiceModeActive(), getSessionPromise(), setSessionPromise(p),
  // setSessionListener(l), nativeStop() -> promise,
  // invalidateNative(), finishNative(gen, button), fallbackPlay(button, opts),
  // createAbortController().

  const MAX_TTS_SENTENCE_RETRIES = 3;
  const MAX_NATIVE_TTS_LOOKAHEAD = 4;
  const MAX_TTS_CLIP_ATTEMPTS = 2;
  const TTS_CLIP_RETRY_BACKOFF_MS = 400;

  function createDesktopClipPipeline(deps) {
    deps = deps || {};
    var isLive = deps.isLive;
    var sanitize = deps.sanitize;
    var hasPreload = deps.hasPreload;
    var getPreload = deps.getPreload;
    var setPreload = deps.setPreload;
    var deletePreload = deps.deletePreload;
    var getAbortSignal = deps.getAbortSignal;
    var fetchVoiceRetry = deps.fetchVoiceRetry;
    var withCsrf = deps.withCsrf;
    var getAudio = deps.getAudio;
    var createObjectUrl = deps.createObjectUrl;
    var adoptBlobUrl = deps.adoptBlobUrl;
    var releaseBlobUrl = deps.releaseBlobUrl;
    var isVoiceModeActive = deps.isVoiceModeActive;
    var noteClipStarted = deps.noteClipStarted;
    var noteClipFinished = deps.noteClipFinished;
    var notifyStarted = deps.notifyStarted;
    var notifyEnded = deps.notifyEnded;
    var logError = deps.logError;
    var setTimeoutFn = deps.setTimeout;
    var revokeObjectUrl = deps.revokeObjectUrl;

    function fetchClip(sessionId, text) {
      if (!isLive(sessionId)) return Promise.resolve(null);
      var cleaned = sanitize(text);
      if (!cleaned) return Promise.resolve(null);

      var cacheKey = sessionId + ':' + cleaned;
      if (hasPreload(cacheKey)) {
        return getPreload(cacheKey);
      }

      var signal = getAbortSignal();
      var promise = fetchVoiceRetry('/tts', {
        method: 'POST',
        headers: withCsrf({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ text: cleaned }),
        signal: signal
      })
      .then(function (r) {
        if (!isLive(sessionId)) return null;
        return r.json();
      })
      .then(function (data) {
        if (!isLive(sessionId) || !data || !data.token) return null;
        var clipUrl = '/tts_stream/' + encodeURIComponent(data.token);
        return fetchVoiceRetry(clipUrl, {
          method: 'GET',
          headers: withCsrf({}),
          signal: signal
        }, MAX_TTS_CLIP_ATTEMPTS);
      })
      .then(function (res) {
        if (!res || !isLive(sessionId)) return null;
        return res.blob();
      })
      .then(function (blob) {
        if (!blob || !isLive(sessionId)) return null;
        var clip = {
          blobUrl: null,
          blob: blob,
          cleanUp: function () {
            if (clip.blobUrl) {
              try { revokeObjectUrl(clip.blobUrl); } catch (e) { /* ignore */ }
              clip.blobUrl = null;
            }
          }
        };
        return clip;
      })
      .catch(function (err) {
        deletePreload(cacheKey);
        throw err;
      });

      setPreload(cacheKey, promise);
      return promise;
    }

    function preloadSentence(sessionId, text) {
      if (!isLive(sessionId) || !text) return;
      var cleaned = sanitize(text);
      if (!cleaned) return;
      var cacheKey = sessionId + ':' + cleaned;
      if (hasPreload(cacheKey)) return;
      fetchClip(sessionId, text).catch(function () {});
    }

    function playOne(sessionId, text) {
      if (!isLive(sessionId)) return Promise.resolve(false);
      var cleaned = sanitize(text);
      if (!cleaned) return Promise.resolve(true);

      var cacheKey = sessionId + ':' + cleaned;
      var cached = getPreload(cacheKey);

      var signal = getAbortSignal();
      void signal;
      var getClipPromise = cached
        ? Promise.resolve(cached)
        : fetchClip(sessionId, text);
      deletePreload(cacheKey);

      return getClipPromise.then(function (clip) {
        if (!isLive(sessionId) || !clip || !clip.blob) return false;
        var audio = getAudio();
        return new Promise(function (resolve) {
          if (!isLive(sessionId)) {
            clip.cleanUp();
            resolve(false);
            return;
          }
          var settled = false;
          var clipAttempt = 0;

          var finish = function (ok) {
            if (settled) return;
            settled = true;
            audio.onended = null;
            audio.onerror = null;
            var playedUrl = clip.blobUrl;
            // Original finish owns the URL from here on via cleanUp +
            // releaseBlobUrlIfCurrent; preserve order exactly.
            if (clip.cleanUp) clip.cleanUp();
            if (typeof releaseBlobUrl === 'function') releaseBlobUrl(playedUrl);
            if (isVoiceModeActive()) {
              noteClipFinished();
              if (typeof notifyEnded === 'function') notifyEnded();
            }
            resolve(!!ok && isLive(sessionId));
          };

          var startClip = function () {
            if (settled) return;
            clipAttempt += 1;
            var myAttempt = clipAttempt;
            var attemptFailed = false;
            var failAttempt = function (err) {
              if (settled || attemptFailed || myAttempt !== clipAttempt) return;
              attemptFailed = true;
              if (err && err.name === 'NotAllowedError') {
                logError('TTS audio.play() failed:', err);
                finish(false);
                return;
              }
              if (clipAttempt >= MAX_TTS_CLIP_ATTEMPTS || !isLive(sessionId)) {
                finish(false);
                return;
              }
              setTimeoutFn(function () {
                if (settled || !isLive(sessionId)) return;
                startClip();
              }, TTS_CLIP_RETRY_BACKOFF_MS * clipAttempt);
            };
            if (clip.cleanUp) clip.cleanUp();
            var freshUrl = null;
            try {
              if (isLive(sessionId) && clip.blob) {
                freshUrl = createObjectUrl(clip.blob);
              }
            } catch (e) { /* fall through to failAttempt */ }
            if (!freshUrl) {
              failAttempt(null);
              return;
            }
            clip.blobUrl = freshUrl;
            adoptBlobUrl(clip.blobUrl);
            audio.onended = function () { finish(true); };
            audio.onerror = function () {
              try {
                var mediaErr = audio.error;
                logError('TTS clip media error:',
                  mediaErr && mediaErr.code, mediaErr && mediaErr.message);
              } catch (e) { /* ignore */ }
              failAttempt(null);
            };
            audio.src = clip.blobUrl;
            if (isVoiceModeActive()) {
              noteClipStarted();
              if (typeof notifyStarted === 'function') notifyStarted();
            }
            var playPromise = audio.play();
            if (playPromise && typeof playPromise.then === 'function') {
              playPromise.catch(function (err) {
                if (!err || err.name !== 'NotAllowedError') {
                  logError('TTS audio.play() rejected:',
                    err && err.name, err && err.message);
                }
                failAttempt(err);
              });
            }
          };
          startClip();
        });
      }).catch(function (err) {
        if (err && (err.name === 'AbortError' || (err.message && err.message.indexOf('aborted') !== -1))) {
          return false;
        }
        logError('TTS error:', err);
        return false;
      });
    }

    return {
      fetchClip: fetchClip,
      preloadSentence: preloadSentence,
      playOne: playOne
    };
  }

  function playFixedSentenceList(deps, sessionId, button, sentences) {
    var isLive = deps.isLive;
    var onComplete = deps.onComplete;
    var preload = deps.preload;
    var playOne = deps.playOne;
    var reportVoice = deps.reportVoice;
    var appendMessage = deps.appendMessage;
    var logError = deps.logError;
    var setTimeoutFn = deps.setTimeout;
    var isVoiceModeActive = deps.isVoiceModeActive;

    var queue = (sentences || []).slice();
    var sentenceRetries = 0;

    function pump() {
      if (!isLive(sessionId)) return;
      if (!queue.length) {
        onComplete(button);
        return;
      }
      var next = queue.shift();
      if (queue.length > 0) {
        preload(sessionId, queue[0]);
      }
      playOne(sessionId, next).then(function (ok) {
        if (!isLive(sessionId)) return;
        if (!ok) {
          if (sentenceRetries < MAX_TTS_SENTENCE_RETRIES || (isVoiceModeActive() && isLive(sessionId))) {
            sentenceRetries += 1;
            queue.unshift(next);
            var delay = isVoiceModeActive()
              ? Math.min(400 * sentenceRetries, 3000)
              : 400 * sentenceRetries;
            setTimeoutFn(function () {
              if (!isLive(sessionId)) return;
              pump();
            }, delay);
            return;
          }
          sentenceRetries = 0;
          queue.length = 0;
          logError('Desktop TTS sentence failed after retries');
          reportVoice('VOICE-ERROR', 'TTS sentence failed (fixed list)');
          appendMessage('Voice output failed. Try again.', 'error-message');
          onComplete(button);
          return;
        }
        sentenceRetries = 0;
        pump();
      });
    }

    if (queue.length > 0) {
      preload(sessionId, queue[0]);
    }
    pump();
  }

  function playMessageBodyTts(deps, sessionId, button) {
    var isLive = deps.isLive;
    var onComplete = deps.onComplete;
    var source = deps.source;
    var getText = function () { return source.getText(); };
    var isGenerating = function () { return source.isGenerating(); };
    var split = deps.split;
    var terminator = deps.terminator;
    var preload = deps.preload;
    var playOne = deps.playOne;
    var reportVoice = deps.reportVoice;
    var appendMessage = deps.appendMessage;
    var logError = deps.logError;
    var setTimeoutFn = deps.setTimeout;
    var clearTimeoutFn = deps.clearTimeout;
    var isVoiceModeActive = deps.isVoiceModeActive;
    var observeChanges = deps.observeChanges;

    var consumedLen = 0;
    var queue = [];
    var running = false;
    var disconnectObserver = null;
    var disconnectSource = null;
    var pollTimer = null;
    var sentenceRetries = 0;
    var retryScheduled = false;

    function discoverAbsolute() {
      if (!isLive(sessionId)) return;
      var full = getText();
      if (!full || full.length <= consumedLen) return;
      var sentences = split(full);
      for (var i = 0; i < sentences.length; i++) {
        var s = sentences[i];
        if (s.end <= consumedLen) continue;
        if (consumedLen > s.start) {
          var spoken = full.slice(s.start, consumedLen);
          var tail = s.text.slice(spoken.length);
          if (tail && /^[\.\!\?…\"'”’\)\]]+$/.test(tail) && spoken + tail === s.text) continue;
        }
        var isTrailingFragment = (i === sentences.length - 1);
        if (isTrailingFragment && !terminator(s.text) && isGenerating()) break;
        queue.push(s.text);
        consumedLen = s.end;
      }
      if (queue.length > 0) {
        preload(sessionId, queue[0]);
      }
    }

    function onTextChanged() {
      if (!isLive(sessionId)) {
        teardownObserver();
        return;
      }
      discoverAbsolute();
      if (!running && queue.length) pump();
    }

    function teardownObserver() {
      if (disconnectObserver) {
        try { disconnectObserver(); } catch (e) { /* ignore */ }
        disconnectObserver = null;
      }
      if (disconnectSource) {
        try { disconnectSource(); } catch (e) { /* ignore */ }
        disconnectSource = null;
      }
      if (pollTimer) {
        clearTimeoutFn(pollTimer);
        pollTimer = null;
      }
    }

    function finishIfIdle() {
      if (!isLive(sessionId)) {
        teardownObserver();
        return;
      }
      if (running || queue.length) return;
      if (isGenerating()) {
        pollTimer = setTimeoutFn(function () {
          pollTimer = null;
          if (!isLive(sessionId)) return;
          discoverAbsolute();
          pump();
        }, 60);
        return;
      }
      discoverAbsolute();
      if (queue.length) {
        pump();
        return;
      }
      teardownObserver();
      onComplete(button);
    }

    function pump() {
      if (!isLive(sessionId) || running || retryScheduled) return;
      discoverAbsolute();
      if (!queue.length) {
        finishIfIdle();
        return;
      }
      running = true;
      var next = queue.shift();
      if (queue.length > 0) {
        preload(sessionId, queue[0]);
      }
      playOne(sessionId, next).then(function (ok) {
        running = false;
        if (!isLive(sessionId)) {
          teardownObserver();
          return;
        }
        if (!ok) {
          if (sentenceRetries < MAX_TTS_SENTENCE_RETRIES || (isVoiceModeActive() && isLive(sessionId))) {
            sentenceRetries += 1;
            queue.unshift(next);
            retryScheduled = true;
            var delay = isVoiceModeActive()
              ? Math.min(400 * sentenceRetries, 3000)
              : 400 * sentenceRetries;
            setTimeoutFn(function () {
              retryScheduled = false;
              pump();
            }, delay);
            return;
          }
          sentenceRetries = 0;
          queue.length = 0;
          logError('Desktop TTS sentence failed after retries');
          reportVoice('VOICE-ERROR', 'TTS sentence failed (desktop)');
          appendMessage('Voice output failed. Try again.', 'error-message');
          teardownObserver();
          onComplete(button);
          return;
        }
        sentenceRetries = 0;
        pump();
      });
    }

    if (typeof observeChanges === 'function') {
      disconnectObserver = observeChanges(onTextChanged) || null;
    }
    // Primary wakeup is the event-fed source; the DOM observer above stays
    // only as a text-change backstop and never supplies progress.
    if (source && typeof source.subscribe === 'function') {
      disconnectSource = source.subscribe(onTextChanged) || null;
    }

    pump();
  }

  function playNativeVoiceModeTts(deps, button, options) {
    options = options || {};
    var voiceLifecycle = deps.voiceLifecycle;
    var split = deps.split;
    var terminator = deps.terminator;
    var sanitize = deps.sanitize;
    // Explicit per-message source, initialized by initMessageContext at the
    // original point below; local wrappers keep discover/pump call sites
    // unchanged while text/progress come from the shared owner.
    var source = deps.source || null;
    var getText = function () { return source.getText(); };
    var isGenerating = function () { return source.isGenerating(); };
    var observeChanges = deps.observeChanges;
    var fetchVoiceRetry = deps.fetchVoiceRetry;
    var withCsrf = deps.withCsrf;
    var sleepMs = deps.sleepMs;
    var isRetryableVoiceStatus = deps.isRetryableVoiceStatus;
    var getNativeBridge = deps.getNativeBridge;
    var streamUrl = deps.streamUrl;
    var cancelToken = deps.cancelToken;
    var stopDesktop = deps.stopDesktop;
    var stopAll = deps.stopAll;
    var abortStt = deps.abortStt;
    var vadReset = deps.vadReset;
    var resetPlayButton = deps.resetPlayButton;
    var clearMessageUi = deps.clearMessageUi;
    var syncSendButton = deps.syncSendButton;
    var setButtonPlaying = deps.setButtonPlaying;
    var notifyStarted = deps.notifyStarted;
    var notifyEnded = deps.notifyEnded;
    var reportVoice = deps.reportVoice;
    var appendMessage = deps.appendMessage;
    var logError = deps.logError;
    var setTimeoutFn = deps.setTimeout;
    var clearTimeoutFn = deps.clearTimeout;
    var isVoiceModeActive = deps.isVoiceModeActive;
    var getSessionPromise = deps.getSessionPromise;
    var setSessionPromise = deps.setSessionPromise;
    var setSessionListener = deps.setSessionListener;
    var nativeStop = deps.nativeStop;

    var bridge = (typeof getNativeBridge === 'function') ? getNativeBridge() : null;
    if (!bridge) {
      if (typeof deps.fallbackPlay === 'function') deps.fallbackPlay(button, options);
      return;
    }
    if (voiceLifecycle.isCurrentButton(button)) {
      stopAll();
      return;
    }
    if (voiceLifecycle.hasCurrentAudio()) stopAll();

    if (typeof deps.invalidateNative === 'function') deps.invalidateNative();
    else voiceLifecycle.invalidateNativeSession();
    var stopPromise = nativeStop();
    stopDesktop();

    if (typeof vadReset === 'function') vadReset();
    if (typeof abortStt === 'function') abortStt();

    var createAbortController = deps.createAbortController;
    var voiceTtsAbortController = (typeof createAbortController === 'function')
      ? createAbortController()
      : new AbortController();
    var ttsSignal = voiceTtsAbortController ? voiceTtsAbortController.signal : undefined;
    // Message context initializes here — the exact original point of the
    // $(button).closest('.message') read (after teardown/stop/reset, before
    // queue fields) — so bridge-availability/toggle early paths touch no DOM
    // and later reads cannot shift. The adapter publishes the explicit
    // per-message source on deps at this point.
    if (typeof deps.initMessageContext === 'function') deps.initMessageContext();
    source = deps.source || source;
    var pendingNativeTtsTokens = new Set();
    var stopped = false;
    var consumedSentences = 0;
    var sentenceQueue = [];
    var endRequested = false;
    var inFlightSentences = 0;
    var pendingEnqueues = 0;
    var enqueueTail = Promise.resolve();
    var sessionReady = false;
    var sessionStarting = false;
    var nativeBackpressure = false;
    var lookahead = MAX_NATIVE_TTS_LOOKAHEAD;
    var queuedNativeClips = new Map();
    var isFixedList = !!(options.sentences && options.sentences.length);

    var generation = voiceLifecycle.beginNativePlayback(button, function () {
      stopped = true;
      teardownObserver();
      pendingNativeTtsTokens.forEach(function (token) {
        cancelToken(token);
      });
      pendingNativeTtsTokens.clear();
      try { if (voiceTtsAbortController) voiceTtsAbortController.abort(); } catch (e) { /* ignore */ }
      if (typeof deps.invalidateNative === 'function') deps.invalidateNative();
      else voiceLifecycle.invalidateNativeSession();
      voiceLifecycle.noteNativeManualStop();
      resetPlayButton(button);
      clearMessageUi();
      nativeStop().catch(function () {});
    });
    setButtonPlaying(button);
    syncSendButton();

    function live() {
      return !stopped && voiceLifecycle.isLiveNativeGeneration(generation);
    }

    function discoverSentences() {
      if (!live() || isFixedList) return;
      var fullText = getText();
      if (!fullText) return;
      var parts = split(fullText);
      for (var i = consumedSentences; i < parts.length; i++) {
        var part = parts[i];
        var isTrailingFragment = (i === parts.length - 1);
        if (isTrailingFragment && !terminator(part.text) && isGenerating()) break;
        sentenceQueue.push(part.text);
        consumedSentences++;
      }
    }

    function ensureSession() {
      var existing = getSessionPromise ? getSessionPromise() : null;
      if (existing) return existing;
      var created = stopPromise.then(function () {
        if (!live()) return null;
        return bridge.beginSession();
      }).then(function (res) {
        if (!live()) return;
        var nativeSessionGen = (res && res.generation) || 0;
        nativeBackpressure = !!(res && res.maxQueuedClips > 0);
        if (nativeBackpressure) lookahead = Math.min(MAX_NATIVE_TTS_LOOKAHEAD, res.maxQueuedClips);
        var nativeStarted = false;
        var listenerPromise = bridge.addListener('playbackState', function (data) {
          if (!data || !voiceLifecycle.isLiveNativeGeneration(generation)) return;
          if (nativeSessionGen && data.generation && data.generation !== nativeSessionGen) return;
          if (data.type === 'started') {
            nativeStarted = true;
            notifyStarted();
          } else if (data.type === 'clipConsumed') {
            var job = queuedNativeClips.get(data.url);
            if (job) {
              queuedNativeClips.delete(data.url);
              pendingNativeTtsTokens.delete(job.token);
              releaseSlot(job);
            }
          } else if (data.type === 'ended') {
            if (!nativeStarted && !endRequested) {
              return;
            }
            if (typeof deps.finishNative === 'function') deps.finishNative(generation, button);
            else voiceLifecycle.finishNativePlayback(generation, button);
          } else if (data.type === 'error') {
            logError('Native voice TTS error:', data.message);
          }
        });
        if (setSessionListener) setSessionListener(listenerPromise);
        return listenerPromise;
      });
      if (setSessionPromise) setSessionPromise(created);
      return created;
    }

    function markEndOfQueue() {
      if (!live() || endRequested) return;
      endRequested = true;
      ensureSession().then(function () {
        if (live()) return bridge.markEndOfQueue();
      }).catch(function (err) {
        if (live()) {
          logError('Native voice TTS session failed:', err);
          if (typeof deps.finishNative === 'function') deps.finishNative(generation, button);
          else voiceLifecycle.finishNativePlayback(generation, button);
        }
      });
    }

    function onTextChanged() {
      if (!live()) {
        teardownObserver();
        return;
      }
      discoverSentences();
      pump();
    }

    var disconnectObserver = null;
    var disconnectSource = null;
    var pollTimer = null;

    function teardownObserver() {
      if (disconnectObserver) {
        try { disconnectObserver(); } catch (e) { /* ignore */ }
        disconnectObserver = null;
      }
      if (disconnectSource) {
        try { disconnectSource(); } catch (e) { /* ignore */ }
        disconnectSource = null;
      }
      if (pollTimer) {
        clearTimeoutFn(pollTimer);
        pollTimer = null;
      }
    }

    function postOneToken(rawText) {
      var cleaned = sanitize(rawText || '').trim();
      if (!cleaned) return Promise.resolve(null);
      return ensureSession().then(function () {
        if (!live()) return null;
        return fetchVoiceRetry('/tts', {
          method: 'POST',
          headers: withCsrf({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ text: cleaned }),
          signal: ttsSignal
        });
      }).then(function (response) {
        if (!response) return null;
        var responseToken = response.headers && response.headers.get('X-TTS-Token');
        if (responseToken) {
          var token = String(responseToken);
          pendingNativeTtsTokens.add(token);
          if (!live()) {
            pendingNativeTtsTokens.delete(token);
            cancelToken(token);
            return null;
          }
          if (response.body) response.body.cancel().catch(function () {});
          return { token: token };
        }
        return response.json();
      }).then(function (data) {
        if (!data || !data.token) return null;
        var token = String(data.token);
        pendingNativeTtsTokens.add(token);
        if (!live()) {
          pendingNativeTtsTokens.delete(token);
          cancelToken(token);
          return null;
        }
        return token;
      });
    }

    function requestToken(text) {
      function attempt(n) {
        if (!live()) return Promise.resolve(null);
        return postOneToken(text).catch(function (err) {
          if (!live() || (err && err.message === 'Session expired')) throw err;
          var match = /request failed \((\d+)\)/.exec((err && err.message) || '');
          var status = match ? Number(match[1]) : 0;
          if (n >= MAX_TTS_SENTENCE_RETRIES || (status && !isRetryableVoiceStatus(status))) throw err;
          return sleepMs(400 * (n + 1)).then(function () { return attempt(n + 1); });
        });
      }
      return attempt(0);
    }

    function releaseSlot(job) {
      if (job.released) return;
      job.released = true;
      inFlightSentences--;
      if (live()) pump();
    }

    function queueSentence(text) {
      var job = { token: null, released: false };
      inFlightSentences++;
      pendingEnqueues++;
      var prepared = requestToken(text).then(function (token) {
        return { token: token };
      }, function (error) { return { error: error }; });
      enqueueTail = enqueueTail.then(function () { return prepared; }).then(function (result) {
        if (!live()) return;
        if (result.error) throw result.error;
        if (!result.token) { releaseSlot(job); return; }
        job.token = result.token;
        var url = streamUrl(job.token);
        if (nativeBackpressure) queuedNativeClips.set(url, job);
        var attemptEnqueue = function (attempt) {
          if (!live()) return Promise.resolve();
          // Normalize a synchronous bridge throw into a rejection so the
          // bounded retry below applies to every enqueue failure mode.
          return Promise.resolve().then(function () { return bridge.enqueue(url); }).then(function () {
            if (!nativeBackpressure) releaseSlot(job);
            return;
          }).catch(function (err) {
            if (attempt >= MAX_TTS_SENTENCE_RETRIES) throw err;
            return sleepMs(400 * (attempt + 1)).then(function () { return attemptEnqueue(attempt + 1); });
          });
        };
        return attemptEnqueue(0);
      }).catch(function (err) {
        if (job.token) {
          queuedNativeClips.delete(streamUrl(job.token));
          pendingNativeTtsTokens.delete(job.token);
          cancelToken(job.token);
        }
        if (!live()) return;
        logError('Native voice TTS sentence failed after retries:', err);
        reportVoice('VOICE-ERROR', 'TTS sentence failed (native)');
        appendMessage('Voice output failed. Try again.', 'error-message');
        stopped = true;
        teardownObserver();
        bridge.stop().catch(function () {});
        if (typeof deps.finishNative === 'function') deps.finishNative(generation, button);
        else voiceLifecycle.finishNativePlayback(generation, button);
      }).then(function () {
        pendingEnqueues--;
        if (live()) pump();
      });
    }

    function pump() {
      if (!live() || endRequested) return;
      if (!sessionReady) {
        if (sessionStarting) return;
        sessionStarting = true;
        ensureSession().then(function () {
          sessionReady = true;
          if (live()) pump();
        }).catch(function (err) {
          if (!live()) return;
          stopped = true;
          teardownObserver();
          logError('Native voice TTS session failed:', err);
          bridge.stop().catch(function () {});
          if (typeof deps.finishNative === 'function') deps.finishNative(generation, button);
          else voiceLifecycle.finishNativePlayback(generation, button);
        });
        return;
      }
      discoverSentences();
      while (sentenceQueue.length > 0 && inFlightSentences < lookahead) {
        var text = sanitize(sentenceQueue.shift() || '').trim();
        if (text) queueSentence(text);
      }
      if (!isFixedList && isGenerating()) {
        if (!pollTimer) pollTimer = setTimeoutFn(function () {
          pollTimer = null;
          pump();
        }, 80);
      } else if (sentenceQueue.length === 0 && pendingEnqueues === 0) {
        teardownObserver();
        markEndOfQueue();
      }
    }

    if (isFixedList) {
      options.sentences.forEach(function (sentence) {
        if (sentence && String(sentence).trim()) sentenceQueue.push(String(sentence));
      });
    }

    if (typeof observeChanges === 'function') {
      disconnectObserver = observeChanges(onTextChanged) || null;
    }
    // Primary wakeup is the event-fed source; the DOM observer above stays
    // only as a text-change backstop and never supplies progress.
    if (source && typeof source.subscribe === 'function') {
      disconnectSource = source.subscribe(onTextChanged) || null;
    }

    pump();
  }

  return {
    MAX_TTS_SENTENCE_RETRIES: MAX_TTS_SENTENCE_RETRIES,
    MAX_NATIVE_TTS_LOOKAHEAD: MAX_NATIVE_TTS_LOOKAHEAD,
    MAX_TTS_CLIP_ATTEMPTS: MAX_TTS_CLIP_ATTEMPTS,
    TTS_CLIP_RETRY_BACKOFF_MS: TTS_CLIP_RETRY_BACKOFF_MS,
    createDesktopClipPipeline: createDesktopClipPipeline,
    playFixedSentenceList: playFixedSentenceList,
    playMessageBodyTts: playMessageBodyTts,
    playNativeVoiceModeTts: playNativeVoiceModeTts
  };
}));
