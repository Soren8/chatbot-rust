'use strict';
// TTS retry exhaustion ends the session with a visible error on the REAL
// owned desktop streaming, fixed-list, and native queues (leaf I/O failing).
// Nothing after the failed sentence may play or post; the chat error bubble
// is the user-visible signal, with console + server telemetry for diagnosis.
// A stale session failing after replacement must not touch the new playback.
const assert = require('node:assert/strict');

const ttsPlaybackPath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
const voiceLifecyclePath = process.argv[5];
const playbackSourcePath = process.argv[6];
assert(
  ttsPlaybackPath && voiceTextPath && conversationStatePath && voiceLifecyclePath && playbackSourcePath,
  'usage: node tts_exhaustion_test.js <static/tts-playback.js> <static/voice-text.js> <static/conversation-state.js> <static/voice-lifecycle.js> <static/playback-source.js>'
);
const ttsPlayback = require(ttsPlaybackPath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);
const playbackSource = require(playbackSourcePath);

function makeOwner(voiceMode) {
  return voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => !!voiceMode,
    stopNativePlayback: () => {},
  });
}

async function flush() {
  for (let i = 0; i < 80; i++) await Promise.resolve();
}

function desktopStreamingSession() {
  const state = {
    raw: 'First sentence here. Second sentence here.',
    played: [], completed: 0, chatErrors: [], reports: [], consoleErrors: [],
    timers: [], observer: null, live: true,
  };
  const voiceLifecycle = makeOwner(false);
  voiceLifecycle.stopDesktopPlayback();
  voiceLifecycle.beginDesktopPlayback({});
  // Settled text through the shared explicit source, bound finished the way
  // chat binds settled history; the queue reads only the source.
  const chatRequests = conversationState.createChatRequestTracker();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: null,
  });
  source.publish({ original: state.raw, fallbackVisible: '' });
  source.finish();
  const deps = {
    isLive: (id) => state.live && voiceLifecycle.isLiveDesktop(id),
    onComplete: (button) => {
      voiceLifecycle.completeDesktopPlayback(button);
      state.completed++; state.live = false;
    },
    source: source,
    split: voiceText.splitSentences,
    terminator: voiceText.sentenceEndsWithTerminator,
    preload: () => {},
    playOne: (sessionId, text) => { state.played.push(String(text)); return Promise.resolve(false); },
    reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
    appendMessage: (t) => { state.chatErrors.push(String(t)); },
    logError: (...a) => { state.consoleErrors.push(a.join(' ')); },
    setTimeout: (fn) => { state.timers.push(fn); return state.timers.length; },
    clearTimeout: () => {},
    isVoiceModeActive: () => false,
    observeChanges: (cb) => { state.observer = cb; return () => { state.observer = null; }; },
  };
  ttsPlayback.playMessageBodyTts(deps, 1, {});
  return {
    state,
    async settle() {
      for (let i = 0; i < 12 && state.live; i++) {
        const timers = state.timers.splice(0);
        timers.forEach(fn => fn());
        await flush();
      }
      await flush();
    },
  };
}

function fixedListSession() {
  const state = {
    played: [], completed: 0, chatErrors: [], reports: [], consoleErrors: [],
    timers: [], live: true,
  };
  const voiceLifecycle = makeOwner(false);
  voiceLifecycle.stopDesktopPlayback();
  voiceLifecycle.beginDesktopPlayback({});
  const deps = {
    isLive: (id) => state.live && voiceLifecycle.isLiveDesktop(id),
    onComplete: (button) => {
      voiceLifecycle.completeDesktopPlayback(button);
      state.completed++; state.live = false;
    },
    preload: () => {},
    playOne: (sessionId, text) => { state.played.push(String(text)); return Promise.resolve(false); },
    reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
    appendMessage: (t) => { state.chatErrors.push(String(t)); },
    logError: (...a) => { state.consoleErrors.push(a.join(' ')); },
    setTimeout: (fn) => { state.timers.push(fn); return state.timers.length; },
    isVoiceModeActive: () => false,
  };
  ttsPlayback.playFixedSentenceList(deps, 1, {}, ['Alpha one here.', 'Beta two here.']);
  return {
    state,
    async settle() {
      for (let i = 0; i < 12 && state.live; i++) {
        const timers = state.timers.splice(0);
        timers.forEach(fn => fn());
        await flush();
      }
      await flush();
    },
  };
}

function nativeFailingSession() {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const state = {
    raw: 'One here now. Two here now.',
    ended: 0, finished: 0, listener: null, observer: null,
    chatErrors: [], reports: [], consoleErrors: [],
  };
  const voiceLifecycle = makeOwner(false);
  let sessionPromise = null;
  let sessionListener = null;
  const chatRequests = conversationState.createChatRequestTracker();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: null,
  });
  source.publish({ original: state.raw, fallbackVisible: '' });
  source.finish();
  const bridge = {
    stop: async () => {},
    beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
    addListener: async (name, listener) => { state.listener = listener; return { remove() {} }; },
    enqueue: async (url) => { enqueued.push(url.split('/').pop()); },
    markEndOfQueue: async () => { state.ended++; },
  };
  const deps = {
    voiceLifecycle,
    split: voiceText.splitSentences,
    terminator: voiceText.sentenceEndsWithTerminator,
    sanitize: voiceText.sanitizeForTTS,
    source: source,
    observeChanges: (cb) => { state.observer = cb; return () => { state.observer = null; }; },
    fetchVoiceRetry: (url, options) => {
      return new Promise((resolve, reject) => {
        posts.push({ text: JSON.parse(options.body).text, reject });
        reject(new Error('network lost'));
      });
    },
    withCsrf: (headers) => headers,
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: (status) => status === 429 || status >= 500,
    getNativeBridge: () => bridge,
    streamUrl: (token) => 'https://chat/tts_stream/' + token,
    cancelToken: (token) => cancelled.push(token),
    stopDesktop: () => { voiceLifecycle.stopDesktopPlayback(); },
    stopAll: (opts) => { voiceLifecycle.stopAllPlayback(opts); },
    abortStt: () => {},
    vadReset: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    setButtonPlaying: () => {},
    notifyStarted: () => { voiceLifecycle.notePlaybackStarted(); },
    notifyEnded: () => { voiceLifecycle.notePlaybackEnded(); },
    reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
    appendMessage: (t) => { state.chatErrors.push(String(t)); },
    logError: (...a) => { state.consoleErrors.push(a.join(' ')); },
    setTimeout: () => 1,
    clearTimeout: () => {},
    isVoiceModeActive: () => false,
    getSessionPromise: () => sessionPromise,
    setSessionPromise: (p) => { sessionPromise = p; },
    getSessionListener: () => sessionListener,
    setSessionListener: (l) => { sessionListener = l; },
    nativeStop: () => bridge.stop().catch(() => {}),
    invalidateNative: () => {
      voiceLifecycle.invalidateNativeSession();
      sessionPromise = null;
      sessionListener = null;
    },
    finishNative: (generation, button) => {
      if (voiceLifecycle.finishNativePlayback(generation, button)) state.finished++;
    },
    fallbackPlay: () => {},
    createAbortController: () => new AbortController(),
  };
  ttsPlayback.playNativeVoiceModeTts(deps, {}, {});
  return {
    posts, enqueued, cancelled, state,
    async settle() {
      for (let i = 0; i < 30; i++) await flush();
    },
  };
}

function nativeReplacementHarness() {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const sleepers = [];
  const stops = [];
  const finishedGens = [];
  const observers = [];
  const texts = { A: 'Apple apple.', B: 'Cherry cherry.' };
  const enqueueCalls = [];
  const deferredOldRejections = [];
  const state = {
    phase: 'A', ended: 0,
    chatErrors: [], reports: [], consoleErrors: [],
  };
  const voiceLifecycle = makeOwner(false);
  const chatRequests = conversationState.createChatRequestTracker();
  chatRequests.begin();
  let sessionPromise = null;
  let sessionListener = null;
  const mkBridge = () => ({
    stop: async () => { stops.push(enqueued.length); },
    beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
    addListener: async () => ({ remove() {} }),
    enqueue: (url) => {
      const tok = url.split('/').pop();
      enqueueCalls.push(tok);
      if (tok.startsWith('old')) {
        if (enqueueCalls.filter(t => t === tok).length >= 4) {
          return new Promise((_, reject) => deferredOldRejections.push(() => reject(new Error('clip gone'))));
        }
        throw new Error('clip gone');
      }
      enqueued.push(tok);
    },
    markEndOfQueue: async () => { state.ended++; },
  });
  const bridge = mkBridge();
  function mkDeps() {
    const source = playbackSource.createMessageSource({
      sanitize: voiceText.sanitizeForTTS,
      isTrackerGenerating: () => chatRequests.isGenerating(),
      isTrackerLive: (s) => chatRequests.isLive(s),
      boundSeq: chatRequests.seq(),
    });
    function publish() {
      source.publish({ original: texts[state.phase], fallbackVisible: '' });
    }
    publish();
    return {
      voiceLifecycle,
      split: voiceText.splitSentences,
      terminator: voiceText.sentenceEndsWithTerminator,
      sanitize: voiceText.sanitizeForTTS,
      source: source,
      observeChanges: (cb) => { observers.push(cb); return () => {}; },
      fetchVoiceRetry: (url, options) => {
        return new Promise((resolve, reject) => {
          const text = JSON.parse(options.body).text;
          posts.push({ text, resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); }, reject });
        });
      },
      withCsrf: (headers) => headers,
      sleepMs: () => new Promise(resolve => sleepers.push(resolve)),
      isRetryableVoiceStatus: (status) => status === 429 || status >= 500,
      getNativeBridge: () => bridge,
      streamUrl: (token) => 'https://chat/tts_stream/' + token,
      cancelToken: (token) => cancelled.push(token),
      stopDesktop: () => { voiceLifecycle.stopDesktopPlayback(); },
      stopAll: (opts) => { voiceLifecycle.stopAllPlayback(opts); },
      abortStt: () => {},
      vadReset: () => {},
      resetPlayButton: () => {},
      clearMessageUi: () => {},
      syncSendButton: () => {},
      setButtonPlaying: () => {},
      notifyStarted: () => { voiceLifecycle.notePlaybackStarted(); },
      notifyEnded: () => { voiceLifecycle.notePlaybackEnded(); },
      reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
      appendMessage: (t) => { state.chatErrors.push(String(t)); },
      logError: (...a) => { state.consoleErrors.push(a.join(' ')); },
      setTimeout: () => 1,
      clearTimeout: () => {},
      isVoiceModeActive: () => false,
      getSessionPromise: () => sessionPromise,
      setSessionPromise: (p) => { sessionPromise = p; },
      getSessionListener: () => sessionListener,
      setSessionListener: (l) => { sessionListener = l; },
      nativeStop: () => bridge.stop().catch(() => {}),
      invalidateNative: () => {
        voiceLifecycle.invalidateNativeSession();
        sessionPromise = null;
        sessionListener = null;
      },
      finishNative: (generation, button) => {
        if (voiceLifecycle.finishNativePlayback(generation, button)) finishedGens.push(generation);
      },
      fallbackPlay: () => {},
      createAbortController: () => new AbortController(),
    };
  }
  // First session uses its own deps; replacement invalidates generation via
  // the shared lifecycle owner, mirroring chat's invalidateNativeVoiceTts.
  const allDeps = [];
  const depsA = mkDeps();
  allDeps.push(depsA);
  ttsPlayback.playNativeVoiceModeTts(depsA, {}, {});
  return {
    posts, enqueued, cancelled, stops, finishedGens, observers, state, texts,
    enqueueCalls, deferredOldRejections, chatRequests,
    playReplacement(btn) {
      const depsB = mkDeps();
      allDeps.push(depsB);
      ttsPlayback.playNativeVoiceModeTts(depsB, btn, {});
      return depsB;
    },
    publishCurrent() {
      // New text arriving on the live message is a source publish event, the
      // way chat's stream append callbacks publish (only the live session's
      // source moves; the replaced session stays dead).
      const current = texts[state.phase];
      const live = allDeps[allDeps.length - 1];
      if (live && live.source) live.source.publish({ original: current, fallbackVisible: '' });
    },
    wake() {
      const pending = sleepers.splice(0);
      pending.forEach(resolve => resolve());
    },
  };
}

(async () => {
  // Desktop streaming: first sentence fails throughout; second must never play.
  {
    const s = desktopStreamingSession();
    await s.settle();
    assert.deepEqual(s.state.played, [
      'First sentence here.', 'First sentence here.',
      'First sentence here.', 'First sentence here.',
    ], 'desktop must retry the failed sentence, never advance: ' + JSON.stringify(s.state.played));
    assert.equal(s.state.completed, 1, 'desktop must end the session');
    assert.deepEqual(s.state.chatErrors, ['Voice output failed. Try again.'], 'desktop must show the failure');
    assert(s.state.reports.includes('VOICE-ERROR:TTS sentence failed (desktop)'), 'desktop must report the failure');
  }

  // Fixed list: same fail-stop contract on the click path.
  {
    const s = fixedListSession();
    await s.settle();
    assert.deepEqual(s.state.played, [
      'Alpha one here.', 'Alpha one here.', 'Alpha one here.', 'Alpha one here.',
    ], 'fixed list must retry the failed sentence, never advance: ' + JSON.stringify(s.state.played));
    assert.equal(s.state.completed, 1, 'fixed list must end the session');
    assert.deepEqual(s.state.chatErrors, ['Voice output failed. Try again.'], 'fixed list must show the failure');
    assert(s.state.reports.includes('VOICE-ERROR:TTS sentence failed (fixed list)'), 'fixed list must report the failure');
  }

  // Native: token requests fail throughout; nothing may enqueue or finish cleanly.
  {
    const s = nativeFailingSession();
    await s.settle();
    assert.deepEqual(s.enqueued, [], 'native must not enqueue after exhaustion: ' + JSON.stringify(s.enqueued));
    assert.equal(s.state.finished, 1, 'native must end the session');
    assert.equal(s.state.ended, 0, 'native must not mark a clean end of queue');
    assert.deepEqual(s.state.chatErrors, ['Voice output failed. Try again.'], 'native must show the failure');
    assert(s.state.reports.includes('VOICE-ERROR:TTS sentence failed (native)'), 'native must report the failure');
    assert(s.posts.length >= 4 && s.posts.length <= 8, 'native must bound retries, got ' + s.posts.length);
    assert(s.posts.every(p => p.text === 'One here now.' || p.text === 'Two here now.'), 'native must not advance beyond the window');
  }

  // Replacement race: an old session's FINAL enqueue attempt is still in
  // flight when a new session begins playing; its rejection must not stop
  // the new playback or finish any generation.
  {
    const t = nativeReplacementHarness();
    const btnA = {}, btnB = {};
    // First play already started in harness constructor; drive it.
    await flush();
    assert.deepEqual(t.posts.map(p => p.text), ['Apple apple.'], 'old session queues while live');
    t.posts.forEach((p, i) => p.resolve('old-' + i));
    await flush();
    for (let i = 0; i < 3; i++) { t.wake(); await flush(); }
    assert.equal(t.deferredOldRejections.length, 1, 'old final attempt must be in flight before replacement');
    t.playReplacement(btnB);
    t.state.phase = 'B';
    t.publishCurrent();
    await flush();
    assert.deepEqual(t.posts.map(p => p.text), ['Apple apple.', 'Cherry cherry.'], 'new session queues after replacement');
    t.posts.slice(1).forEach((p, i) => p.resolve('new-' + i));
    await flush();
    assert.deepEqual(t.enqueued, ['new-0'], 'new playback begins');
    t.deferredOldRejections.splice(0).forEach(reject => reject());
    await flush();
    assert(t.stops.every(n => n === 0), 'stale failure must not stop new playback, stops saw enqueued: ' + JSON.stringify(t.stops));
    assert.deepEqual(t.finishedGens, [], 'stale failure must not finish any generation: ' + JSON.stringify(t.finishedGens));
    assert.deepEqual(t.enqueued, ['new-0'], 'new playback intact');
    assert.deepEqual(t.state.chatErrors, [], 'stale failure stays silent');
    assert.deepEqual(t.state.reports, [], 'stale failure stays silent');
    t.chatRequests.finish(t.chatRequests.seq());
    t.observers[1]();
    await flush();
    assert.equal(t.state.ended, 1, 'new session marks end of queue');
  }

  console.error('tts exhaustion: all queues end the session with a visible error, never advance');
})().catch(error => { console.error(error); process.exitCode = 1; });
