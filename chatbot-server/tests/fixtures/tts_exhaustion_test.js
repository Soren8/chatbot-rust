'use strict';
// TTS retry exhaustion ends the session with a visible error on the REAL
// desktop streaming, fixed-list, and native queues (leaf I/O failing).
// Nothing after the failed sentence may play or post; the chat error bubble
// is the user-visible signal, with console + server telemetry for diagnosis.
// A stale session failing after replacement must not touch the new playback.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chatJsPath = process.argv[2];
assert(chatJsPath, 'usage: node tts_exhaustion_test.js <static/chat.js>');
const source = fs.readFileSync(chatJsPath, 'utf8');

function extractTop(name) {
  const header = 'function ' + name + '(';
  const start = source.indexOf(header);
  assert(start >= 0, name + ' must be declared in static/chat.js');
  const open = source.indexOf('{', start);
  const close = source.indexOf('\n}\n', open);
  assert(close > open, 'unbalanced braces in ' + name);
  return source.slice(start, close + 2);
}

const langSrc = ['isAsciiDigit', 'sentenceEndsWithTerminator', 'splitSentences', 'sanitizeForTTS'].map(extractTop);
const streamingSrc = extractTop('playMessageBodyTts');
const fixedSrc = extractTop('playFixedSentenceList');
const nativeStart = source.indexOf('  function playNativeVoiceModeTts(');
const nativeEnd = source.indexOf('  window.playNativeVoiceModeTts =', nativeStart);
assert(nativeStart >= 0 && nativeEnd > nativeStart, 'native TTS entry point must be available');
const nativeSrc = source.slice(nativeStart, nativeEnd);

async function flush() {
  for (let i = 0; i < 80; i++) await Promise.resolve();
}

function desktopStreamingSession() {
  const state = {
    raw: 'First sentence here. Second sentence here.', generating: false,
    played: [], completed: 0, chatErrors: [], reports: [], consoleErrors: [],
    timers: [], observer: null, live: true,
  };
  const element = {
    0: {},
    find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; },
    text() { return state.raw; },
    prop(name, value) { if (value !== undefined) return this; return true; },
    addClass() { return this; }, removeClass() { return this; }, html() { return this; },
    attr() { return ''; },
  };
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); }, log() {}, debug() {}, warn() {} },
    Promise, Set, Map,
    setTimeout(fn) { state.timers.push(fn); return state.timers.length; },
    clearTimeout() {},
    $() { return element; },
    currentAbortController: null,
    desktopTtsIsLive(id) { return state.live && id === 1; },
    completeDesktopTtsPlayback() { state.completed++; state.live = false; },
    preloadDesktopTtsSentence() {},
    playOneTtsUtterance(sessionId, text) { state.played.push(String(text)); return Promise.resolve(false); },
    getMessageTtsText() { return context.sanitizeForTTS(state.raw); },
    MAX_TTS_SENTENCE_RETRIES: 3,
    MutationObserver: class { constructor(cb) { state.observer = cb; } observe() {} disconnect() { state.observer = null; } },
    window: { voiceModeActive: false },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
  });
  for (const src of langSrc) vm.runInContext(src, context);
  vm.runInContext(streamingSrc, context);
  context.playMessageBodyTts(1, {}, element);
  return {
    state, context,
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
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); }, log() {}, debug() {}, warn() {} },
    Promise, Set, Map,
    setTimeout(fn) { state.timers.push(fn); return state.timers.length; },
    clearTimeout() {},
    desktopTtsIsLive(id) { return state.live && id === 1; },
    completeDesktopTtsPlayback() { state.completed++; state.live = false; },
    preloadDesktopTtsSentence() {},
    playOneTtsUtterance(sessionId, text) { state.played.push(String(text)); return Promise.resolve(false); },
    MAX_TTS_SENTENCE_RETRIES: 3,
    window: { voiceModeActive: false },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
  });
  vm.runInContext(fixedSrc, context);
  context.playFixedSentenceList(1, {}, ['Alpha one here.', 'Beta two here.']);
  return {
    state, context,
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
    raw: 'One here now. Two here now.', generating: false,
    ended: 0, finished: 0, listener: null, observer: null,
    chatErrors: [], reports: [], consoleErrors: [],
  };
  const element = {
    0: {},
    find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; },
    text() { return state.raw; },
    prop(name, value) { if (value !== undefined) return this; return true; },
    addClass() { return this; }, html() { return this; },
  };
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); } },
    AbortController, Promise, Set, Map,
    setTimeout() { return 1; }, clearTimeout() {},
    $() { return element; }, currentAbortController: null,
    CURRENT_AUDIO: null, CURRENT_AUDIO_BUTTON: null, nativeMicBridge: null,
    voiceSttAbortController: null, nativeVoiceTtsGeneration: 0,
    nativeVoiceTtsSessionPromise: null, nativeVoiceTtsSessionListener: null,
    voiceModeTtsSessionActive: false, voiceModeTtsPlaying: false,
    MAX_TTS_SENTENCE_RETRIES: 3, MAX_NATIVE_TTS_LOOKAHEAD: 4,
    getMessageTtsText: () => '',
    withCsrf: headers => headers,
    nativeVoiceTtsStreamUrl: token => 'https://chat/tts_stream/' + token,
    cancelNativeTtsToken: token => cancelled.push(token),
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: status => status === 429 || status >= 500,
    stopCurrentDesktopTts() {}, resetPlayButtonUi() {}, clearMessageTtsPlayingUi() {},
    syncSendButtonState() {}, onVoiceModeTtsStarted() {},
    finishNativeVoiceTts() { state.finished++; },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        posts.push({ text: JSON.parse(options.body).text, reject });
        reject(new Error('network lost'));
      });
    },
    MutationObserver: class { constructor(cb) { state.observer = cb; } observe() {} disconnect() { state.observer = null; } },
    window: {
      nativeVoiceTtsAvailable: true, voiceModeActive: false,
      NativeVoiceTts: {
        stop: async () => {},
        beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
        addListener: async (name, listener) => { state.listener = listener; return { remove() {} }; },
        enqueue: async url => { enqueued.push(url.split('/').pop()); },
        markEndOfQueue: async () => { state.ended++; },
      },
    },
  });
  for (const src of langSrc) vm.runInContext(src, context);
  context.getMessageTtsText = () => context.sanitizeForTTS(state.raw);
  context.invalidateNativeVoiceTts = () => {
    context.nativeVoiceTtsGeneration++;
    context.nativeVoiceTtsSessionPromise = null;
  };
  vm.runInContext(nativeSrc, context);
  context.playNativeVoiceModeTts({}, {});
  return {
    posts, enqueued, cancelled, state, context,
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
  const element = {
    0: {},
    find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; },
    text() { return texts[state.phase]; },
    prop(name, value) { if (value !== undefined) return this; return true; },
    addClass() { return this; }, html() { return this; },
  };
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); } },
    AbortController, Promise, Set, Map,
    setTimeout() { return 1; }, clearTimeout() {},
    $() { return element; }, currentAbortController: {},
    CURRENT_AUDIO: null, CURRENT_AUDIO_BUTTON: null, nativeMicBridge: null,
    voiceSttAbortController: null, nativeVoiceTtsGeneration: 0,
    nativeVoiceTtsSessionPromise: null, nativeVoiceTtsSessionListener: null,
    voiceModeTtsSessionActive: false, voiceModeTtsPlaying: false,
    MAX_TTS_SENTENCE_RETRIES: 3, MAX_NATIVE_TTS_LOOKAHEAD: 4,
    getMessageTtsText() { return context.sanitizeForTTS(texts[state.phase]); },
    withCsrf: headers => headers,
    nativeVoiceTtsStreamUrl: token => 'https://chat/tts_stream/' + token,
    cancelNativeTtsToken: token => cancelled.push(token),
    sleepMs: () => new Promise(resolve => sleepers.push(resolve)),
    isRetryableVoiceStatus: status => status === 429 || status >= 500,
    stopCurrentDesktopTts() {}, resetPlayButtonUi() {}, clearMessageTtsPlayingUi() {},
    stopAllTtsPlayback() {},
    syncSendButtonState() {}, onVoiceModeTtsStarted() {},
    finishNativeVoiceTts(generation) { finishedGens.push(generation); },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        const text = JSON.parse(options.body).text;
        posts.push({ text, resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); }, reject });
      });
    },
    MutationObserver: class { constructor(cb) { observers.push(cb); } observe() {} disconnect() {} },
    window: {
      nativeVoiceTtsAvailable: true, voiceModeActive: false,
      NativeVoiceTts: {
        stop: async () => { stops.push(enqueued.length); },
        beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
        addListener: async () => ({ remove() {} }),
        enqueue: url => {
          const tok = url.split('/').pop();
          enqueueCalls.push(tok);
          if (tok.startsWith('old')) {
            // Final attempt (attempt index 3) stays pending so the test can
            // land its rejection after the replacement session began playing.
            if (enqueueCalls.filter(t => t === tok).length >= 4) {
              return new Promise((_, reject) => deferredOldRejections.push(() => reject(new Error('clip gone'))));
            }
            throw new Error('clip gone');
          }
          enqueued.push(tok);
        },
        markEndOfQueue: async () => { state.ended++; },
      },
    },
  });
  for (const src of langSrc) vm.runInContext(src, context);
  context.invalidateNativeVoiceTts = () => {
    context.nativeVoiceTtsGeneration++;
    context.nativeVoiceTtsSessionPromise = null;
  };
  vm.runInContext(nativeSrc, context);
  return {
    posts, enqueued, cancelled, stops, finishedGens, observers, state, context, texts,
    enqueueCalls, deferredOldRejections,
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
    t.context.playNativeVoiceModeTts(btnA, {});
    await flush();
    assert.deepEqual(t.posts.map(p => p.text), ['Apple apple.'], 'old session queues while live');
    t.posts.forEach((p, i) => p.resolve('old-' + i));
    await flush();
    // Drive attempts 0-2; the final attempt parks on a deferred rejection.
    // (One sentence: the shared enqueue tail serializes jobs, so a single
    // sentence keeps the interleaving deterministic.)
    for (let i = 0; i < 3; i++) { t.wake(); await flush(); }
    assert.equal(t.deferredOldRejections.length, 1, 'old final attempt must be in flight before replacement');
    t.context.playNativeVoiceModeTts(btnB, {});
    t.state.phase = 'B';
    await flush();
    assert.deepEqual(t.posts.map(p => p.text), ['Apple apple.', 'Cherry cherry.'], 'new session queues after replacement');
    t.posts.slice(1).forEach((p, i) => p.resolve('new-' + i));
    await flush();
    assert.deepEqual(t.enqueued, ['new-0'], 'new playback begins');
    // Land the old final rejections after replacement: stale termination here
    // would stop the new playback.
    t.deferredOldRejections.splice(0).forEach(reject => reject());
    await flush();
    assert(t.stops.every(n => n === 0), 'stale failure must not stop new playback, stops saw enqueued: ' + JSON.stringify(t.stops));
    assert.deepEqual(t.finishedGens, [], 'stale failure must not finish any generation: ' + JSON.stringify(t.finishedGens));
    assert.deepEqual(t.enqueued, ['new-0'], 'new playback intact');
    assert.deepEqual(t.state.chatErrors, [], 'stale failure stays silent');
    assert.deepEqual(t.state.reports, [], 'stale failure stays silent');
    t.context.currentAbortController = null;
    t.observers[1]();
    await flush();
    assert.equal(t.state.ended, 1, 'new session marks end of queue');
  }

  console.error('tts exhaustion: all queues end the session with a visible error, never advance');
})().catch(error => { console.error(error); process.exitCode = 1; });
