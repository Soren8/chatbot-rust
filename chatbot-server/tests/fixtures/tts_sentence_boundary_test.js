'use strict';
// Streaming TTS sentence boundaries on the REAL desktop + native queues.
//
// Sentence/normalize helpers come from the shared static/voice-text.js unit
// (stable import); the real playMessageBodyTts + playNativeVoiceModeTts queue
// logic is exercised from static/chat.js (leaf I/O mocked). Extendable
// trailing fragments (colon, digit period, all-caps initialism, known
// abbreviations/honorifics) must wait while generating so both queues speak
// each sentence once; ordinary endings stream at once. A chunk that only
// appends punctuation/closers to an already-queued sentence is ignored
// instead of repeated.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chatJsPath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
const voiceLifecyclePath = process.argv[5];
assert(
  chatJsPath && voiceTextPath && conversationStatePath && voiceLifecyclePath,
  'usage: node tts_sentence_boundary_test.js <static/chat.js> <static/voice-text.js> <static/conversation-state.js> <static/voice-lifecycle.js>'
);
const source = fs.readFileSync(chatJsPath, 'utf8');
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);

function extractTop(name) {
  const header = 'function ' + name + '(';
  const start = source.indexOf(header);
  assert(start >= 0, name + ' must be declared in static/chat.js');
  const open = source.indexOf('{', start);
  const close = source.indexOf('\n}\n', open);
  assert(close > open, 'unbalanced braces in ' + name);
  return source.slice(start, close + 2);
}

const desktopSrc = extractTop('playMessageBodyTts');
const nativeStart = source.indexOf('  function playNativeVoiceModeTts(');
const nativeEnd = source.indexOf('  window.playNativeVoiceModeTts =', nativeStart);
assert(nativeStart >= 0 && nativeEnd > nativeStart, 'native TTS entry point must be available');
const nativeSrc = source.slice(nativeStart, nativeEnd);

async function flush() {
  for (let i = 0; i < 80; i++) await Promise.resolve();
}

function desktopSession() {
  const state = {
    raw: '', domText: '', generating: true, played: [], preloaded: [],
    completed: 0, chatErrors: [], reports: [], consoleErrors: [], timers: [],
    observer: null, live: true,
  };
  const element = {
    0: {},
    find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; },
    text() { return state.domText; },
    prop(name, value) { if (value !== undefined) return this; return true; },
    addClass() { return this; }, removeClass() { return this; }, html() { return this; },
    attr() { return ''; },
  };
  // Generating state comes from the real conversation request tracker, the
  // single authority chat.js reads via chatRequests.isGenerating(). Lifecycle
  // liveness/completion delegate to the real voice owner through coherent
  // adapters (no copied algorithm).
  const chatRequests = conversationState.createChatRequestTracker();
  let liveSeq = chatRequests.begin();
  const voiceLifecycle = voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => false,
    stopNativePlayback: () => {},
  });
  voiceLifecycle.stopDesktopPlayback();
  voiceLifecycle.beginDesktopPlayback({});
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); }, log() {}, debug() {}, warn() {} },
    Promise, Set, Map,
    setTimeout(fn) { state.timers.push(fn); return state.timers.length; },
    clearTimeout() {},
    $() { return element; },
    chatRequests, voiceLifecycle,
    desktopTtsIsLive(id) { return state.live && voiceLifecycle.isLiveDesktop(id); },
    completeDesktopTtsPlayback(button) {
      voiceLifecycle.completeDesktopPlayback(button);
      state.completed++; state.live = false;
    },
    preloadDesktopTtsSentence(sessionId, text) { state.preloaded.push(String(text)); },
    playOneTtsUtterance(sessionId, text) { state.played.push(String(text)); return Promise.resolve(true); },
    getMessageTtsText() { return context.sanitizeForTTS(state.raw); },
    MAX_TTS_SENTENCE_RETRIES: 3,
    MutationObserver: class { constructor(cb) { state.observer = cb; } observe() {} disconnect() { state.observer = null; } },
    window: { voiceModeActive: false },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
  });
  context.isAsciiDigit = voiceText.isAsciiDigit;
  context.sentenceEndsWithTerminator = voiceText.sentenceEndsWithTerminator;
  context.splitSentences = voiceText.splitSentences;
  context.sanitizeForTTS = voiceText.sanitizeForTTS;
  vm.runInContext(desktopSrc, context);
  context.playMessageBodyTts(1, {}, element);
  return {
    state, context,
    stream(raw) {
      state.raw = raw; state.domText = raw;
      if (!chatRequests.isGenerating()) liveSeq = chatRequests.begin();
      state.observer();
    },
    finish(raw) {
      if (raw !== undefined) { state.raw = raw; state.domText = raw; }
      state.generating = false;
      if (chatRequests.isGenerating()) chatRequests.finish(liveSeq);
      state.observer();
    },
  };
}

function nativeSession() {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const state = {
    raw: '', generating: true, ended: 0, finished: 0, listener: null,
    observer: null, chatErrors: [], reports: [], consoleErrors: [],
  };
  const element = {
    0: {},
    find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; },
    text() { return state.raw; },
    prop(name, value) { if (value !== undefined) return this; return true; },
    addClass() { return this; }, html() { return this; },
  };
  let timer = 0;
  const chatRequests = conversationState.createChatRequestTracker();
  let liveSeq = chatRequests.begin();
  const voiceLifecycle = voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => false,
    stopNativePlayback: () => {},
  });
  const context = vm.createContext({
    console: { error(...a) { state.consoleErrors.push(a.join(' ')); } },
    AbortController, Promise, Set, Map,
    setTimeout() { return ++timer; }, clearTimeout() {},
    $() { return element; }, chatRequests, voiceLifecycle,
    nativeMicBridge: null,
    voiceSttAbortController: null,
    nativeVoiceTtsSessionPromise: null, nativeVoiceTtsSessionListener: null,
    MAX_TTS_SENTENCE_RETRIES: 3, MAX_NATIVE_TTS_LOOKAHEAD: 4,
    getMessageTtsText: () => '',
    withCsrf: headers => headers,
    nativeVoiceTtsStreamUrl: token => 'https://chat/tts_stream/' + token,
    cancelNativeTtsToken: token => cancelled.push(token),
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: status => status === 429 || status >= 500,
    stopCurrentDesktopTts() { voiceLifecycle.stopDesktopPlayback(); },
    stopAllTtsPlayback(opts) { voiceLifecycle.stopAllPlayback(opts); },
    resetPlayButtonUi() {}, clearMessageTtsPlayingUi() {},
    syncSendButtonState() {},
    onVoiceModeTtsStarted() { voiceLifecycle.notePlaybackStarted(); },
    finishNativeVoiceTts(generation, button) {
      if (voiceLifecycle.finishNativePlayback(generation, button)) state.finished++;
    },
    reportVoice(k, m) { state.reports.push(k + ':' + m); },
    appendMessage(t) { state.chatErrors.push(String(t)); },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        posts.push({
          text: JSON.parse(options.body).text, reject,
          resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); },
        });
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
  context.isAsciiDigit = voiceText.isAsciiDigit;
  context.sentenceEndsWithTerminator = voiceText.sentenceEndsWithTerminator;
  context.splitSentences = voiceText.splitSentences;
  context.sanitizeForTTS = voiceText.sanitizeForTTS;
  context.getMessageTtsText = () => context.sanitizeForTTS(state.raw);
  context.invalidateNativeVoiceTts = () => {
    voiceLifecycle.invalidateNativeSession();
    context.nativeVoiceTtsSessionPromise = null;
    context.nativeVoiceTtsSessionListener = null;
  };
  vm.runInContext(nativeSrc, context);
  context.playNativeVoiceModeTts({}, {});
  return {
    posts, enqueued, cancelled, state, context,
    stream(raw) {
      state.raw = raw;
      if (!chatRequests.isGenerating()) liveSeq = chatRequests.begin();
      state.observer();
    },
    finish(raw) {
      if (raw !== undefined) state.raw = raw;
      state.generating = false;
      if (chatRequests.isGenerating()) chatRequests.finish(liveSeq);
      state.observer();
    },
  };
}

async function checkDesktop(name, raws, expected, holdFirst) {
  const s = desktopSession();
  await flush();
  s.stream(raws[0]);
  await flush();
  if (holdFirst) {
    assert.deepEqual(s.state.played, [], name + ' desktop must hold the extendable fragment while generating');
  } else {
    assert.deepEqual(s.state.played, [expected[0]], name + ' desktop must stream the stable sentence at once');
  }
  for (let i = 1; i < raws.length - 1; i++) {
    s.stream(raws[i]);
    await flush();
  }
  s.finish(raws[raws.length - 1]);
  await flush();
  assert.deepEqual(s.state.played, expected, name + ' desktop must speak once in order: ' + JSON.stringify(s.state.played));
}

async function checkNative(name, raws, expected, holdFirst) {
  const s = nativeSession();
  await flush();
  s.stream(raws[0]);
  await flush();
  if (holdFirst) {
    assert.deepEqual(s.posts.map(p => p.text), [], name + ' native must hold the extendable fragment while generating');
  } else {
    assert.deepEqual(s.posts.map(p => p.text), [expected[0]], name + ' native must stream the stable sentence at once');
  }
  for (let i = 1; i < raws.length - 1; i++) {
    s.stream(raws[i]);
    await flush();
  }
  s.finish(raws[raws.length - 1]);
  await flush();
  assert.deepEqual(s.posts.map(p => p.text), expected, name + ' native must request once in order: ' + JSON.stringify(s.posts.map(p => p.text)));
  s.posts.forEach((p, i) => p.resolve('tok' + i));
  await flush();
  assert.deepEqual(s.enqueued, s.posts.map((p, i) => 'tok' + i), name + ' native must enqueue once in order');
  assert.equal(s.state.ended, 1, name + ' native must mark end of queue');
}

(async () => {
  const cases = [
    ['colon continuation',
      ['Reminder:', 'Reminder: bring the keys.', 'Reminder: bring the keys. See you soon.'],
      ['Reminder: bring the keys.', 'See you soon.'], true],
    ['colon before newline',
      ['Steps:', 'Steps:\nDo this first.', 'Steps:\nDo this first. Then that.'],
      ['Steps:', 'Do this first.', 'Then that.'], true],
    ['decimal continuation',
      ['Version 4.', 'Version 4.6 is out.'],
      ['Version 4.6 is out.'], true],
    ['initialism continuation',
      ['He visited the U.S.', 'He visited the U.S. economy is strong.'],
      ['He visited the US economy is strong.'], true],
    ['ellipsis continuation',
      ['Wait', 'Wait...', 'Wait... Still going.'],
      ['Wait...', 'Still going.'], true],
    ['punctuation burst extension speaks once',
      ['Hello.', 'Hello...', 'Hello... Next sentence.'],
      ['Hello.', 'Next sentence.'], false],
    ['closing quote extension speaks once',
      ['Say "hi.', 'Say "hi."', 'Say "hi." Bye.'],
      ['Say "hi.', 'Bye.'], false],
    ['question burst extension speaks once',
      ['Really?', 'Really?!', 'Really?! Next one.'],
      ['Really?', 'Next one.'], false],
    ['abbreviation etc continuation',
      ['See etc.', 'See etc. stuff here.'],
      ['See etc. stuff here.'], true],
    ['honorific continuation',
      ['Visit St.', 'Visit St. Louis today.'],
      ['Visit St. Louis today.'], true],
    ['lowercase honorific continuation',
      ['See mr.', 'See mr. smith here.'],
      ['See mr. smith here.'], true],
    ['approx expansion holds',
      ['It costs approx.', 'It costs approx. 50 bucks.'],
      ['It costs approximately 50 bucks.'], true],
    ['closing quote continuation',
      ['He said "Hi', 'He said "Hi."', 'He said "Hi." Bye.'],
      ['He said "Hi."', 'Bye.'], true],
    ['single newline',
      ['Hello world.', 'Hello world.\nNext line here.'],
      ['Hello world.', 'Next line here.'], false],
    ['paragraph newline',
      ['Para one.', 'Para one.\n\nPara two.'],
      ['Para one.', 'Para two.'], false],
    ['stable period streams immediately',
      ['Hello world.', 'Hello world. Still going.'],
      ['Hello world.', 'Still going.'], false],
  ];
  const failures = [];
  for (const [name, raws, expected, holdFirst] of cases) {
    for (const check of [checkDesktop, checkNative]) {
      try {
        await check(name, raws, expected, holdFirst);
      } catch (error) {
        failures.push(name + ' [' + check.name + ']: ' + (error && error.message ? error.message : String(error)));
      }
    }
  }
  if (failures.length) {
    console.error('tts sentence boundaries FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('tts sentence boundaries: all scenarios speak once, in order, on both real queues');
})().catch(error => { console.error(error); process.exitCode = 1; });
