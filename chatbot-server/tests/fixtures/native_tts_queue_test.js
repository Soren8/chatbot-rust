'use strict';
// Native TTS lookahead queue on the REAL owned queue (static/tts-playback.js).
//
// Generating state comes from the real conversation request tracker and
// liveness/completion from the real voice lifecycle owner. Token/bridge I/O
// is mocked at the leaf. No source slicing, no copied queue functions.
// Entry-point parity is covered too: bridge-missing fallback and the
// current-button toggle return before any message-DOM read, while the
// success path initializes the message context exactly once at the original
// point (after teardown, before queue work).
const assert = require('node:assert/strict');

const ttsPlayback = require(process.argv[2]);
const conversationState = require(process.argv[3]);
const voiceLifecycleMod = require(process.argv[4]);
const playbackSource = require(process.argv[5]);
assert(
  process.argv[2] && process.argv[3] && process.argv[4] && process.argv[5],
  'usage: node native_tts_queue_test.js <static/tts-playback.js> <static/conversation-state.js> <static/voice-lifecycle.js> <static/playback-source.js>'
);

async function flush() {
  for (let i = 0; i < 40; i++) await Promise.resolve();
}

function session(sentences, generating = false, modern = true) {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const state = { generating, sentences, ended: 0, listener: null, observer: null };
  let timer = 0;
  // Generating state comes from the real conversation request tracker, the
  // single authority the shared per-message source reads via
  // isTrackerGenerating/isTrackerLive. Text/progress travel through that
  // explicit source, fed the way chat feeds it (bind, publish, finish);
  // the queue reads only the source.
  const chatRequests = conversationState.createChatRequestTracker();
  if (generating) chatRequests.begin();
  const source = playbackSource.createMessageSource({
    sanitize: text => text,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: chatRequests.seq(),
  });
  function publish() {
    source.publish({ original: state.sentences.join(' '), fallbackVisible: '' });
  }
  // Lifecycle comes from the real voice owner: desktop/native share one
  // owner, generations gate stale work. Coherent adapters below delegate to
  // it instead of copying the algorithm.
  const voiceLifecycle = voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => true,
    stopNativePlayback: () => {},
  });
  let sessionPromise = null;
  let sessionListener = null;
  const bridge = {
    stop: async () => {},
    beginSession: async () => modern ? { generation: 1, maxQueuedClips: 4 } : { generation: 1 },
    addListener: async (name, listener) => { state.listener = listener; return { remove() {} }; },
    enqueue: async url => { enqueued.push(url.split('/').pop()); },
    markEndOfQueue: async () => { state.ended++; }
  };
  const deps = {
    voiceLifecycle,
    split: () => state.sentences.map(text => ({ text })),
    terminator: text => /[.!?]$/.test(text),
    sanitize: text => text,
    source: source,
    observeChanges: (callback) => { state.observer = callback; return () => { state.observer = null; }; },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        posts.push({ text: JSON.parse(options.body).text, reject,
          resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); }
        });
      });
    },
    withCsrf: headers => headers,
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: status => status === 429 || status >= 500,
    getNativeBridge: () => bridge,
    streamUrl: token => 'https://chat/tts_stream/' + token,
    cancelToken: token => cancelled.push(token),
    stopDesktop() { voiceLifecycle.stopDesktopPlayback(); },
    stopAll(opts) { voiceLifecycle.stopAllPlayback(opts); },
    abortStt() {},
    vadReset() {},
    resetPlayButton() {},
    clearMessageUi() {},
    syncSendButton() {},
    setButtonPlaying() {},
    notifyStarted() { voiceLifecycle.notePlaybackStarted(); },
    notifyEnded() { voiceLifecycle.notePlaybackEnded(); },
    reportVoice() {},
    appendMessage() {},
    logError() {},
    setTimeout() { return ++timer; },
    clearTimeout() {},
    isVoiceModeActive: () => true,
    getSessionPromise: () => sessionPromise,
    setSessionPromise: (promise) => { sessionPromise = promise; },
    setSessionListener: (listener) => { sessionListener = listener; },
    nativeStop: () => bridge.stop().catch(() => {}),
    invalidateNative() {
      voiceLifecycle.invalidateNativeSession();
      sessionPromise = null;
      sessionListener = null;
    },
    finishNative(generation, button) {
      if (voiceLifecycle.finishNativePlayback(generation, button)) state.ended++;
    },
    fallbackPlay() {},
    createAbortController: () => new AbortController(),
  };
  publish();
  ttsPlayback.playNativeVoiceModeTts(deps, {}, generating ? {} : { sentences });
  return { posts, enqueued, cancelled, state, voiceLifecycle,
    restream() { publish(); },
    consume(token) { state.listener({ type: 'clipConsumed', generation: 1, url: 'https://chat/tts_stream/' + token }); }
  };
}

// Message-DOM reads live behind initMessageContext, invoked by the owned
// queue at the exact original point (after bridge/toggle early returns and
// teardown, before queue work). This harness tracks that boundary: early
// paths must never initialize the context, and the success path must order
// it after teardown and before the first token request.
function earlyPathHarness(overrides) {
  overrides = overrides || {};
  const order = [];
  const calls = { fallback: [], stopAll: [], contextInits: 0, posts: 0 };
  const voiceLifecycle = voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => true,
    stopNativePlayback: () => {},
  });
  const bridge = {
    stop: async () => { order.push('nativeStop'); },
    beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
    addListener: async () => ({ remove() {} }),
    enqueue: async () => {},
    markEndOfQueue: async () => {},
  };
  const harnessSource = playbackSource.createMessageSource({
    sanitize: text => text,
    isTrackerGenerating: () => false,
    isTrackerLive: () => true,
    boundSeq: null,
  });
  harnessSource.publish({ original: 'Hello there.', fallbackVisible: '' });
  harnessSource.finish();
  const deps = {
    voiceLifecycle,
    split: () => [{ text: 'Hello there.' }],
    terminator: () => true,
    sanitize: text => text,
    source: harnessSource,
    observeChanges: () => null,
    fetchVoiceRetry: () => {
      order.push('token');
      calls.posts++;
      return Promise.resolve({ headers: { get: () => null }, json: async () => ({}) });
    },
    withCsrf: headers => headers,
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: () => false,
    getNativeBridge: () => (overrides.bridge === undefined ? bridge : overrides.bridge),
    streamUrl: token => 'https://chat/tts_stream/' + token,
    cancelToken: () => {},
    stopDesktop() { order.push('stopDesktop'); voiceLifecycle.stopDesktopPlayback(); },
    stopAll(opts) { calls.stopAll.push(opts || {}); voiceLifecycle.stopAllPlayback(opts); },
    abortStt() { order.push('abortStt'); },
    vadReset() { order.push('vadReset'); },
    resetPlayButton() {},
    clearMessageUi() {},
    syncSendButton() {},
    setButtonPlaying() {},
    notifyStarted() {},
    notifyEnded() {},
    reportVoice() {},
    appendMessage() {},
    logError() {},
    setTimeout() { return 1; },
    clearTimeout() {},
    isVoiceModeActive: () => true,
    getSessionPromise: () => null,
    setSessionPromise: () => {},
    setSessionListener: () => {},
    nativeStop: () => bridge.stop().catch(() => {}),
    invalidateNative() { order.push('invalidate'); voiceLifecycle.invalidateNativeSession(); },
    finishNative() {},
    fallbackPlay: (btn, opts) => { calls.fallback.push([btn, opts]); },
    createAbortController: () => { order.push('abortCtl'); return new AbortController(); },
    initMessageContext: () => { order.push('context'); calls.contextInits++; deps.source = harnessSource; },
  };
  return { deps, voiceLifecycle, order, calls };
}

async function fallbackWithoutBridgeSkipsDomAndDelegates() {
  const h = earlyPathHarness({ bridge: null });
  const button = { id: 'play' };
  const options = { sentences: ['Hi.'] };
  ttsPlayback.playNativeVoiceModeTts(h.deps, button, options);
  await flush();
  assert.equal(h.calls.fallback.length, 1, 'missing bridge must fall back to desktop playback');
  assert.equal(h.calls.fallback[0][0], button, 'fallback keeps the exact button');
  assert.equal(h.calls.fallback[0][1], options, 'fallback keeps the exact options');
  assert.equal(h.calls.contextInits, 0, 'fallback must not read message DOM');
  assert.deepEqual(h.order, [], 'fallback returns before any teardown or queue work');
  assert.equal(h.calls.posts, 0, 'fallback posts no voice tokens');
  assert.equal(h.calls.stopAll.length, 0, 'fallback stops nothing');
}

async function toggleCurrentButtonStopsWithoutDomReads() {
  const h = earlyPathHarness({});
  const button = { id: 'play' };
  h.voiceLifecycle.beginNativePlayback(button, () => {});
  ttsPlayback.playNativeVoiceModeTts(h.deps, button, {});
  await flush();
  assert.equal(h.calls.stopAll.length, 1, 're-pressing the speaking button must toggle stop');
  assert.equal(h.calls.fallback.length, 0, 'toggle must not fall back to desktop');
  assert.equal(h.calls.contextInits, 0, 'toggle must not read message DOM');
  assert.deepEqual(h.order, [], 'toggle returns before teardown or queue work');
  assert.equal(h.calls.posts, 0, 'toggle posts no voice tokens');
}

async function messageContextInitializesAtTheOriginalPoint() {
  const h = earlyPathHarness({});
  ttsPlayback.playNativeVoiceModeTts(h.deps, {}, {});
  await flush();
  assert.equal(h.calls.contextInits, 1, 'message context initializes exactly once per play');
  assert.deepEqual(
    h.order.slice(0, 8),
    ['invalidate', 'nativeStop', 'stopDesktop', 'vadReset', 'abortStt', 'abortCtl', 'context', 'token'],
    'context must initialize after teardown/stop/reset and before queue work: ' + JSON.stringify(h.order)
  );
  assert.equal(h.calls.fallback.length, 0, 'native bridge present: no fallback');
}

async function readyHeadDoesNotWaitForSlowTailAndWindowRefills() {
  const s = session(['One.', 'Two.', 'Three.', 'Four.', 'Five.', 'Six.']);
  await flush();
  assert.equal(s.posts.length, 4, 'only four sentences may get tokens ahead of playback');
  s.posts[1].resolve('two');
  await flush();
  assert.deepEqual(s.enqueued, [], 'out-of-order token must wait for first');
  s.posts[0].resolve('one');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two'], 'ready head must start without waiting for slow tail tokens');
  s.posts[2].resolve('three');
  s.posts[3].resolve('four');
  await flush();
  assert.equal(s.posts.length, 4, 'token responses alone must not expand the window');
  s.consume('one');
  s.consume('one');
  await flush();
  assert.equal(s.posts.length, 5, 'one consumed clip releases exactly one slot');
  assert.equal(s.state.ended, 0, 'unknown tail cannot mark end of queue');
  s.posts[4].resolve('five');
  s.consume('two');
  await flush();
  s.posts[5].resolve('six');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two', 'three', 'four', 'five', 'six']);
  assert.equal(s.state.ended, 1, 'end is marked after all URLs have been enqueued');
}

async function streamingTextFillsWindowWithoutWaitingForGenerationToEnd() {
  const s = session(['One.'], true);
  await flush();
  s.state.sentences = ['One.', 'Two.', 'Three.', 'unfinished'];
  // Newly streamed text arrives as a source publish event (the way chat's
  // append callbacks publish); the observer backstop just re-wakes.
  s.restream();
  s.state.observer();
  await flush();
  assert.deepEqual(s.posts.map(p => p.text), ['One.', 'Two.', 'Three.'],
    'completed streaming sentences overlap token requests while fragments wait');
  assert.equal(s.state.ended, 0, 'generation still active');
  s.voiceLifecycle.stopAllPlayback();
}

async function failedHeadRetriesInOrderWithoutRepostingReadyTail() {
  const s = session(['One.', 'Two.']);
  await flush();
  s.posts[1].resolve('two');
  s.posts[0].reject(new Error('network lost'));
  await flush();
  assert.deepEqual(s.posts.map(p => p.text), ['One.', 'Two.', 'One.']);
  assert.deepEqual(s.enqueued, [], 'ready tail waits through head retry');
  s.posts[2].resolve('one');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two'], 'retry plays each sentence once in order');
}

async function stopCancelsLateTokensWithoutEnqueueingThem() {
  const s = session(['One.', 'Two.']);
  await flush();
  s.voiceLifecycle.stopAllPlayback();
  s.posts[0].resolve('late-one');
  s.posts[1].resolve('late-two');
  await flush();
  assert.deepEqual(s.enqueued, [], 'stopped session must not enqueue late tokens');
  assert(s.cancelled.includes('late-one') && s.cancelled.includes('late-two'), 'late tokens released');
}

async function olderApkDoesNotWaitForUnsupportedConsumptionEvents() {
  const s = session(['One.', 'Two.', 'Three.', 'Four.', 'Five.'], false, false);
  await flush();
  for (let i = 0; i < 5; i++) {
    assert(s.posts[i], 'old APK continues issuing tokens without clipConsumed');
    s.posts[i].resolve(String(i));
    await flush();
  }
  assert.equal(s.enqueued.length, 5);
  assert.equal(s.state.ended, 1);
}

(async () => {
  await fallbackWithoutBridgeSkipsDomAndDelegates();
  await toggleCurrentButtonStopsWithoutDomReads();
  await messageContextInitializesAtTheOriginalPoint();
  await readyHeadDoesNotWaitForSlowTailAndWindowRefills();
  await streamingTextFillsWindowWithoutWaitingForGenerationToEnd();
  await failedHeadRetriesInOrderWithoutRepostingReadyTail();
  await stopCancelsLateTokensWithoutEnqueueingThem();
  await olderApkDoesNotWaitForUnsupportedConsumptionEvents();
})().catch(error => { console.error(error); process.exitCode = 1; });
