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

async function flushUntil(predicate, label) {
  for (let i = 0; i < 1000; i++) {
    if (predicate()) return;
    await Promise.resolve();
  }
  assert.fail('timed out waiting for ' + label);
}

const voiceText = require(require('node:path').join(require('node:path').dirname(process.argv[2]), 'voice-text.js'));
const activitySync = require(require('node:path').join(require('node:path').dirname(process.argv[2]), 'activity-sync.js'));

function session(sentences, generating = false, modern = true, realSplit = false) {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const state = { generating, sentences, ended: 0, listener: null, observer: null,
    generation: 0, beginSessions: 0, sessionEnqueues: [], queueClosed: false, messages: [], stops: 0, endMarkers: 0 };
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
    stop: async () => { state.stops++; state.queueClosed = true; },
    beginSession: async () => {
      state.beginSessions++;
      state.generation++;
      state.queueClosed = false;
      state.sessionEnqueues.push([]);
      return modern ? { generation: state.generation, maxQueuedClips: 4 } : { generation: state.generation };
    },
    addListener: async (name, listener) => { state.listener = listener; return { remove() { if (state.listener === listener) state.listener = null; } }; },
    enqueue: async url => {
      if (state.queueClosed) throw new Error('native queue closed');
      const token = url.split('/').pop();
      enqueued.push(token);
      state.sessionEnqueues[state.sessionEnqueues.length - 1].push(token);
    },
    markEndOfQueue: async () => { state.ended++; state.endMarkers++; }
  };
  const deps = {
    voiceLifecycle,
    split: realSplit ? voiceText.splitSentences : () => state.sentences.map(text => ({ text })),
    terminator: text => /[.!?]$/.test(text),
    sanitize: text => text,
    source: source,
    observeChanges: (callback) => { state.observer = callback; return () => { state.observer = null; }; },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        posts.push({ text: JSON.parse(options.body).text, key: options.headers['Idempotency-Key'], reject,
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
    appendMessage(text) { state.messages.push(text); },
    logError() {},
    setTimeout() { return ++timer; },
    clearTimeout() {},
    isVoiceModeActive: () => true,
    getSessionPromise: () => sessionPromise,
    setSessionPromise: (promise) => { sessionPromise = promise; },
    setSessionListener: (listener) => { sessionListener = listener; },
    resetNativeSession: async () => {
      sessionPromise = null;
      if (sessionListener) await Promise.resolve(sessionListener).then(handle => handle && handle.remove());
      sessionListener = null;
      state.listener = null;
    },
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
    emit(event) { state.listener(event); },
    consume(token, outcome) {
      const result = Object.assign({ type: 'clipConsumed', generation: state.generation, url: 'https://chat/tts_stream/' + token }, outcome || {});
      if (result.outcome === 'expired' || result.outcome === 'failed') state.queueClosed = true;
      state.listener(result);
    }
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
  s.consume('one', { outcome: 'played' });
  s.consume('one', { outcome: 'played' });
  await flush();
  assert.equal(s.posts.length, 5, 'one consumed clip releases exactly one slot');
  assert.equal(s.state.ended, 0, 'unknown tail cannot mark end of queue');
  s.posts[4].resolve('five');
  s.consume('two', { outcome: 'played' });
  await flush();
  s.posts[5].resolve('six');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two', 'three', 'four', 'five', 'six']);
  assert.equal(s.state.ended, 0, 'end marker waits until every bounded native slot is consumed');
  ['three', 'four', 'five', 'six'].forEach(token => s.consume(token, { outcome: 'played' }));
  await flush();
  assert.equal(s.state.ended, 1, 'end is marked after all queued clips are consumed');
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
  assert.equal(s.posts[0].key, s.posts[2].key, 'outer sentence retry retains its admission identity');
  assert.deepEqual(s.enqueued, [], 'ready tail waits through head retry');
  s.posts[2].resolve('one');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two'], 'retry plays each sentence once in order');
  s.restream(); s.restream(); await flush();
  assert.equal(s.posts.length, 3, 'duplicate published text never requeues through the real sentence pipeline');
}

async function expiredNativeTokenRenewsSameSentenceInPlace() {
  const s = session(['Keep this sentence.']);
  await flush();
  s.posts[0].resolve('expired-token');
  await flush();
  assert.deepEqual(s.enqueued, ['expired-token']);
  // Native protocol reports a download 404 as an expired token, not as a
  // consumed/skipped clip. JS must renew this exact sentence under its key.
  s.consume('expired-token', { outcome: 'expired' });
  await flush();
  assert.equal(s.posts.length, 2, 'expired token causes one bounded same-sentence re-admission');
  assert.equal(s.posts[1].text, 'Keep this sentence.', 'renewal retains the original sentence text');
  assert.equal(s.posts[1].key, s.posts[0].key, 'renewal retains the original sentence operation ID');
  s.posts[1].resolve('renewed-token');
  await flush();
  assert.equal(s.state.beginSessions, 2, 'expired native queue is replaced with a fresh session');
  assert.deepEqual(s.enqueued, ['expired-token', 'renewed-token'], 'renewed clip occupies the original queue slot');
  assert.equal(s.state.ended, 0, 'replacement session is not marked complete before playback');
  s.consume('renewed-token', { outcome: 'played' });
  await flush();
  assert.equal(s.state.ended, 1, 'successful renewed clip permits queue completion');
}

async function expiredHeadRestartsFourClipWindowInOrder() {
  const s = session(['One.', 'Two.', 'Three.', 'Four.', 'Five.']);
  await flush();
  assert.equal(s.posts.length, 4, 'native lookahead is bounded to four sentence admissions');
  ['old-one', 'two', 'three', 'four'].forEach((token, i) => s.posts[i].resolve(token));
  await flushUntil(() => s.state.sessionEnqueues[0].length === 4, 'all four admitted clips to enqueue');
  assert.deepEqual(s.state.sessionEnqueues[0], ['old-one', 'two', 'three', 'four']);

  // Native closes this queue on the expired first download and will not emit
  // clipConsumed for the later downloads that were ready behind it.
  s.consume('old-one', { outcome: 'expired' });
  await flushUntil(() => s.posts.length === 5, 'same-key admission renewal');
  assert.equal(s.posts.length, 5, 'only the expired head is renewed');
  assert.equal(s.posts[4].text, 'One.', 'renewal keeps the failed head sentence');
  assert.equal(s.posts[4].key, s.posts[0].key, 'renewal reuses the head operation key');
  s.posts[4].resolve('new-one');
  await flushUntil(() => s.state.sessionEnqueues[1] && s.state.sessionEnqueues[1].length === 4,
    'replacement session to replay all four logical clips');
  assert.equal(s.state.beginSessions, 2, 'the failed native queue is replaced');
  assert.deepEqual(s.state.sessionEnqueues[1], ['new-one', 'two', 'three', 'four'],
    'all outstanding logical jobs replay in original order without holes');
  assert.equal(s.posts.length, 5, 'lookahead slot remains occupied until a clip is played');
  assert.equal(s.state.ended, 0, 'no end marker is sent while replayed clips remain');

  s.emit({ type: 'clipConsumed', generation: 1, url: 'https://chat/tts_stream/new-one', outcome: 'played' });
  await flush();
  assert.equal(s.posts.length, 5, 'late event from the closed native generation cannot release a current slot');

  ['new-one', 'two', 'three', 'four'].forEach(token => s.consume(token, { outcome: 'played' }));
  await flushUntil(() => s.posts.length === 6, 'one freed slot to admit the fifth sentence');
  assert.equal(s.posts.length, 6, 'a played clip releases one slot for the fifth sentence');
  assert.equal(s.posts[5].text, 'Five.');
  s.posts[5].resolve('five');
  await flushUntil(() => s.state.sessionEnqueues[1].length === 5, 'fifth clip to enqueue after replayed clips');
  assert.deepEqual(s.state.sessionEnqueues[1], ['new-one', 'two', 'three', 'four', 'five']);
  ['five'].forEach(token => s.consume(token, { outcome: 'played' }));
  await flush();
  assert.equal(s.state.ended, 1, 'end marker follows the final played clip');
}

async function manualStopDuringRenewalDoesNotRestartOrRequeue() {
  const s = session(['Stop me.']);
  await flush();
  s.posts[0].resolve('expired-token');
  await flush();
  s.consume('expired-token', { outcome: 'expired' });
  await flush();
  assert.equal(s.posts.length, 2, 'renewal request is in flight');
  s.voiceLifecycle.stopAllPlayback();
  s.posts[1].resolve('late-renewal');
  await flush();
  assert.equal(s.state.beginSessions, 1, 'manual stop prevents creation of a replacement native session');
  assert.deepEqual(s.enqueued, ['expired-token'], 'manual stop prevents late renewal enqueue');
  assert(s.cancelled.includes('late-renewal'), 'late renewed token is cancelled');
  assert.equal(s.state.ended, 0, 'manual stop never marks the queue complete');
}

async function permanentNativeClipFailureSurfacesAndStops() {
  const s = session(['One.', 'Two.']);
  await flush();
  s.posts[0].resolve('one');
  s.posts[1].resolve('two');
  await flush();
  s.consume('one', { outcome: 'failed' });
  await flush();
  assert.equal(s.state.beginSessions, 1, 'permanent failure does not silently restart or skip forward');
  assert(s.state.messages.includes('Voice output failed. Try again.'), 'permanent failure is visible');
  assert(s.state.stops > 0, 'native playback is stopped on a permanent failure');
  assert.equal(s.state.endMarkers, 0, 'failed clip never advances to normal end-of-queue');
}

async function missingOrUnknownNativeOutcomeFailsClosed() {
  for (const outcome of [undefined, 'unexpected']) {
    const s = session(['One.', 'Two.']);
    await flush();
    s.posts[0].resolve('one');
    s.posts[1].resolve('two');
    await flush();
    s.consume('one', outcome === undefined ? {} : { outcome });
    await flush();
    assert(s.state.messages.includes('Voice output failed. Try again.'),
      'missing/unknown outcome is not treated as a successfully played clip');
    assert(s.state.stops > 0, 'protocol mismatch stops the native queue');
    assert.equal(s.state.endMarkers, 0, 'protocol mismatch never emits normal end-of-queue');
  }
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

async function durableReplayFeedsRealSentenceQueueOnce() {
  const s = session([], true, true, true);
  await flush();
  let views = 0;
  const urls = [];
  let text = '';
  const sync = activitySync.createActivitySync({
    fetch: async url => {
      urls.push(url);
      const first = ++views === 1;
      const events = first ? [{ seq: 1, type: 'delta', text: 'First sentence. ' }] : [
        { seq: 1, type: 'delta', text: 'First sentence. ' },
        { seq: 2, type: 'delta', text: 'Second sentence. ' },
        { seq: 3, type: 'saved' }
      ];
      let index = 0;
      return { ok: true, status: 200, body: { getReader: () => ({
        read: async () => {
          if (index < events.length) return { value: new TextEncoder().encode(JSON.stringify(events[index++]) + '\n'), done: false };
          if (first) throw new TypeError('view lost');
          return { done: true };
        }, cancel: async () => {}
      }) } };
    }, sleep: async () => {}, refreshSession: async () => true,
    onEvent: event => {
      if (event.type !== 'delta') return;
      text += event.text;
      s.state.sentences = [text];
      s.restream();
    }
  });
  await sync.attach({ generation_id: 'sentences' });
  await flush();
  assert.ok(urls[1].endsWith('after=1'), 'overlapping reconnect uses contiguous cursor');
  assert.deepEqual(s.posts.map(post => post.text), ['First sentence.', 'Second sentence.'], 'actual discovery queues each sentence once');
  s.posts.forEach((post, i) => post.resolve('replay-' + i));
  await flush();
  assert.deepEqual(s.enqueued, ['replay-0', 'replay-1'], 'actual playback queue does not replay sentences');
}

(async () => {
  await durableReplayFeedsRealSentenceQueueOnce();
  await fallbackWithoutBridgeSkipsDomAndDelegates();
  await toggleCurrentButtonStopsWithoutDomReads();
  await messageContextInitializesAtTheOriginalPoint();
  await readyHeadDoesNotWaitForSlowTailAndWindowRefills();
  await streamingTextFillsWindowWithoutWaitingForGenerationToEnd();
  await failedHeadRetriesInOrderWithoutRepostingReadyTail();
  await expiredNativeTokenRenewsSameSentenceInPlace();
  await expiredHeadRestartsFourClipWindowInOrder();
  await manualStopDuringRenewalDoesNotRestartOrRequeue();
  await permanentNativeClipFailureSurfacesAndStops();
  await missingOrUnknownNativeOutcomeFailsClosed();
  await stopCancelsLateTokensWithoutEnqueueingThem();
  await olderApkDoesNotWaitForUnsupportedConsumptionEvents();
})().catch(error => { console.error(error); process.exitCode = 1; });
