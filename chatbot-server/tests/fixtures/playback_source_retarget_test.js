'use strict';
// Regression: retargeting a finished (historical) source to a replacement
// sequence must atomically restart it — bound sequence, cleared text,
// unfinished — with a single notify, on the REAL owned desktop + native
// queues with the real voice-text splitter, conversation tracker, and
// voice-lifecycle owner. Leaf I/O (clip fetch, token POST, bridge) is
// stubbed; no queue/parse/projection code is copied.
//
// The previous two-step retarget left finished=true (a fresh autoplay queue
// on the empty source completed before chunks arrived) and notified with
// the stale text first (a fresh queue enqueued the old answer).
const assert = require('node:assert/strict');

const ttsPlaybackPath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
const voiceLifecyclePath = process.argv[5];
const playbackSourcePath = process.argv[6];
assert(
  ttsPlaybackPath && voiceTextPath && conversationStatePath && voiceLifecyclePath && playbackSourcePath,
  'usage: node playback_source_retarget_test.js <static/tts-playback.js> <static/voice-text.js> <static/conversation-state.js> <static/voice-lifecycle.js> <static/playback-source.js>'
);
const ttsPlayback = require(ttsPlaybackPath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);
const playbackSource = require(playbackSourcePath);

const OLD = 'Old answer here. Done.';
const OLD_SENT = ['Old answer here.', 'Done.'];
const PARTIAL = 'New partial';
const FULL = 'New partial here. Done.';
const FULL_SENT = ['New partial here.', 'Done.'];

async function flush() {
  for (let i = 0; i < 80; i++) await Promise.resolve();
}

function makeOwner() {
  return voiceLifecycleMod.createVoiceLifecycle({
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
}

function makeSource(chatRequests, boundSeq) {
  return playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: boundSeq,
  });
}

function desktopQueue(source) {
  const state = { played: [], completed: 0, timers: [], observer: null, live: true };
  const lifecycle = makeOwner();
  lifecycle.stopDesktopPlayback();
  lifecycle.beginDesktopPlayback({});
  const deps = {
    isLive: (id) => state.live && lifecycle.isLiveDesktop(id),
    onComplete: (button) => {
      lifecycle.completeDesktopPlayback(button);
      state.completed++; state.live = false;
    },
    source: source,
    split: voiceText.splitSentences,
    terminator: voiceText.sentenceEndsWithTerminator,
    preload: () => {},
    playOne: (sessionId, text) => { state.played.push(String(text)); return Promise.resolve(true); },
    reportVoice: () => {},
    appendMessage: () => {},
    logError: () => {},
    setTimeout: (fn) => { state.timers.push(fn); return state.timers.length; },
    clearTimeout: () => {},
    isVoiceModeActive: () => false,
    observeChanges: (cb) => { state.observer = cb; return () => { state.observer = null; }; },
  };
  ttsPlayback.playMessageBodyTts(deps, 1, {});
  return {
    state,
    async drain() {
      for (let i = 0; i < 12 && state.live; i++) {
        const timers = state.timers.splice(0);
        timers.forEach((fn) => fn());
        await flush();
      }
      await flush();
    },
  };
}

function nativeQueue(source) {
  const posts = [];
  const enqueued = [];
  const state = { ended: 0, finished: 0, observer: null, listener: null };
  const lifecycle = makeOwner();
  let sessionPromise = null;
  let sessionListener = null;
  const bridge = {
    stop: async () => {},
    beginSession: async () => ({ generation: 1, maxQueuedClips: 4 }),
    addListener: async (name, listener) => { state.listener = listener; return { remove() {} }; },
    enqueue: async (url) => { enqueued.push(url.split('/').pop()); },
    markEndOfQueue: async () => { state.ended++; },
  };
  const deps = {
    voiceLifecycle: lifecycle,
    split: voiceText.splitSentences,
    terminator: voiceText.sentenceEndsWithTerminator,
    sanitize: voiceText.sanitizeForTTS,
    source: source,
    observeChanges: (cb) => { state.observer = cb; return () => { state.observer = null; }; },
    fetchVoiceRetry: (url, options) => new Promise((resolve) => {
      const text = JSON.parse(options.body).text;
      const entry = { text, resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); } };
      posts.push(entry);
    }),
    withCsrf: (headers) => headers,
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: (status) => status === 429 || status >= 500,
    getNativeBridge: () => bridge,
    streamUrl: (token) => 'https://chat/tts_stream/' + token,
    cancelToken: () => {},
    stopDesktop: () => { lifecycle.stopDesktopPlayback(); },
    stopAll: (opts) => { lifecycle.stopAllPlayback(opts); },
    abortStt: () => {},
    vadReset: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    setButtonPlaying: () => {},
    notifyStarted: () => {},
    notifyEnded: () => {},
    reportVoice: () => {},
    appendMessage: () => {},
    logError: () => {},
    setTimeout: () => 1,
    clearTimeout: () => {},
    isVoiceModeActive: () => false,
    getSessionPromise: () => sessionPromise,
    setSessionPromise: (p) => { sessionPromise = p; },
    setSessionListener: (l) => { sessionListener = l; },
    nativeStop: () => bridge.stop().catch(() => {}),
    invalidateNative: () => { lifecycle.invalidateNativeSession(); sessionPromise = null; sessionListener = null; },
    finishNative: (generation, button) => { if (lifecycle.finishNativePlayback(generation, button)) state.finished++; },
    fallbackPlay: () => {},
    createAbortController: () => new AbortController(),
  };
  ttsPlayback.playNativeVoiceModeTts(deps, {}, {});
  return {
    posts, enqueued, state,
    async resolveAll() {
      for (let i = 0; i < 12; i++) await flush();
      posts.forEach((p, i) => { if (!p.done) { p.done = true; p.resolve('tok' + i); } });
      await flush();
      for (let i = 0; i < 12; i++) await flush();
    },
  };
}

async function checkDesktop() {
  const chatRequests = conversationState.createChatRequestTracker();
  // Settled history seed: known text, finished, unbound — tracker idle.
  const source = makeSource(chatRequests, null);
  source.publish({ original: OLD, fallbackVisible: '' });
  source.finish();

  const q1 = desktopQueue(source);
  await q1.drain();
  assert.deepEqual(q1.state.played, OLD_SENT, 'history speaks once in order: ' + JSON.stringify(q1.state.played));
  assert.equal(q1.state.completed, 1, 'history completes');

  // Regeneration restarts the same source on a live sequence.
  const seq2 = chatRequests.begin();
  source.retarget(seq2, { original: '', fallbackVisible: '' });
  assert.equal(source.isGenerating(), true, 'retarget must reopen progress on the replacement sequence');
  assert.equal(source.getText(), '', 'retarget must clear stale text atomically');

  // Fresh autoplay queue on the restarted source: nothing stale may play,
  // and it must wait for chunks instead of completing.
  const q2 = desktopQueue(source);
  await flush();
  assert.deepEqual(q2.state.played, [], 'fresh queue must not enqueue stale text upon retarget: ' + JSON.stringify(q2.state.played));
  assert.equal(q2.state.completed, 0, 'fresh queue must wait for chunks, not complete');

  // Partial trailing fragment is held while generating.
  source.publish({ original: PARTIAL, fallbackVisible: '' });
  await flush();
  assert.deepEqual(q2.state.played, [], 'partial fragment held while generating: ' + JSON.stringify(q2.state.played));

  // Full text settles: spoken once in order, then completes.
  source.publish({ original: FULL, fallbackVisible: '' });
  chatRequests.finish(seq2);
  source.finish();
  await q2.drain();
  assert.deepEqual(q2.state.played, FULL_SENT, 'replacement speaks once in order: ' + JSON.stringify(q2.state.played));
  assert.equal(q2.state.completed, 1, 'replacement completes');
}

async function checkNative() {
  const chatRequests = conversationState.createChatRequestTracker();
  const source = makeSource(chatRequests, null);
  source.publish({ original: OLD, fallbackVisible: '' });
  source.finish();

  const q1 = nativeQueue(source);
  await q1.resolveAll();
  assert.deepEqual(q1.posts.map((p) => p.text), OLD_SENT, 'history requests once in order: ' + JSON.stringify(q1.posts.map((p) => p.text)));
  assert.deepEqual(q1.enqueued, ['tok0', 'tok1'], 'history enqueues in order');
  assert.equal(q1.state.ended, 1, 'history marks end of queue');

  const seq2 = chatRequests.begin();
  source.retarget(seq2, { original: '', fallbackVisible: '' });
  assert.equal(source.isGenerating(), true, 'retarget must reopen progress on the replacement sequence');
  assert.equal(source.getText(), '', 'retarget must clear stale text atomically');

  const q2 = nativeQueue(source);
  await flush();
  assert.deepEqual(q2.posts.map((p) => p.text), [], 'fresh queue must not request stale text upon retarget: ' + JSON.stringify(q2.posts.map((p) => p.text)));
  assert.equal(q2.state.ended, 0, 'fresh queue must wait for chunks, not end');

  source.publish({ original: PARTIAL, fallbackVisible: '' });
  await flush();
  assert.deepEqual(q2.posts.map((p) => p.text), [], 'partial fragment held while generating: ' + JSON.stringify(q2.posts.map((p) => p.text)));

  source.publish({ original: FULL, fallbackVisible: '' });
  chatRequests.finish(seq2);
  source.finish();
  await q2.resolveAll();
  assert.deepEqual(q2.posts.map((p) => p.text), FULL_SENT, 'replacement requests once in order: ' + JSON.stringify(q2.posts.map((p) => p.text)));
  assert.deepEqual(q2.enqueued, ['tok0', 'tok1'], 'replacement enqueues in order');
  assert.equal(q2.state.ended, 1, 'replacement marks end of queue');
}

(async () => {
  const failures = [];
  for (const [name, check] of [['desktop', checkDesktop], ['native', checkNative]]) {
    try {
      await check();
    } catch (error) {
      failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
    }
  }
  if (failures.length) {
    console.error('playback retarget FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('playback retarget: finished source restarts without stale text on both real queues');
})().catch((error) => { console.error(error); process.exitCode = 1; });
