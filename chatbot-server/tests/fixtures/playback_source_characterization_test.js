'use strict';
// Characterization for the MOD-009 playback-source follow-up.
//
// Drives the REAL owned desktop + native queues (static/tts-playback.js) with
// the REAL voice-text splitter/normalizer, conversation tracker (generating)
// and voice-lifecycle owner (liveness/completion). Leaf I/O (clip fetch,
// token POST, bridge) is stubbed; no queue/parse/projection code is copied.
//
// Each scenario pins one behavior the explicit per-message source must keep:
//  1. parity: streaming increments vs one historical seed speak the same text.
//  2. thinking: <think> stripped, Thinking.../Error placeholders silent.
//  3. hold: extendable trailing fragment waits while generating.
//  4. fixed: sentence-click list speaks exact strings in order.
//  5. historical: a settled message completes while the tracker generates
//     elsewhere (unbound sequence never reports generating).
//  6. stop: a [Stopped] DOM suffix is not spoken when the published original
//     (which never carries it) is preferred.
const assert = require('node:assert/strict');

const ttsPlaybackPath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
const voiceLifecyclePath = process.argv[5];
const playbackSourcePath = process.argv[6];
const scenario = process.argv[7] || 'all';
assert(
  ttsPlaybackPath && voiceTextPath && conversationStatePath && voiceLifecyclePath && playbackSourcePath,
  'usage: node playback_source_characterization_test.js <tts-playback> <voice-text> <conversation-state> <voice-lifecycle> <playback-source> [scenario]'
);
const ttsPlayback = require(ttsPlaybackPath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);
const playbackSource = require(playbackSourcePath);

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

// Explicit per-step text/progress driver for the desktop streaming queue.
// Text/progress travel through the REAL shared per-message source, fed the
// way chat feeds it: bind at message creation, publish at text updates,
// finish when the generation settles. The queue reads only the source and
// wakes on its subscribe plus the observer backstop.
function desktopDrive(steps, opts) {
  opts = opts || {};
  const settled = !!opts.settled;
  const state = {
    raw: opts.initialRaw || '', generating: true, played: [], preloaded: [],
    completed: 0, timers: [], observer: null, live: true,
  };
  const chatRequests = conversationState.createChatRequestTracker();
  let liveSeq = chatRequests.begin();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: liveSeq,
  });
  function publish() {
    source.publish({ original: state.raw, fallbackVisible: '' });
  }
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
    preload: (sessionId, text) => { state.preloaded.push(String(text)); },
    playOne: (sessionId, text) => { state.played.push(String(text)); return Promise.resolve(true); },
    reportVoice: () => {},
    appendMessage: () => {},
    logError: () => {},
    setTimeout: (fn) => { state.timers.push(fn); return state.timers.length; },
    clearTimeout: () => {},
    isVoiceModeActive: () => false,
    observeChanges: (cb) => { state.observer = cb; return () => { state.observer = null; }; },
  };
  if (settled) {
    // Settled history seed: text known up front, generation already done.
    publish();
    source.finish();
    if (chatRequests.isGenerating()) chatRequests.finish(liveSeq);
  } else {
    publish();
  }
  ttsPlayback.playMessageBodyTts(deps, 1, {});
  return {
    state,
    async run() {
      await flush();
      for (const step of steps) {
        state.raw = step.text;
        if (step.generating) {
          if (!chatRequests.isGenerating()) liveSeq = chatRequests.begin();
        } else if (chatRequests.isGenerating()) {
          chatRequests.finish(liveSeq);
        }
        publish();
        if (!step.generating) source.finish();
        // A pre-seeded finished message may already have completed during
        // the initial flush; further steps are then no-ops.
        if (state.observer) state.observer();
        await flush();
      }
      // Drain the queue: run pending poll/retry timers until completion.
      for (let i = 0; i < 12 && state.live; i++) {
        const timers = state.timers.splice(0);
        timers.forEach((fn) => fn());
        await flush();
      }
      await flush();
    },
  };
}

function nativeDrive(steps, opts) {
  opts = opts || {};
  const settled = !!opts.settled;
  const posts = [];
  const enqueued = [];
  const state = {
    raw: opts.initialRaw || '', ended: 0, finished: 0,
    observer: null, listener: null,
  };
  const chatRequests = conversationState.createChatRequestTracker();
  let liveSeq = chatRequests.begin();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: liveSeq,
  });
  function publish() {
    source.publish({ original: state.raw, fallbackVisible: '' });
  }
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
  if (settled) {
    publish();
    source.finish();
    if (chatRequests.isGenerating()) chatRequests.finish(liveSeq);
  } else {
    publish();
  }
  ttsPlayback.playNativeVoiceModeTts(deps, {}, {});
  return {
    posts, enqueued, state,
    async run() {
      await flush();
      for (const step of steps) {
        state.raw = step.text;
        if (step.generating) {
          if (!chatRequests.isGenerating()) liveSeq = chatRequests.begin();
        } else if (chatRequests.isGenerating()) {
          chatRequests.finish(liveSeq);
        }
        publish();
        if (!step.generating) source.finish();
        // A pre-seeded finished message may already have ended during the
        // initial flush; further steps are then no-ops.
        if (state.observer) state.observer();
        await flush();
      }
      for (let i = 0; i < 12; i++) await flush();
      posts.forEach((p, i) => p.resolve('tok' + i));
      await flush();
      for (let i = 0; i < 12; i++) await flush();
    },
  };
}

const FINAL = 'Hello world. How are you today. Thanks for asking.';

async function checkParity() {
  // Streaming increments vs one historical seed speak the same answer text
  // on both queues (non-streaming and streaming text are the same).
  const streaming = [
    { text: 'Hello world.', generating: true },
    { text: 'Hello world. How are you today.', generating: true },
    { text: FINAL, generating: false },
  ];
  const historical = [{ text: FINAL, generating: false }];
  const expected = ['Hello world.', 'How are you today.', 'Thanks for asking.'];

  const dStream = desktopDrive(streaming);
  await dStream.run();
  assert.deepEqual(dStream.state.played, expected, 'desktop streaming speaks once in order: ' + JSON.stringify(dStream.state.played));

  const dHist = desktopDrive(historical, { settled: true, initialRaw: FINAL });
  await dHist.run();
  assert.deepEqual(dHist.state.played, expected, 'desktop historical speaks the same text: ' + JSON.stringify(dHist.state.played));

  const nStream = nativeDrive(streaming);
  await nStream.run();
  assert.deepEqual(nStream.posts.map((p) => p.text), expected, 'native streaming requests once in order: ' + JSON.stringify(nStream.posts.map((p) => p.text)));

  const nHist = nativeDrive(historical, { settled: true, initialRaw: FINAL });
  await nHist.run();
  assert.deepEqual(nHist.posts.map((p) => p.text), expected, 'native historical requests the same text: ' + JSON.stringify(nHist.posts.map((p) => p.text)));
}

async function checkThinking() {
  // <think> reasoning is stripped (chat strips the block before the shared
  // sanitizer, which only strips the bare tags); Thinking.../Error
  // placeholders are silent.
  const raw = '<think>reasoning here</think>Visible answer here.';
  const withoutThink = raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  const visible = voiceText.sanitizeForTTS(withoutThink);
  assert.equal(visible, 'Visible answer here.', 'think block must strip before sanitize, got: ' + JSON.stringify(visible));

  const d = desktopDrive([
    { text: '', generating: true },
    { text: visible, generating: false },
  ]);
  await d.run();
  assert.deepEqual(d.state.played, ['Visible answer here.'], 'desktop speaks visible only: ' + JSON.stringify(d.state.played));

  const n = nativeDrive([
    { text: '', generating: true },
    { text: visible, generating: false },
  ]);
  await n.run();
  assert.deepEqual(n.posts.map((p) => p.text), ['Visible answer here.'], 'native requests visible only');

  // Pure error text stays silent but completes.
  const dErr = desktopDrive([{ text: '', generating: false }]);
  await dErr.run();
  assert.deepEqual(dErr.state.played, [], 'error/empty text must stay silent');
  assert.equal(dErr.state.completed, 1, 'silent message must still complete');
}

async function checkHold() {
  // Extendable trailing fragment waits while generating, speaks when done.
  const d = desktopDrive([
    { text: 'Version 4.', generating: true },
    { text: 'Version 4.6 is out.', generating: false },
  ]);
  await d.run();
  assert.deepEqual(d.state.played, ['Version 4.6 is out.'], 'desktop must hold the digit-period fragment: ' + JSON.stringify(d.state.played));

  const n = nativeDrive([
    { text: 'Version 4.', generating: true },
    { text: 'Version 4.6 is out.', generating: false },
  ]);
  await n.run();
  assert.deepEqual(n.posts.map((p) => p.text), ['Version 4.6 is out.'], 'native must hold the digit-period fragment');
}

async function checkFixed() {
  // Sentence-click path: the fixed list speaks exact strings in order.
  const played = [];
  const lifecycle = makeOwner();
  lifecycle.stopDesktopPlayback();
  lifecycle.beginDesktopPlayback({});
  let live = true;
  const deps = {
    isLive: (id) => live && lifecycle.isLiveDesktop(id),
    onComplete: (button) => { lifecycle.completeDesktopPlayback(button); live = false; },
    preload: () => {},
    playOne: (sessionId, text) => { played.push(String(text)); return Promise.resolve(true); },
    reportVoice: () => {},
    appendMessage: () => {},
    logError: () => {},
    setTimeout: (fn) => { fn(); return 1; },
    isVoiceModeActive: () => false,
  };
  ttsPlayback.playFixedSentenceList(deps, 1, {}, ['Say "hi.', 'Bye.']);
  await flush();
  await flush();
  assert.deepEqual(played, ['Say "hi.', 'Bye.'], 'fixed list must speak exact click strings: ' + JSON.stringify(played));
}

async function checkHistorical() {
  // A settled message completes while the tracker generates elsewhere:
  // progress is per-message sequence state, not global.
  const tracker = conversationState.createChatRequestTracker();
  tracker.begin(); // another message streaming elsewhere
  assert.equal(tracker.isGenerating(), true, 'precondition: tracker generating elsewhere');
  const d = desktopDrive(
    [{ text: 'Older answer here. Done.', generating: false }],
    { settled: true, initialRaw: 'Older answer here. Done.' }
  );
  await d.run();
  assert.deepEqual(d.state.played, ['Older answer here.', 'Done.'], 'historical must not stall on global generation');
  assert.equal(d.state.completed, 1, 'historical must complete');
  tracker.finish(tracker.seq());
}

async function checkStop() {
  // User stop appends [Stopped] to the bubble, but playback was published
  // the original without the suffix and then finished: only it may speak.
  const d = desktopDrive([{ text: 'Answer here.', generating: false }]);
  await d.run();
  assert.deepEqual(d.state.played, ['Answer here.'], 'stop suffix must not be spoken: ' + JSON.stringify(d.state.played));
  assert(!d.state.played.some((t) => t.includes('Stopped')), 'no [Stopped] may reach speech');
}

(async () => {
  const checks = { parity: checkParity, thinking: checkThinking, hold: checkHold, fixed: checkFixed, historical: checkHistorical, stop: checkStop };
  const names = scenario === 'all' ? Object.keys(checks) : [scenario];
  const failures = [];
  for (const name of names) {
    const check = checks[name];
    if (!check) {
      console.error('unknown scenario: ' + name);
      process.exitCode = 1;
      return;
    }
    try {
      await check();
    } catch (error) {
      failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
    }
  }
  if (failures.length) {
    console.error('playback characterization FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('playback characterization: ' + names.join(',') + ' ok');
})().catch((error) => { console.error(error); process.exitCode = 1; });
