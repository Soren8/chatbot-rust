'use strict';
// MOD-009-B regression: desktop playback cancellation owns settlement/disposal.
//
// Drives the REAL owned desktop clip pipeline (static/tts-playback.js) with the
// REAL voice lifecycle (static/voice-lifecycle.js), REAL voice-text splitter,
// REAL conversation tracker and REAL per-message source over FAKE audio/fetch/
// timers. No queue/clip/lifecycle code is copied; leaf I/O is stubbed.
//
// Given a successfully started clip (audio playing, handlers installed):
// when the session is stopped with no later text/media events,
// then the active clip promise settles (false) and queue-owned source
// subscriptions, observers and timers are disposed with no onComplete,
// error bubble, telemetry or notifyEnded, and no later play.
//
// Also covers replacement playback (stale completion cannot disturb the
// replacement) and cancellation during clip/sentence retry backoff.
//
// Before the fix, the legacy stop clears audio handlers without settling the
// clip promise; the queue stays waiting with its subscription/observer/timers
// retained. The composed stop below uses the explicit cancellation path when
// present (queue handle + pipeline cancelSession) and falls back to the legacy
// lifecycle stop otherwise, so this file is unchanged across the fix: it fails
// on the legacy path and passes on the explicit path.
const assert = require('node:assert/strict');

const ttsPlaybackPath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
const voiceLifecyclePath = process.argv[5];
const playbackSourcePath = process.argv[6];
const scenario = process.argv[7] || 'all';
assert(
  ttsPlaybackPath && voiceTextPath && conversationStatePath && voiceLifecyclePath && playbackSourcePath,
  'usage: node desktop_playback_cancellation_test.js <tts-playback> <voice-text> <conversation-state> <voice-lifecycle> <playback-source> [scenario]'
);
const ttsPlayback = require(ttsPlaybackPath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);
const playbackSource = require(playbackSourcePath);

async function flush(rounds) {
  const n = rounds || 80;
  for (let i = 0; i < n; i++) await Promise.resolve();
}

function makeTimerRig() {
  let nextId = 1;
  const pending = new Map();
  return {
    pending,
    pendingCount() { return pending.size; },
    setTimeout(fn, ms) { const id = nextId++; pending.set(id, { fn, ms }); return id; },
    clearTimeout(id) { pending.delete(id); },
    runAll() {
      const due = Array.from(pending.values());
      pending.clear();
      for (const entry of due) {
        try { entry.fn(); } catch (e) { /* ignore */ }
      }
    },
  };
}

function makeFakeAudio() {
  return {
    onended: null,
    onerror: null,
    onloadeddata: null,
    error: null,
    src: '',
    currentSrc: '',
    paused: true,
    playCalls: 0,
    pauseCalls: 0,
    playBehavior: 'pending',
    playRejectErr: null,
    play() {
      this.playCalls += 1;
      this.paused = false;
      if (this.playBehavior === 'resolve') return Promise.resolve();
      if (this.playBehavior === 'reject') {
        const err = this.playRejectErr || new Error('decode failed');
        return Promise.reject(err);
      }
      return new Promise(() => {});
    },
    pause() { this.paused = true; this.pauseCalls += 1; },
    removeAttribute() {},
    fireEnded() { const h = this.onended; if (typeof h === 'function') h(); },
    fireError() { const h = this.onerror; if (typeof h === 'function') h(); },
  };
}

function makeOwner(fakeAudio, voiceMode) {
  return voiceLifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => fakeAudio,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => !!voiceMode,
    stopNativePlayback: () => {},
  });
}

// Desktop rig wired the way chat wires it: lifecycle owns liveness/session,
// the pipeline owns clip fetch/play over the shared audio element, the queue
// owns sentence discovery over the explicit per-message source.
function setupDesktop(opts) {
  opts = opts || {};
  const fakeAudio = makeFakeAudio();
  if (opts.playBehavior) fakeAudio.playBehavior = opts.playBehavior;
  if (opts.playRejectErr) fakeAudio.playRejectErr = opts.playRejectErr;
  const timers = makeTimerRig();
  const lifecycle = makeOwner(fakeAudio, !!opts.voiceMode);
  const notifications = { started: 0, ended: 0 };
  const errors = [];
  const fetchCalls = [];
  const urlCalls = { created: [], revoked: [] };
  let urlSeq = 0;
  const token = opts.token || 'tok1';
  const fetchStub = (url) => {
    fetchCalls.push(String(url));
    if (String(url) === '/tts') {
      if (opts.fetchMode === 'no-token') return Promise.resolve({ json: async () => ({}) });
      return Promise.resolve({ json: async () => ({ token }) });
    }
    return Promise.resolve({ blob: async () => ({ fakeBlob: true }) });
  };
  const pipelineDeps = {
    isLive: (id) => lifecycle.isLiveDesktop(id),
    sanitize: voiceText.sanitizeForTTS,
    hasPreload: (k) => lifecycle.hasPreload(k),
    getPreload: (k) => lifecycle.getPreload(k),
    setPreload: (k, p) => lifecycle.setPreload(k, p),
    deletePreload: (k) => lifecycle.deletePreload(k),
    getAbortSignal: () => lifecycle.getDesktopAbortSignal(),
    fetchVoiceRetry: fetchStub,
    withCsrf: (h) => h,
    getAudio: () => lifecycle.getDesktopAudio(),
    createObjectUrl: () => { const u = 'blob:fake-' + (++urlSeq); urlCalls.created.push(u); return u; },
    revokeObjectUrl: (u) => { urlCalls.revoked.push(u); },
    adoptBlobUrl: (u) => lifecycle.adoptBlobUrl(u),
    releaseBlobUrl: (u) => lifecycle.releaseBlobUrlIfCurrent(u),
    isVoiceModeActive: () => !!opts.voiceMode,
    noteClipStarted: () => lifecycle.noteDesktopClipStarted(),
    noteClipFinished: () => lifecycle.noteDesktopClipFinished(),
    notifyStarted: () => { notifications.started += 1; },
    notifyEnded: () => { notifications.ended += 1; },
    logError: (...a) => { errors.push(a.join(' ')); },
    setTimeout: (fn, ms) => timers.setTimeout(fn, ms),
    clearTimeout: (id) => timers.clearTimeout(id),
  };
  if (typeof lifecycle.registerDesktopClipCanceller === 'function') {
    pipelineDeps.registerClipCanceller = (entry) => lifecycle.registerDesktopClipCanceller(entry);
  }
  if (typeof lifecycle.unregisterDesktopClipCanceller === 'function') {
    pipelineDeps.unregisterClipCanceller = (entry) => lifecycle.unregisterDesktopClipCanceller(entry);
  }
  const pipeline = ttsPlayback.createDesktopClipPipeline(pipelineDeps);
  return { fakeAudio, timers, lifecycle, pipeline, notifications, errors, fetchCalls, urlCalls };
}

function makeSettledSource(text) {
  const chatRequests = conversationState.createChatRequestTracker();
  const seq = chatRequests.begin();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: seq,
  });
  source.publish({ original: text, fallbackVisible: '' });
  source.finish();
  chatRequests.finish(seq);
  return { chatRequests, seq, source };
}

// Queue wired the way chat wires playMessageBodyTts: lifecycle liveness,
// explicit source, pipeline preload/playOne, observer backstop.
function startDesktopQueue(rig, text) {
  const settled = makeSettledSource(text);
  const state = {
    observer: null,
    observerDisconnects: 0,
    sourceDisconnects: 0,
    completed: 0,
    reports: [],
    chatErrors: [],
    consoleErrors: [],
    clipCalls: [],
    clipSettled: [],
  };
  const origSubscribe = settled.source.subscribe.bind(settled.source);
  settled.source.subscribe = (cb) => {
    const disc = origSubscribe(cb);
    return () => { state.sourceDisconnects += 1; if (disc) disc(); };
  };
  const deps = {
    isLive: (id) => rig.lifecycle.isLiveDesktop(id),
    onComplete: (button) => { rig.lifecycle.completeDesktopPlayback(button); state.completed += 1; },
    source: settled.source,
    split: voiceText.splitSentences,
    terminator: voiceText.sentenceEndsWithTerminator,
    preload: (sid, t) => rig.pipeline.preloadSentence(sid, t),
    playOne: (sid, t) => {
      state.clipCalls.push(String(t));
      const p = rig.pipeline.playOne(sid, t);
      p.then(
        (r) => { state.clipSettled.push({ text: String(t), result: r }); },
        (e) => { state.clipSettled.push({ text: String(t), error: String((e && e.message) || e) }); }
      );
      return p;
    },
    reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
    appendMessage: (t) => { state.chatErrors.push(String(t)); },
    logError: (...a) => { state.consoleErrors.push(a.join(' ')); },
    setTimeout: (fn, ms) => rig.timers.setTimeout(fn, ms),
    clearTimeout: (id) => rig.timers.clearTimeout(id),
    isVoiceModeActive: () => false,
    observeChanges: (cb) => {
      state.observer = cb;
      return () => { state.observer = null; state.observerDisconnects += 1; };
    },
  };
  rig.lifecycle.stopDesktopPlayback();
  const sessionId = rig.lifecycle.beginDesktopPlayback({});
  const handle = ttsPlayback.playMessageBodyTts(deps, sessionId, {});
  return { sessionId, handle, state, source: settled.source };
}

// Composed stop mirrors chat's stop adapters after the fix: dispose the queue
// handle, cancel the pipeline session, then stop the lifecycle. Before the fix
// the handle/pipeline cancel are absent and only the legacy lifecycle stop runs.
function composedStop(rig, started) {
  const handle = started.handle;
  if (handle && typeof handle.cancel === 'function') {
    try { handle.cancel(); } catch (e) { /* ignore */ }
  } else if (handle && typeof handle.dispose === 'function') {
    try { handle.dispose(); } catch (e) { /* ignore */ }
  }
  if (rig.pipeline && typeof rig.pipeline.cancelSession === 'function') {
    try { rig.pipeline.cancelSession(started.sessionId); } catch (e) { /* ignore */ }
  } else if (rig.pipeline && typeof rig.pipeline.cancelAllClips === 'function') {
    try { rig.pipeline.cancelAllClips(); } catch (e) { /* ignore */ }
  } else if (rig.pipeline && typeof rig.pipeline.cancelAll === 'function') {
    try { rig.pipeline.cancelAll(); } catch (e) { /* ignore */ }
  }
  if (typeof rig.lifecycle.cancelDesktopClips === 'function') {
    try { rig.lifecycle.cancelDesktopClips(started.sessionId); } catch (e) { /* ignore */ }
  }
  rig.lifecycle.stopDesktopPlayback();
}

async function checkMidclip() {
  const rig = setupDesktop({});
  const started = startDesktopQueue(rig, 'First sentence here. Second sentence here.');
  await flush();
  await flush();
  assert(rig.fakeAudio.playCalls >= 1, 'precondition: fake audio play started, got ' + rig.fakeAudio.playCalls);
  assert(typeof rig.fakeAudio.onended === 'function', 'precondition: clip installed onended while playing');
  assert.equal(started.state.clipSettled.length, 0, 'precondition: active clip promise is pending while audio plays');

  composedStop(rig, started);
  await flush();
  await flush();

  assert(started.state.clipSettled.length >= 1, 'midclip stop must settle the active clip promise, still pending');
  assert.equal(started.state.clipSettled[0].result, false, 'cancelled clip settles false, got ' + JSON.stringify(started.state.clipSettled));
  assert.equal(started.state.completed, 0, 'cancelled queue must not complete via onComplete');
  assert.equal(started.state.observer, null, 'cancelled queue must disconnect its observer');
  assert(started.state.sourceDisconnects >= 1, 'cancelled queue must dispose its source subscription');
  assert.equal(rig.timers.pendingCount(), 0, 'cancelled queue must clear its timers, still pending: ' + rig.timers.pendingCount());
  assert.deepEqual(started.state.reports, [], 'cancelled queue must not report voice errors: ' + JSON.stringify(started.state.reports));
  assert.deepEqual(started.state.chatErrors, [], 'cancelled queue must not append chat errors: ' + JSON.stringify(started.state.chatErrors));
  assert.equal(rig.notifications.ended, 0, 'cancelled clip must not emit notifyEnded');

  const playCalls = rig.fakeAudio.playCalls;
  const clipCalls = started.state.clipCalls.length;
  rig.timers.runAll();
  await flush();
  rig.fakeAudio.fireEnded();
  rig.fakeAudio.fireError();
  started.source.publish({ original: 'First sentence here. Second sentence here. Third late sentence here.' });
  if (started.state.observer) started.state.observer();
  await flush();
  rig.timers.runAll();
  await flush();
  assert.equal(rig.fakeAudio.playCalls, playCalls, 'no later audio play after midclip stop');
  assert.equal(started.state.clipCalls.length, clipCalls, 'no later clip play after midclip stop');
  assert.equal(started.state.completed, 0, 'no late completion after midclip stop');
  assert.deepEqual(started.state.reports, [], 'no late voice errors after midclip stop');
  assert.equal(rig.notifications.ended, 0, 'no late notifyEnded after midclip stop');
}

async function checkReplacement() {
  const rig = setupDesktop({});
  const first = startDesktopQueue(rig, 'Alpha one here. Beta two here.');
  await flush();
  await flush();
  assert(rig.fakeAudio.playCalls >= 1, 'precondition: first playback started audio');
  assert(typeof rig.fakeAudio.onended === 'function', 'precondition: first clip installed handlers');

  composedStop(rig, first);
  await flush();
  await flush();
  assert(first.state.clipSettled.length >= 1, 'replacement precondition: first clip settled on stop, still pending');
  assert.equal(first.state.observer, null, 'replacement precondition: first queue observer disposed on stop');
  assert(first.state.sourceDisconnects >= 1, 'replacement precondition: first queue source disposed on stop');

  const second = startDesktopQueue(rig, 'Gamma three here. Done now.');
  await flush();
  await flush();
  assert(second.state.clipCalls.length >= 1, 'replacement must start its first clip, got ' + JSON.stringify(second.state.clipCalls));
  assert.equal(second.state.clipCalls[0], 'Gamma three here.', 'replacement speaks its own first sentence in order, got ' + JSON.stringify(second.state.clipCalls));

  // Late first-session events must not disturb the replacement.
  first.source.publish({ original: 'Alpha one here. Beta two here. Late stale text here.' });
  if (first.state.observer) first.state.observer();
  rig.timers.runAll();
  await flush();
  assert.deepEqual(second.state.clipCalls.slice(0, 1), ['Gamma three here.'], 'stale first-session text must not disturb replacement');

  // Advance the replacement through its real clip pipeline to completion.
  rig.fakeAudio.fireEnded();
  await flush();
  await flush();
  rig.timers.runAll();
  await flush();
  await flush();
  assert(second.state.clipCalls.length >= 2, 'replacement must advance to its second sentence, got ' + JSON.stringify(second.state.clipCalls));
  assert.equal(second.state.clipCalls[1], 'Done now.', 'replacement keeps sentence order, got ' + JSON.stringify(second.state.clipCalls));
  rig.fakeAudio.fireEnded();
  await flush();
  await flush();
  rig.timers.runAll();
  await flush();
  await flush();
  assert.equal(second.state.completed, 1, 'replacement must complete via onComplete');
  assert.deepEqual(second.state.reports, [], 'replacement must not report errors: ' + JSON.stringify(second.state.reports));
  assert.equal(first.state.completed, 0, 'stopped first session must never complete after replacement');
}

async function checkClipRetry() {
  const rig = setupDesktop({ playBehavior: 'reject', playRejectErr: new Error('decode failed') });
  const started = startDesktopQueue(rig, 'Retry sentence here. Second here.');
  await flush();
  await flush();
  assert(rig.fakeAudio.playCalls >= 1, 'precondition: first clip attempt played, got ' + rig.fakeAudio.playCalls);
  assert.equal(started.state.clipSettled.length, 0, 'precondition: clip retries before settling');
  assert(rig.timers.pendingCount() >= 1, 'precondition: clip retry backoff timer is pending');

  composedStop(rig, started);
  await flush();
  await flush();
  assert(started.state.clipSettled.length >= 1, 'retry stop must settle the active clip, still pending');
  assert.equal(started.state.clipSettled[0].result, false, 'cancelled retry settles false');
  assert.equal(rig.timers.pendingCount(), 0, 'retry stop must clear the clip backoff timer');
  assert.equal(started.state.completed, 0, 'cancelled retry must not complete');
  assert.deepEqual(started.state.reports, [], 'cancelled retry must not report errors');
  assert.deepEqual(started.state.chatErrors, [], 'cancelled retry must not append chat errors');

  const playCalls = rig.fakeAudio.playCalls;
  rig.timers.runAll();
  await flush();
  await flush();
  assert.equal(rig.fakeAudio.playCalls, playCalls, 'no later clip attempt after retry cancellation');
  assert.equal(started.state.completed, 0, 'no late completion after retry cancellation');
}

async function checkSentenceRetry() {
  const rig = setupDesktop({ fetchMode: 'no-token' });
  const started = startDesktopQueue(rig, 'Alpha one here. Beta two here.');
  await flush();
  await flush();
  await flush();
  assert(started.state.clipCalls.length >= 1, 'precondition: queue attempted the sentence, got ' + JSON.stringify(started.state.clipCalls));
  assert.equal(started.state.completed, 0, 'precondition: failing sentence has not completed');
  assert(rig.timers.pendingCount() >= 1, 'precondition: sentence retry backoff timer is pending');

  composedStop(rig, started);
  await flush();
  await flush();
  assert.equal(rig.timers.pendingCount(), 0, 'sentence-retry stop must clear the queue backoff timer');
  assert.equal(started.state.completed, 0, 'cancelled sentence retry must not complete');
  assert(started.state.observer === null, 'cancelled sentence retry must disconnect its observer');
  assert(started.state.sourceDisconnects >= 1, 'cancelled sentence retry must dispose its source subscription');
  assert.deepEqual(started.state.reports, [], 'cancelled sentence retry must not report errors after stop');
  assert.deepEqual(started.state.chatErrors, [], 'cancelled sentence retry must not append chat errors after stop');

  const clipCalls = started.state.clipCalls.length;
  rig.timers.runAll();
  await flush();
  await flush();
  assert.equal(started.state.clipCalls.length, clipCalls, 'no later sentence attempt after sentence-retry cancellation');
  assert.equal(started.state.completed, 0, 'no late completion after sentence-retry cancellation');
}

(async () => {
  const checks = {
    midclip: checkMidclip,
    replacement: checkReplacement,
    clipretry: checkClipRetry,
    sentenceretry: checkSentenceRetry,
  };
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
    console.error('desktop playback cancellation FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('desktop playback cancellation: ' + names.join(',') + ' ok');
})().catch((error) => { console.error(error); process.exitCode = 1; });
