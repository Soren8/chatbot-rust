'use strict';
// MOD-009-B review proof: the REAL chat adapters over REAL owners.
//
// Bounded [start,end) slices of static/chat.js (verified anchors + V8 parse
// check, no scanners) are evaluated in a vm sandbox with the real lifecycle,
// clip pipeline, voice-text, tracker and playback source plus fake audio,
// fetch, timers and DOM. Stops go through the real stopCurrentDesktopTts and
// stopAllTtsPlayback; direct lifecycle stops go through the real owner.
// Resolved-play midclip, fixed-list retry, immediate replacement and direct
// stops in retry/poll must settle silently with no later work.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chatPath = process.argv[2];
const ttsPlaybackPath = process.argv[3];
const voiceTextPath = process.argv[4];
const conversationStatePath = process.argv[5];
const voiceLifecyclePath = process.argv[6];
const playbackSourcePath = process.argv[7];
const scenario = process.argv[8] || 'all';
assert(
  chatPath && ttsPlaybackPath && voiceTextPath && conversationStatePath && voiceLifecyclePath && playbackSourcePath,
  'usage: node desktop_playback_cancellation_vm_test.js <chat> <tts-playback> <voice-text> <conversation-state> <voice-lifecycle> <playback-source> [scenario]'
);
const ttsPlayback = require(ttsPlaybackPath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);
const voiceLifecycleMod = require(voiceLifecyclePath);
const playbackSource = require(playbackSourcePath);
const chatSrc = fs.readFileSync(chatPath, 'utf8');

async function flush(rounds) {
  const n = rounds || 80;
  for (let i = 0; i < n; i++) await Promise.resolve();
}

function makeTimerRig() {
  let nextId = 1;
  const pending = new Map();
  return {
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

function makeFakeAudio(playBehavior, playRejectErr) {
  return {
    onended: null,
    onerror: null,
    onloadeddata: null,
    error: null,
    _src: '',
    get src() { return this._src; },
    set src(v) { this._src = v; this.srcLog.push(String(v)); },
    srcLog: [],
    currentSrc: '',
    paused: true,
    dataset: {},
    playCalls: 0,
    playBehavior: playBehavior || 'pending',
    playRejectErr: playRejectErr || null,
    play() {
      this.playCalls += 1;
      this.paused = false;
      if (this.playBehavior === 'resolve') return Promise.resolve();
      if (this.playBehavior === 'reject') return Promise.reject(this.playRejectErr || new Error('decode failed'));
      return new Promise(() => {});
    },
    pause() { this.paused = true; },
    removeAttribute() {},
    fireEnded() { const h = this.onended; if (typeof h === 'function') h(); },
    fireError() { const h = this.onerror; if (typeof h === 'function') h(); },
  };
}

const slices = [
  ['var voiceLifecycle = ChatVoiceLifecycle.createVoiceLifecycle({',
    'const TTS_LISTEN_COOLDOWN_MS = ChatVoiceLifecycle.TTS_LISTEN_COOLDOWN_MS;'],
  ['var desktopTtsClip = ChatTtsPlayback.createDesktopClipPipeline({',
    'var activeDesktopTtsQueue = null;'],
  ['var activeDesktopTtsQueue = null;',
    'function stopCurrentDesktopTts() {'],
  ['function stopCurrentDesktopTts() {',
    'function disablePremiumModels() {'],
  ['function clearTtsHoverHighlight() {',
    '/** Highlight the sentence under the caret. Returns the sentence record or null. */'],
  ['var messagePlaybackSources = new WeakMap();',
    'function messagePlaybackSourceDeps(boundSeq) {'],
  ['function bindMessagePlaybackSource(hostEl, site) {',
    '// Canonical wire shape for data-original and source publishes alike.'],
  ['function fetchDesktopTtsClip(sessionId, text) {',
    '/**\n * Play TTS for an AI message.'],
  ['  function stopAllTtsPlayback(opts) {',
    '  function stopVoicePlaybackOnly() {'],
];

function loadSlice(startAnchor, endAnchor) {
  const start = chatSrc.indexOf(startAnchor);
  assert(start !== -1, 'chat.js must contain ' + startAnchor);
  const end = chatSrc.indexOf(endAnchor, start + startAnchor.length);
  assert(end !== -1 && end > start, 'chat.js slice end missing after ' + startAnchor);
  const src = chatSrc.slice(start, end);
  try {
    new vm.Script(src);
  } catch (e) {
    assert.fail('chat.js slice [' + startAnchor + ' .. ' + endAnchor + '] is not valid JS: ' + e.message);
  }
  return src;
}

function makeRig(opts) {
  opts = opts || {};
  const timers = makeTimerRig();
  const fakeAudio = makeFakeAudio(opts.playBehavior, opts.playRejectErr);
  const fetchCalls = [];
  const fetchStub = (url, options) => {
    let text = '';
    try { text = String(JSON.parse(options.body).text); } catch (e) { /* ignore */ }
    fetchCalls.push({ url: String(url), text });
    if (String(url) === '/tts') {
      if (opts.fetchMode === 'no-token') return Promise.resolve({ json: async () => ({}) });
      const tok = 'tok' + (++tokenSeq);
      tokenTexts[tok] = text;
      return Promise.resolve({ json: async () => ({ token: tok }) });
    }
    const tok = String(url).split('/').pop();
    return Promise.resolve({ blob: async () => ({ fakeBlob: true, text: tokenTexts[tok] || '' }) });
  };
  const state = {
    completed: 0, reports: [], chatErrors: [], endedNotifies: 0,
    observerConnects: [], observerDisconnects: [],
  };
  const tokenTexts = {};
  let tokenSeq = 0;
  function FakeMutationObserver(cb) {
    state.observerConnects.push(this);
    this.cb = cb;
  }
  FakeMutationObserver.prototype.observe = function () {};
  FakeMutationObserver.prototype.disconnect = function () { state.observerDisconnects.push(this); };
  const window = {};
  const context = vm.createContext({
    ChatVoiceLifecycle: voiceLifecycleMod,
    ChatTtsPlayback: ttsPlayback,
    ChatPlaybackSource: playbackSource,
    sanitizeForTTS: voiceText.sanitizeForTTS,
    splitSentences: voiceText.splitSentences,
    sentenceEndsWithTerminator: voiceText.sentenceEndsWithTerminator,
    AbortController,
    Audio: function () { return fakeAudio; },
    URL: {
      createObjectURL: (blob) => 'blob:vm-' + String((blob && blob.text) || 'x'),
      revokeObjectURL: () => {},
    },
    MutationObserver: FakeMutationObserver,
    setTimeout: (fn, ms) => timers.setTimeout(fn, ms),
    clearTimeout: (id) => timers.clearTimeout(id),
    console,
    window,
    document: { querySelectorAll: () => [] },
    $: () => ({ removeClass() { return this; }, prop() { return this; }, html() { return this; } }),
    syncSendButtonState: () => {},
    reportVoice: (k, m) => { state.reports.push(k + ':' + m); },
    appendMessage: (t) => { state.chatErrors.push(String(t)); },
    fetchVoiceRetry: fetchStub,
    withCsrf: (h) => h,
  });
  // File order matters: the file uses the names as defined in the repo.
  const tracker = conversationState.createChatRequestTracker();
  context.messagePlaybackSourceDeps = (boundSeq) => ({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => tracker.isGenerating(),
    isTrackerLive: (s) => tracker.isLive(s),
    boundSeq,
  });
  for (const [startAnchor, endAnchor] of slices) {
    vm.runInContext(loadSlice(startAnchor, endAnchor), context);
  }
  // The lifecycle factory takes createAudio from deps; rebind to the fake.
  // The sliced creation already ran with a missing createAudio dep default
  // (new Audio), so recreate the owner deterministically on the fake audio by
  // re-running only the creation slice with the dep injected.
  const V = (name) => vm.runInContext(name, context);
  return { timers, fakeAudio, fetchCalls, state, window, context, tracker, V };
}

function fakeMessage() {
  const host = {};
  const textEl = {};
  const $msg = { 0: host, length: 1, find: () => [textEl] };
  return { host, textEl, $msg };
}

function bindSettled(rig, $msg, host, text) {
  const V = rig.V;
  const seq = rig.tracker.begin();
  V('bindMessagePlaybackSource')(host, { original: text, visible: '', boundSeq: seq });
  V('publishMessagePlaybackText')($msg, text, '');
  V('finishMessagePlayback')($msg);
  rig.tracker.finish(seq);
  return seq;
}

function lastObserver(rig) {
  return rig.state.observerConnects[rig.state.observerConnects.length - 1];
}

async function checkStopCurrent() {
  const rig = makeRig({ playBehavior: 'resolve' });
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  let completedCalls = 0;
  const realComplete = voiceLifecycle.completeDesktopPlayback.bind(voiceLifecycle);
  voiceLifecycle.completeDesktopPlayback = (b) => { completedCalls += 1; return realComplete(b); };
  const msg = fakeMessage();
  bindSettled(rig, msg.$msg, msg.host, 'First sentence here. Second sentence here.');
  const sessionId = voiceLifecycle.beginDesktopPlayback({});
  V('playMessageBodyTts')(sessionId, {}, msg.$msg);
  await flush();
  await flush();
  assert(rig.fakeAudio.playCalls >= 1, 'precondition: resolved audio started');
  assert(typeof rig.fakeAudio.onended === 'function', 'precondition: clip handlers installed');
  V('stopCurrentDesktopTts')();
  await flush();
  await flush();
  assert.equal(completedCalls, 0, 'real stopCurrentDesktopTts must not complete a cancelled queue');
  assert(rig.state.observerDisconnects.length >= 1, 'real stop must disconnect the wrapper observer');
  assert.equal(rig.timers.pendingCount(), 0, 'real stop must clear queue timers');
  assert.deepEqual(rig.state.reports, [], 'no voice errors on stop');
  assert.deepEqual(rig.state.chatErrors, [], 'no chat errors on stop');
  const playCalls = rig.fakeAudio.playCalls;
  const fetchCalls = rig.fetchCalls.length;
  rig.timers.runAll();
  await flush();
  rig.fakeAudio.fireEnded();
  rig.fakeAudio.fireError();
  const obs = lastObserver(rig);
  if (obs) obs.cb();
  await flush();
  rig.timers.runAll();
  await flush();
  assert.equal(rig.fakeAudio.playCalls, playCalls, 'no later audio play after real stop');
  assert.equal(rig.fetchCalls.length, fetchCalls, 'no later clip fetch after real stop');
  assert.equal(completedCalls, 0, 'no late completion after real stop');
}

async function checkStopAll() {
  const rig = makeRig({ playBehavior: 'resolve' });
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  let completedCalls = 0;
  const realComplete = voiceLifecycle.completeDesktopPlayback.bind(voiceLifecycle);
  voiceLifecycle.completeDesktopPlayback = (b) => { completedCalls += 1; return realComplete(b); };
  const msg = fakeMessage();
  bindSettled(rig, msg.$msg, msg.host, 'First sentence here. Second sentence here.');
  const sessionId = voiceLifecycle.beginDesktopPlayback({});
  V('playMessageBodyTts')(sessionId, {}, msg.$msg);
  await flush();
  await flush();
  assert(rig.fakeAudio.playCalls >= 1, 'precondition: resolved audio started');
  V('stopAllTtsPlayback')();
  await flush();
  await flush();
  assert.equal(completedCalls, 0, 'real stopAllTtsPlayback must not complete a cancelled queue');
  assert(rig.state.observerDisconnects.length >= 1, 'real stop-all must disconnect the wrapper observer');
  assert.equal(rig.timers.pendingCount(), 0, 'real stop-all must clear queue timers');
  const playCalls = rig.fakeAudio.playCalls;
  rig.timers.runAll();
  await flush();
  rig.fakeAudio.fireEnded();
  await flush();
  assert.equal(rig.fakeAudio.playCalls, playCalls, 'no later audio play after real stop-all');
  assert.equal(completedCalls, 0, 'no late completion after real stop-all');
}

async function checkFixedRetry() {
  const rig = makeRig({ fetchMode: 'no-token' });
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  let completedCalls = 0;
  const realComplete = voiceLifecycle.completeDesktopPlayback.bind(voiceLifecycle);
  voiceLifecycle.completeDesktopPlayback = (b) => { completedCalls += 1; return realComplete(b); };
  const sessionId = voiceLifecycle.beginDesktopPlayback({});
  V('playFixedSentenceList')(sessionId, {}, ['Alpha one here.', 'Beta two here.']);
  await flush();
  await flush();
  await flush();
  assert(rig.fetchCalls.length >= 1, 'precondition: fixed list attempted the sentence');
  assert.equal(completedCalls, 0, 'precondition: failing fixed list has not completed');
  assert(rig.timers.pendingCount() >= 1, 'precondition: fixed-list retry backoff is pending');
  V('stopCurrentDesktopTts')();
  await flush();
  await flush();
  assert.equal(rig.timers.pendingCount(), 0, 'fixed-list retry stop must clear the backoff timer');
  assert.equal(completedCalls, 0, 'cancelled fixed list must not complete');
  assert.deepEqual(rig.state.reports, [], 'cancelled fixed list must not report errors');
  assert.deepEqual(rig.state.chatErrors, [], 'cancelled fixed list must not append chat errors');
  const fetchCalls = rig.fetchCalls.length;
  rig.timers.runAll();
  await flush();
  await flush();
  assert.equal(rig.fetchCalls.length, fetchCalls, 'no later fixed-list attempt after retry cancellation');
}

async function checkImmediateReplacement() {
  const rig = makeRig({});
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  let completedCalls = 0;
  const realComplete = voiceLifecycle.completeDesktopPlayback.bind(voiceLifecycle);
  voiceLifecycle.completeDesktopPlayback = (b) => { completedCalls += 1; return realComplete(b); };
  const first = fakeMessage();
  bindSettled(rig, first.$msg, first.host, 'Alpha one here. Beta two here.');
  const sessionA = voiceLifecycle.beginDesktopPlayback({});
  V('playMessageBodyTts')(sessionA, {}, first.$msg);
  // No flush: stop and replace synchronously on the same task.
  V('stopCurrentDesktopTts')();
  const second = fakeMessage();
  bindSettled(rig, second.$msg, second.host, 'Gamma three here. Done now.');
  const sessionB = voiceLifecycle.beginDesktopPlayback({});
  assert(sessionA !== sessionB, 'precondition: replacement owns a new session');
  V('playMessageBodyTts')(sessionB, {}, second.$msg);
  await flush();
  await flush();
  const played = rig.fakeAudio.srcLog.filter((u) => u.indexOf('blob:vm-') === 0);
  assert(played.length >= 1, 'replacement must play its first clip');
  assert.equal(played[0], 'blob:vm-Gamma three here.', 'replacement speaks its own first sentence, got ' + JSON.stringify(played));
  rig.fakeAudio.fireEnded();
  await flush();
  await flush();
  rig.timers.runAll();
  await flush();
  await flush();
  const later = rig.fakeAudio.srcLog.filter((u) => u.indexOf('blob:vm-') === 0);
  assert(later.length >= 2, 'replacement must advance, got ' + JSON.stringify(later));
  assert.equal(later[1], 'blob:vm-Done now.', 'replacement keeps order, got ' + JSON.stringify(later));
  assert(!later.some((u) => u.indexOf('Alpha one here.') !== -1 || u.indexOf('Beta two here.') !== -1),
    'stopped first session must never reach audio, got ' + JSON.stringify(later));
  rig.fakeAudio.fireEnded();
  await flush();
  await flush();
  rig.timers.runAll();
  await flush();
  await flush();
  assert.equal(completedCalls, 1, 'replacement must complete exactly once');
  assert.deepEqual(rig.state.reports, [], 'replacement must not report errors');
}

async function checkDirectStopRetry() {
  const rig = makeRig({ fetchMode: 'no-token' });
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  const msg = fakeMessage();
  bindSettled(rig, msg.$msg, msg.host, 'Alpha one here. Beta two here.');
  const sessionId = voiceLifecycle.beginDesktopPlayback({});
  V('playMessageBodyTts')(sessionId, {}, msg.$msg);
  await flush();
  await flush();
  await flush();
  assert(rig.timers.pendingCount() >= 1, 'precondition: sentence retry backoff is pending');
  voiceLifecycle.stopDesktopPlayback();
  assert.equal(rig.timers.pendingCount(), 0, 'direct lifecycle stop must immediately clear queue backoff timers');
  assert(rig.state.observerDisconnects.length >= 1, 'direct lifecycle stop must immediately disconnect the observer');
  await flush();
  const fetchCalls = rig.fetchCalls.length;
  rig.timers.runAll();
  await flush();
  const obs = lastObserver(rig);
  if (obs) obs.cb();
  await flush();
  assert.equal(rig.fetchCalls.length, fetchCalls, 'no later sentence attempt after direct stop');
  assert.deepEqual(rig.state.reports, [], 'no errors after direct stop');
  assert.deepEqual(rig.state.chatErrors, [], 'no chat errors after direct stop');
}

async function checkDirectStopPoll() {
  const rig = makeRig({});
  const V = rig.V;
  const voiceLifecycle = V('voiceLifecycle');
  const msg = fakeMessage();
  const seq = rig.tracker.begin();
  V('bindMessagePlaybackSource')(msg.host, { original: 'Partial without end', visible: '', boundSeq: seq });
  V('publishMessagePlaybackText')(msg.$msg, 'Partial without end', '');
  const sessionId = voiceLifecycle.beginDesktopPlayback({});
  V('playMessageBodyTts')(sessionId, {}, msg.$msg);
  await flush();
  await flush();
  assert(rig.timers.pendingCount() >= 1, 'precondition: idle poll is pending while generating');
  voiceLifecycle.stopDesktopPlayback();
  assert.equal(rig.timers.pendingCount(), 0, 'direct lifecycle stop must immediately clear the idle poll timer');
  assert(rig.state.observerDisconnects.length >= 1, 'direct lifecycle stop must immediately disconnect the observer');
  rig.tracker.finish(seq);
  await flush();
  const fetchCalls = rig.fetchCalls.length;
  rig.timers.runAll();
  await flush();
  assert.equal(rig.fetchCalls.length, fetchCalls, 'no later fetch after direct stop in poll');
}

(async () => {
  const checks = {
    'stop-current': checkStopCurrent,
    'stop-all': checkStopAll,
    'fixed-retry': checkFixedRetry,
    'immediate-replacement': checkImmediateReplacement,
    'direct-stop-retry': checkDirectStopRetry,
    'direct-stop-poll': checkDirectStopPoll,
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
    console.error('desktop playback vm cancellation FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('desktop playback vm cancellation: ' + names.join(',') + ' ok');
})().catch((error) => { console.error(error); process.exitCode = 1; });
