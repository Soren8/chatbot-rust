'use strict';
// Composed request-application tests over the actual chat.js adapters.
//
// The real named functions are read out of static/chat.js and evaluated in a
// vm sandbox wired with the real owners (request tracker, history window,
// stream decoder, session client) and deferred fetch/readers. Only leaf
// DOM/render/playback sinks are stubbed. A set switch mid-flight must settle
// the old ownership without touching the new selection, and a replacement
// request must stay usable.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const chatPath = process.argv[2];
const convPath = process.argv[3];
const sessPath = process.argv[4];
const decPath = process.argv[5];
assert(
  chatPath && convPath && sessPath && decPath,
  'usage: node conversation_request_application_test.js <static/chat.js> <static/conversation-state.js> <static/session-client.js> <static/stream-decoder.js>'
);
const C = require(convPath);
const S = require(sessPath);
const D = require(decPath);
const chatSrc = fs.readFileSync(chatPath, 'utf8');

const unhandled = [];
process.on('unhandledRejection', (e) => { unhandled.push(String((e && e.message) || e)); });

async function flush(n) {
  for (let i = 0; i < (n || 60); i++) await Promise.resolve();
}

function abortError() {
  const e = new Error('Aborted');
  e.name = 'AbortError';
  return e;
}

// Bounded explicit slices: [startAnchor, endAnchor) spans evaluated as-is.
// Both anchors are verified present and ordered, and every slice must parse,
// so a shifted source fails loudly instead of testing the wrong code.
const slices = [
  ['function redirectHomeOnAuthFailure() {', 'try {\n  var appRoot = document.getElementById'],
  ['function refreshSession() {', 'function historyImageUrl(pairIndex, imageIndex) {'],
  ['function withCsrf(headers) {', 'var historyWindow = ChatConversationState.createHistoryWindow'],
  ['function liveUserPairIndex(userMessageElement) {', 'function isLocalOnlyTurn(el) {'],
  ['async function response401Message(response) {', 'function logoutThisComputer() {'],
  ['function fetchHistoryPair(pairIndex, extra) {', 'function sizeEditTextarea(textarea) {'],
  ['function beginChatRequest() {', '// Sanitize raw markdown text for TTS'],
  ['function combinedAiOriginal(fullVisibleText, fullThinkingText) {', 'function getDomPlainText(element) {'],
  ['window.regenerateMessage = function regenerateMessage(button) {', 'function handleDeleteMessage(buttonElement, isRetry) {'],
  ['function saveSystemPromptNow(sysPromptText, isRetry, capturedTarget, capturedGen) {', 'window.sendMessage = sendMessage;'],
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

function makeController() {
  const listeners = [];
  const signal = {
    aborted: false,
    addEventListener(t, f) { listeners.push(f); },
    removeEventListener() {},
  };
  return {
    signal,
    abort() {
      signal.aborted = true;
      listeners.slice().forEach((f) => { try { f(); } catch (e) {} });
    },
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function makeFake(tag) {
  const el = {
    _isFake: true,
    _tag: tag,
    _attrs: {},
    _val: '',
    _text: '',
    _classes: {},
    length: 1,
    calls: { html: [], append: [], attrSet: [] },
    attr(k, v) {
      if (v === undefined) return el._attrs[k];
      el._attrs[k] = v;
      el.calls.attrSet.push([k, v]);
      return el;
    },
    removeAttr(k) { delete el._attrs[k]; return el; },
    val(v) {
      if (v === undefined) return el._val;
      el._val = v;
      return el;
    },
    text(v) {
      if (v === undefined) return el._text;
      el._text = v;
      return el;
    },
    html(v) {
      if (v === undefined) return el._html || '';
      el._html = v;
      el.calls.html.push(v);
      return el;
    },
    find(sel) {
      if (el._find) return el._find(sel);
      return makeFake(tag + '>' + sel);
    },
    closest() { return el._closest || makeFake(tag + '^'); },
    prev() { return el._prev || makeFake(tag + '-'); },
    next() { return makeFake(tag + '+'); },
    last() { return el._last || el; },
    is() { return !!el._checked; },
    hasClass(c) { return !!el._classes[c]; },
    addClass(c) { el._classes[c] = true; return el; },
    removeClass(c) { delete el._classes[c]; return el; },
    prop(k, v) {
      el._props = el._props || {};
      if (v === undefined) return el._props[k];
      el._props[k] = v;
      return el;
    },
    css() { return 'none'; },
    show() { return el; },
    on() { return el; },
    append(v) { el.calls.append.push(v); return el; },
    remove() { return el; },
    empty() { return el; },
  };
  return el;
}

function okJson(obj) {
  return {
    status: 200,
    ok: true,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
    clone() { return okJson(obj); },
  };
}

function makeWorld() {
  const sel = { id: 'set-A', name: 'A', version: '5' };
  const chatRequests = C.createChatRequestTracker(makeController);
  const historyWindow = C.createHistoryWindow(40);
  const APP_DATA = {
    loggedIn: true,
    lastSetId: 'set-A',
    lastSet: 'A',
    setVersion: 5,
    autoplayTTS: false,
  };
  const window = {
    APP_DATA,
    CSRF_TOKEN: 'csrf-test',
    DEFAULT_SYSTEM_PROMPT: 'base prompt',
    location: { href: '' },
    voiceModeActive: false,
  };
  const fetchCalls = [];
  function fetch(url, init) {
    const d = deferred();
    const call = { url, init, resolve: d.resolve, reject: d.reject, readers: [] };
    fetchCalls.push(call);
    const sig = init && init.signal;
    if (sig && typeof sig.addEventListener === 'function') {
      sig.addEventListener('abort', () => {
        call.aborted = true;
        d.reject(abortError());
        call.readers.forEach((r) => r.abortPending());
      });
    }
    return d.promise;
  }
  function makeStream(call) {
    const events = { cancels: [] };
    const pending = [];
    const cancelRejected = () => Promise.reject(new Error('cancelled'));
    const reader = {
      read() {
        const d = deferred();
        pending.push(d);
        const sig = call && call.init && call.init.signal;
        if (sig && sig.aborted) d.reject(abortError());
        return d.promise;
      },
      cancel() { events.cancels.push('reader'); return cancelRejected(); },
      abortPending() { pending.splice(0).forEach((d) => d.reject(abortError())); },
    };
    if (call) call.readers.push(reader);
    const body = {
      cancel() { events.cancels.push('body'); return cancelRejected(); },
      getReader() { return reader; },
    };
    return { body, reader, pending, events };
  }

  const appended = [];
  const loads = [];
  const paints = [];
  const playback = { binds: [], retargets: [], publishes: [], finishes: [] };
  const errors = [];
  let redirects = 0;
  let csrf = 'csrf-test';
  const regenCalls = [];

  const optionFake = makeFake('option:selected');
  const sendButton = makeFake('#send-button');
  const userInput = makeFake('#user-input');
  const systemPromptInput = makeFake('#user-system-prompt');
  systemPromptInput._val = 'prompt A';
  const modelSelect = makeFake('#modelSelect');
  modelSelect._val = 'model-a';
  const userFake = makeFake('user-message');
  const aiFake = makeFake('ai-message');
  const textFake = makeFake('ai-message-text');
  const thinkFake = makeFake('thinking-content');
  aiFake._find = (s) => {
    if (String(s).includes('ai-message-text')) return textFake;
    if (String(s).includes('thinking')) return thinkFake;
    return makeFake('ai' + s);
  };
  userFake._last = userFake;
  function syncOption() {
    optionFake._attrs['data-name'] = sel.name;
    optionFake._attrs['data-version'] = sel.version;
    optionFake._text = sel.name;
  }
  syncOption();

  const setSelector = makeFake('#set-selector');
  setSelector.val = () => sel.id;
  setSelector.find = () => optionFake;
  const selectors = {
    '#user-input': userInput,
    '#user-system-prompt': systemPromptInput,
    '#user-memory': makeFake('#user-memory'),
    '#modelSelect': modelSelect,
    '#web-search-toggle': makeFake('#web-search-toggle'),
    '#check-save-thoughts': makeFake('#check-save-thoughts'),
    '#check-send-thoughts': makeFake('#check-send-thoughts'),
    '#set-selector': setSelector,
    '#set-selector option:selected': optionFake,
    '#send-button': sendButton,
    '#image-input': makeFake('#image-input'),
    '#chat-content .message.user-message': userFake,
    '.ai-message:last-child': aiFake,
    '#chat-content': makeFake('#chat-content'),
  };
  function $(s) {
    if (s && s._isFake) return s;
    if (typeof s !== 'string') return makeFake('obj');
    return selectors[s] || makeFake(s);
  }

  const sessionClient = S.createSessionClient({
    getLoggedIn: () => !!window.APP_DATA.loggedIn,
    getCsrfToken: () => csrf,
    setCsrfToken: (t) => { csrf = t; },
    redirectHome: () => { redirects++; },
    sleep: () => Promise.resolve(),
    fetchImpl: (url, init) => fetch(url, init),
  });

  const box = {
    console: { error(e) { errors.push(String(e)); }, debug() {}, log() {} },
    window,
    document: { querySelectorAll: () => box.__domList || [], getElementById: () => null },
    __domList: [],
    $,
    fetch,
    ChatConversationState: C,
    ChatSessionClient: S,
    ChatStreamDecoder: D,
    sessionClient,
    voiceLifecycle: { isTtsActive: () => false, getCurrentButton: () => null },
    TextDecoder,
    TextEncoder,
    setTimeout,
    clearTimeout,
    Promise,
    SESSION_EXPIRED_SEND_MSG: S.SESSION_EXPIRED_SEND_MSG,
    pendingImageData: null,
    pendingImagePreview: null,
    liveStreamPlaybackSource: null,
    chatRequests,
    historyWindow,
    appendMessage: (m, c, p) => { appended.push({ message: m, className: c, pairIndex: p }); return makeFake('appended'); },
    loadSets: (b) => { loads.push(b); return Promise.resolve(); },
    paintFailedAiTurn: (u, t) => { paints.push(String(t)); return aiFake; },
    bindMessagePlaybackSource: (h, s) => {
      const src = { finished: false, finish() { src.finished = true; playback.finishes.push('source'); } };
      playback.binds.push(s);
      return src;
    },
    retargetMessagePlaybackSource: (h, s) => { playback.retargets.push(s); return {}; },
    publishMessagePlaybackText: (e, o, v) => { playback.publishes.push([o, v]); },
    finishMessagePlayback: () => { playback.finishes.push(true); },
    renderMarkdown: (t) => t,
    buildAiStreamChildren: () => ({}),
    buildAiErrorChildren: (m) => ({ msg: m }),
    replaceChildrenNative: () => {},
    markLocalOnlyTurn: () => {},
    clearLocalOnlyTurn: () => {},
    removeLocalOnlyTurn: () => {},
    reindexUserPairIndices: () => {},
    scrollToBottom: () => {},
    shouldStickChatToBottom: () => false,
    playMessageTts: () => {},
    primeDesktopTtsAudioFromGesture: () => {},
    activeSetName: () => sel.name,
  };
  box.window.sendMessage = function () {};
  box.window.performRegeneration = function () { regenCalls.push(Array.from(arguments)); };
  const ctx = vm.createContext(box);

  for (const [startAnchor, endAnchor] of slices) {
    vm.runInContext(loadSlice(startAnchor, endAnchor), ctx);
  }
  // The regen slice assigns window handlers; expose bare aliases for direct
  // calls, then point the window entry at the submit spy for the pair tests.
  vm.runInContext('var regenerateMessage = window.regenerateMessage; var performRegeneration = window.performRegeneration;', ctx);
  box.window.performRegeneration = function () { regenCalls.push(Array.from(arguments)); };

  const world = {
    sel,
    syncOption,
    chatRequests,
    historyWindow,
    window,
    APP_DATA,
    fetchCalls,
    fetch,
    makeStream,
    appended,
    loads,
    paints,
    playback,
    errors,
    regenCalls,
    redirects: () => redirects,
    ctx,
    userFake,
    aiFake,
    textFake,
    userInput,
    systemPromptInput,
    sendButton,
    switchTo(id, name, version) {
      sel.id = id;
      sel.name = name;
      sel.version = String(version);
      syncOption();
      APP_DATA.lastSetId = id;
      APP_DATA.lastSet = name;
      APP_DATA.setVersion = version;
      historyWindow.beginSetLoad();
      vm.runInContext('settleChatRequestForSetSwitch()', ctx);
    },
  };
  return world;
}

function lastFetch(world) {
  return world.fetchCalls[world.fetchCalls.length - 1];
}

function fetchBody(call) {
  return JSON.parse(call.init.body);
}

async function scenarioChatSwitch() {
  const w = makeWorld();
  w.userInput._val = 'hello A';
  vm.runInContext('sendMessage({ message: "hello A" })', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'chat-switch: one request sent');
  const first = lastFetch(w);
  assert.equal(first.url, '/chat', 'chat-switch: posts to /chat');
  assert.deepEqual(
    { set_id: fetchBody(first).set_id, message: fetchBody(first).message },
    { set_id: 'set-A', message: 'hello A' },
    'chat-switch: body targets the initiating set'
  );
  assert.equal(w.chatRequests.isGenerating(), true, 'chat-switch: request generates');

  // Headers arrive only after the switch to B.
  w.switchTo('set-B', 'B', 3);
  assert.equal(w.chatRequests.isGenerating(), false, 'chat-switch: switch settles the old ownership');
  assert.equal(first.init.signal.aborted, true, 'chat-switch: switch aborts the old fetch');
  const stream = w.makeStream(first);
  first.resolve({ status: 200, ok: true, body: stream.body });
  await flush();
  assert(
    !w.appended.some((a) => a.className === 'ai-message'),
    'chat-switch: delayed headers append nothing into B'
  );

  // A replacement request in B stays fully usable.
  w.userInput._val = 'hi B';
  vm.runInContext('sendMessage({ message: "hi B" })', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 2, 'chat-switch: replacement sends');
  const second = lastFetch(w);
  assert.equal(fetchBody(second).set_id, 'set-B', 'chat-switch: replacement targets B');
  const stream2 = w.makeStream(second);
  second.resolve({ status: 200, ok: true, body: stream2.body });
  await flush();
  assert(w.appended.some((a) => a.className === 'ai-message'), 'chat-switch: replacement appends');
  const enc = new TextEncoder();
  stream2.pending[0].resolve({ done: false, value: enc.encode('Hello. ') });
  await flush();
  assert(w.textFake.calls.html.length > 0, 'chat-switch: replacement chunks render');
  stream2.pending[1].resolve({ done: true, value: enc.encode('') });
  await flush();
  assert.equal(w.APP_DATA.setVersion, 4, 'chat-switch: replacement advances B');
  assert.equal(w.historyWindow.snapshot().total, 1, 'chat-switch: replacement accounts B');
  assert.equal(w.chatRequests.isGenerating(), false, 'chat-switch: replacement settles');
  assert(w.loads.length > 0, 'chat-switch: replacement refreshes the set list');
}

async function scenarioAbortedStreamStaysSilent() {
  const w = makeWorld();
  w.userInput._val = 'hello A';
  vm.runInContext('sendMessage({ message: "hello A" })', w.ctx);
  await flush();
  const first = lastFetch(w);
  const stream = w.makeStream(first);
  first.resolve({ status: 200, ok: true, body: stream.body });
  await flush();
  assert(w.appended.some((a) => a.className === 'ai-message'), 'aborted-stream: live headers append');
  w.switchTo('set-B', 'B', 3);
  await flush();
  assert(w.playback.finishes.includes('source'), 'aborted-stream: switch finishes the outgoing source');
  assert.equal(w.textFake.calls.append.length, 0, 'aborted-stream: no [Stopped] painted into B');
  assert.equal(w.APP_DATA.setVersion, 3, 'aborted-stream: B version untouched');
  assert.equal(w.historyWindow.snapshot().total, 0, 'aborted-stream: B accounting untouched');
}

async function scenarioChatQueuedStale() {
  // Chunk bytes already resolved, then the switch lands before the loop runs.
  const w = makeWorld();
  w.userInput._val = 'hello A';
  vm.runInContext('sendMessage({ message: "hello A" })', w.ctx);
  await flush();
  const first = lastFetch(w);
  const stream = w.makeStream(first);
  first.resolve({ status: 200, ok: true, body: stream.body });
  await flush();
  assert(w.appended.some((a) => a.className === 'ai-message'), 'queued-chat: live headers append');
  stream.pending[0].resolve({ done: false, value: new TextEncoder().encode('Hello. ') });
  w.switchTo('set-B', 'B', 3);
  await flush();
  assert.equal(w.textFake.calls.html.length, 0, 'queued-chat: resolved chunk never renders into B');
  assert.deepEqual(stream.events.cancels, ['reader'], 'queued-chat: resolved stream is cancelled');
  assert.equal(w.APP_DATA.setVersion, 3, 'queued-chat: B version untouched');
  assert.equal(w.historyWindow.snapshot().total, 0, 'queued-chat: B accounting untouched');

  // Completion bytes already resolved, then the switch lands first.
  const v = makeWorld();
  v.userInput._val = 'hello A';
  vm.runInContext('sendMessage({ message: "hello A" })', v.ctx);
  await flush();
  const vf = lastFetch(v);
  const vstream = v.makeStream(vf);
  vf.resolve({ status: 200, ok: true, body: vstream.body });
  await flush();
  vstream.pending[0].resolve({ done: true, value: new TextEncoder().encode('') });
  v.switchTo('set-B', 'B', 3);
  await flush();
  assert.equal(v.APP_DATA.setVersion, 3, 'queued-chat: resolved completion never bumps B');
  assert.equal(v.historyWindow.snapshot().total, 0, 'queued-chat: resolved completion never accounts B');
  assert.equal(v.loads.length, 0, 'queued-chat: resolved completion never refreshes for B');
}

async function scenarioRegenReplacement() {
  const w = makeWorld();
  w.ctx.__ai = w.aiFake;
  w.ctx.__utext = 'q';
  w.ctx.__pair = 0;
  vm.runInContext('performRegeneration(__ai, __utext, __pair)', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'regen: first sends');
  const stale = w.makeStream(w.fetchCalls[0]);
  w.fetchCalls[0].resolve({ status: 200, ok: true, body: stale.body });
  await flush();
  // A chunk resolves, then the replacement starts before the loop continues.
  stale.pending[0].resolve({ done: false, value: new TextEncoder().encode('Stale text. ') });
  vm.runInContext('performRegeneration(__ai, __utext, __pair)', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 2, 'regen: replacement sends');
  assert.equal(w.textFake.calls.html.length, 0, 'regen: stale chunk never renders');
  assert.deepEqual(stale.events.cancels, ['reader'], 'regen: stale stream is cancelled');
  assert.equal(w.APP_DATA.setVersion, 5, 'regen: stale work never bumps the version');
  if (stale.pending.length > 1) {
    stale.pending[1].resolve({ done: true, value: new TextEncoder().encode('') });
    await flush();
    assert.equal(w.APP_DATA.setVersion, 5, 'regen: stale completion never applies');
  }
  const live = w.makeStream(w.fetchCalls[1]);
  w.fetchCalls[1].resolve({ status: 200, ok: true, body: live.body });
  await flush();
  live.pending[0].resolve({ done: false, value: new TextEncoder().encode('Fresh answer. ') });
  await flush();
  assert.deepEqual(w.textFake.calls.html, ['Fresh answer. '], 'regen: replacement renders once');
  live.pending[1].resolve({ done: true, value: new TextEncoder().encode('') });
  await flush();
  assert.equal(w.APP_DATA.setVersion, 6, 'regen: replacement advances the version');
  assert.equal(w.chatRequests.isGenerating(), false, 'regen: replacement settles');
  assert.equal(w.playback.finishes.length, 1, 'regen: only the replacement settles playback');
}

async function scenarioMemoryRetry() {
  const w = makeWorld();
  vm.runInContext('saveMemoryNow("A-memory", false)', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'memory: save sends');
  assert.equal(fetchBody(lastFetch(w)).set_id, 'set-A', 'memory: body targets A');
  const first = lastFetch(w);
  w.switchTo('set-B', 'B', 3);
  first.resolve({ status: 401, ok: false, json: async () => ({}), text: async () => '{}' });
  await flush(120);
  const boot = w.fetchCalls.find((c) => c.url === '/login');
  assert(boot, 'memory: 401 refreshes the session');
  boot.resolve({
    status: 200,
    ok: true,
    text: async () => '<input name="csrf_token" value="boot-csrf">',
    json: async () => ({}),
  });
  await flush(120);
  const remember = w.fetchCalls.find((c) => c.url === '/login/remember');
  assert(remember, 'memory: refresh redeems the remember cookie');
  remember.resolve({ status: 200, ok: true, json: async () => ({ csrf_token: 'new-csrf' }) });
  await flush(120);
  const second = w.fetchCalls.find((c) => c.url === '/update_memory' && c !== first);
  assert(second, 'memory: retries after refresh');
  assert.deepEqual(
    {
      set_id: fetchBody(second).set_id,
      memory: fetchBody(second).memory,
      expected_version: fetchBody(second).expected_version,
    },
    { set_id: 'set-A', memory: 'A-memory', expected_version: 5 },
    'memory: retry resends A against A, never B'
  );
  second.resolve(okJson({ status: 'success', set_id: 'set-A', version: 6 }));
  await flush();
  assert.equal(w.APP_DATA.setVersion, 3, 'memory: stale success never syncs into B');
  assert(
    !w.appended.some((a) => /Memory saved/.test(String(a.message))),
    'memory: stale success stays silent in B'
  );

  // Same-set conflict retries with the authoritative version and applies.
  const v = makeWorld();
  vm.runInContext('saveMemoryNow("m", false)', v.ctx);
  await flush();
  const m1 = lastFetch(v);
  m1.resolve(okJson({ error: 'version_conflict', set_id: 'set-A', current_version: 6 }));
  await flush();
  const m2 = lastFetch(v);
  assert(m2 !== m1, 'memory: conflict retries once');
  assert.equal(fetchBody(m2).expected_version, 6, 'memory: retry uses the authoritative version');
  assert.equal(fetchBody(m2).set_id, 'set-A', 'memory: retry keeps the set');
  m2.resolve(okJson({ status: 'success', set_id: 'set-A', version: 7 }));
  await flush();
  assert.equal(v.APP_DATA.setVersion, 7, 'memory: same-set success syncs');
  assert(v.appended.some((a) => /Memory saved/.test(String(a.message))), 'memory: same-set confirms');
}

async function scenarioSystemPromptRetry() {
  const w = makeWorld();
  vm.runInContext('saveSystemPromptNow("A-prompt", false)', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'prompt: save sends');
  assert.equal(w.fetchCalls[0].url, '/update_system_prompt', 'prompt: posts to /update_system_prompt');
  assert.deepEqual(
    {
      set_id: fetchBody(lastFetch(w)).set_id,
      system_prompt: fetchBody(lastFetch(w)).system_prompt,
      expected_version: fetchBody(lastFetch(w)).expected_version,
    },
    { set_id: 'set-A', system_prompt: 'A-prompt', expected_version: 5 },
    'prompt: body targets A'
  );
  const first = lastFetch(w);
  w.switchTo('set-B', 'B', 3);
  first.resolve({ status: 401, ok: false, json: async () => ({}), text: async () => '{}' });
  await flush(120);
  w.fetchCalls.find((c) => c.url === '/login').resolve({
    status: 200,
    ok: true,
    text: async () => '<input name="csrf_token" value="boot-csrf">',
    json: async () => ({}),
  });
  await flush(120);
  w.fetchCalls.find((c) => c.url === '/login/remember').resolve({
    status: 200,
    ok: true,
    json: async () => ({ csrf_token: 'new-csrf' }),
  });
  await flush(120);
  const second = w.fetchCalls.find((c) => c.url === '/update_system_prompt' && c !== first);
  assert(second, 'prompt: retries after refresh');
  assert.deepEqual(
    {
      set_id: fetchBody(second).set_id,
      system_prompt: fetchBody(second).system_prompt,
      expected_version: fetchBody(second).expected_version,
    },
    { set_id: 'set-A', system_prompt: 'A-prompt', expected_version: 5 },
    'prompt: retry resends A against A, never B'
  );
  second.resolve(okJson({ status: 'success', set_id: 'set-A', version: 6 }));
  await flush();
  assert.equal(w.APP_DATA.setVersion, 3, 'prompt: stale success never syncs into B');
  assert(
    !w.appended.some((a) => /System prompt saved/.test(String(a.message))),
    'prompt: stale success stays silent in B'
  );

  // Same-set conflict retries with the authoritative version and applies.
  const v = makeWorld();
  vm.runInContext('saveSystemPromptNow("p", false)', v.ctx);
  await flush();
  const m1 = lastFetch(v);
  m1.resolve(okJson({ error: 'version_conflict', set_id: 'set-A', current_version: 6 }));
  await flush();
  const m2 = lastFetch(v);
  assert(m2 !== m1, 'prompt: conflict retries once');
  assert.equal(fetchBody(m2).expected_version, 6, 'prompt: retry uses the authoritative version');
  m2.resolve(okJson({ status: 'success', set_id: 'set-A', version: 7 }));
  await flush();
  assert.equal(v.APP_DATA.setVersion, 7, 'prompt: same-set success syncs');
  assert(v.appended.some((a) => /System prompt saved/.test(String(a.message))), 'prompt: same-set confirms');
}

async function scenarioMemoryErrorUi() {
  const w = makeWorld();
  vm.runInContext('saveMemoryNow("A-memory", false)', w.ctx);
  await flush();
  const first = lastFetch(w);
  w.switchTo('set-B', 'B', 3);
  first.resolve(okJson({ error: 'boom' }));
  await flush();
  assert.equal(w.appended.length, 0, 'memory-error: stale failure stays silent in B');
  const v = makeWorld();
  vm.runInContext('saveMemoryNow("m", false)', v.ctx);
  await flush();
  lastFetch(v).reject(new Error('net down'));
  await flush();
  assert(v.appended.some((a) => /net down/.test(String(a.message))), 'memory-error: live failure reports');
  const u = makeWorld();
  vm.runInContext('saveMemoryNow("m", false)', u.ctx);
  await flush();
  lastFetch(u).resolve(okJson({ error: 'boom' }));
  await flush();
  assert(u.appended.some((a) => /boom/.test(String(a.message))), 'memory-error: live error reports');
}

async function scenarioPairPreread() {
  const w = makeWorld();
  w.ctx.__domList = [w.userFake];
  w.userFake._attrs['data-thumb'] = '1';
  w.userFake._attrs['data-local-only'] = '0';
  w.userFake._text = 'thumb [IMAGE:x]';
  const btn = makeFake('regen-button');
  btn._closest = w.aiFake;
  w.aiFake._prev = w.userFake;
  w.ctx.__btn = btn;
  vm.runInContext('regenerateMessage(__btn)', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'pair: pre-read fetches');
  assert.equal(w.fetchCalls[0].url, '/history_pair', 'pair: pre-read hits history_pair');
  assert.equal(fetchBody(w.fetchCalls[0]).set_id, 'set-A', 'pair: pre-read targets A');
  w.switchTo('set-B', 'B', 3);
  w.fetchCalls[0].resolve(okJson({ user: 'full A text', set_id: 'set-A', version: 6 }));
  await flush();
  assert.equal(w.regenCalls.length, 0, 'pair: stale pre-read never submits A into B');
  assert.equal(w.APP_DATA.lastSetId, 'set-B', 'pair: stale pre-read never rebinds the selection');
  assert.equal(w.APP_DATA.setVersion, 3, 'pair: stale pre-read never syncs B');

  const v = makeWorld();
  v.ctx.__domList = [v.userFake];
  v.userFake._attrs['data-thumb'] = '1';
  v.userFake._attrs['data-local-only'] = '0';
  v.userFake._text = 'thumb [IMAGE:x]';
  const btn2 = makeFake('regen-button');
  btn2._closest = v.aiFake;
  v.aiFake._prev = v.userFake;
  v.ctx.__btn = btn2;
  vm.runInContext('regenerateMessage(__btn)', v.ctx);
  await flush();
  v.fetchCalls[0].resolve(okJson({ user: 'full A text', set_id: 'set-A', version: 6 }));
  await flush();
  assert.equal(v.regenCalls.length, 1, 'pair: live pre-read submits');
  assert.equal(v.regenCalls[0][1], 'full A text', 'pair: live pre-read submits the full text');
}

async function scenarioPagination() {
  const w = makeWorld();
  w.historyWindow.applyPage(
    { history: [['u', 'a']], history_start: 8, history_total: 10, has_more: true },
    'replace'
  );
  const applied = [];
  w.ctx.applyHistoryPage = function (d, m) { applied.push(d); };
  vm.runInContext('loadOlderMessages()', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 1, 'pagination: older page fetches');
  assert.equal(fetchBody(lastFetch(w)).before, 8, 'pagination: pages before the offset');
  const first = lastFetch(w);
  w.switchTo('set-B', 'B', 3);
  w.historyWindow.applyPage(
    { history: [['b', 'c']], history_start: 5, history_total: 6, has_more: true },
    'replace'
  );
  vm.runInContext('loadOlderMessages()', w.ctx);
  await flush();
  assert.equal(w.fetchCalls.length, 2, 'pagination: new selection pages while old is in flight');
  first.resolve(okJson({ history: [['stale', 'x']], history_start: 7, history_total: 10, has_more: false, set_id: 'set-A' }));
  await flush(120);
  assert.equal(applied.length, 0, 'pagination: stale page never renders');
  assert.equal(w.historyWindow.snapshot().loadingOlder, true, 'pagination: stale settlement keeps the new load');
  const second = lastFetch(w);
  second.resolve(okJson({ history: [['older', 'y']], history_start: 4, history_total: 6, has_more: false, set_id: 'set-B' }));
  await flush(120);
  assert.equal(applied.length, 1, 'pagination: live page renders once');
  assert.equal(applied[0].history_start, 4, 'pagination: live page carries its offset');
  assert.equal(w.historyWindow.snapshot().loadingOlder, false, 'pagination: live settlement clears');
}

(async () => {
  const cases = [
    ['chat-switch', scenarioChatSwitch],
    ['aborted-stream', scenarioAbortedStreamStaysSilent],
    ['chat-queued-stale', scenarioChatQueuedStale],
    ['regen-replacement', scenarioRegenReplacement],
    ['memory-retry', scenarioMemoryRetry],
    ['prompt-retry', scenarioSystemPromptRetry],
    ['memory-error-ui', scenarioMemoryErrorUi],
    ['pair-preread', scenarioPairPreread],
    ['pagination', scenarioPagination],
  ];
  const failures = [];
  for (const [name, fn] of cases) {
    try {
      await fn();
    } catch (e) {
      failures.push(name + ': ' + (e && e.message ? e.message : String(e)));
    }
  }
  await flush();
  if (unhandled.length) {
    failures.push('unhandledRejection: ' + unhandled.join('; '));
  }
  if (failures.length) {
    console.error('conversation application FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('conversation application: actual adapters fence every stale response');
})().catch((e) => { console.error(e); process.exitCode = 1; });
