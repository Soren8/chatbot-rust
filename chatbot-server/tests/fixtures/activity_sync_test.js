'use strict';
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const context = { module: { exports: {} }, AbortController, TextDecoder, TextEncoder, Promise, TypeError, Error, setTimeout, clearTimeout };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);
const api = context.module.exports;
const tick = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
function response(status, data, reader) {
  return { status, ok: status >= 200 && status < 300, json: async () => data, text: async () => JSON.stringify(data), body: reader && { getReader: () => reader } };
}
function frames(lines, fail) {
  let i = 0;
  return { read: async () => {
    if (i < lines.length) return { value: new TextEncoder().encode(JSON.stringify(lines[i++]) + '\n'), done: false };
    if (fail) throw new TypeError('lost');
    return { done: true };
  }, cancel: async () => {} };
}
function harness(fetchImpl, extra) {
  const waits = [], states = [], events = [], timers = [];
  let time = 0;
  const sync = api.createActivitySync(Object.assign({ fetch: fetchImpl, rng: () => 0.5, clock: () => time,
    sleep: async ms => { waits.push(ms); time += ms; }, setTimeout: (fn, ms) => { const t = { fn, ms, active: true }; timers.push(t); return t; }, clearTimeout: t => { t.active = false; },
    refreshSession: async () => true, refreshCsrfInit: init => Object.assign({}, init, { headers: Object.assign({}, init.headers, { 'X-CSRF-Token': 'new' }) }),
    onState: s => states.push(s), onEvent: e => events.push(e), reconcile: async () => {} }, extra));
  return { sync, waits, states, events, timers };
}
const delta = (seq, text) => ({ seq, type: 'delta', text });
(async () => {
  let releaseVoice;
  const laneCalls = [];
  let lane = harness(async url => {
    laneCalls.push(url);
    if (url === '/tts') return new Promise(resolve => { releaseVoice = () => resolve(response(200, {})); });
    return response(200, {});
  });
  const hangingVoice = lane.sync.request('/tts', { method: 'POST' });
  await tick();
  const priorityStop = lane.sync.request('/generations/g/stop', { method: 'POST' });
  await tick();
  assert.ok(laneCalls.includes('/generations/g/stop'), 'Stop must bypass hanging TTS admission');
  releaseVoice(); await hangingVoice; await priorityStop;
  let releaseSet;
  const orderedCalls = [];
  lane = harness(async url => {
    orderedCalls.push(url);
    if (url === '/set_memory') return new Promise(resolve => { releaseSet = () => resolve(response(200, {})); });
    return response(200, {});
  });
  const firstSet = lane.sync.request('/set_memory', { method: 'POST' });
  const secondSet = lane.sync.request('/set_system_prompt', { method: 'POST' });
  const independentStt = lane.sync.request('/stt', { method: 'POST' });
  await tick();
  assert.ok(orderedCalls.includes('/stt'), 'STT must bypass ordered set writes');
  assert.ok(!orderedCalls.includes('/set_system_prompt'), 'ordered writes must remain serialized');
  releaseSet(); await firstSet; await secondSet; await independentStt;
  console.log('PASS Stop and voice bypass ordered mutation lane');

  let keys = [], admissions = 0, urls = [];
  let h = harness(async (url, init) => {
    urls.push(url);
    if (url === '/chat') { keys.push(init.headers['Idempotency-Key']); if (++admissions === 1) throw new TypeError('accepted, response lost'); return response(202, { generation_id: 'g' }); }
    return response(200, null, frames([delta(1, 'hello'), { seq: 2, type: 'saved' }]));
  });
  await h.sync.start({ kind: 'chat', set_id: 's', message: 'hello' }); await tick();
  assert.equal(keys.length, 2); assert.equal(keys[0], keys[1]); assert.ok(keys[0]);
  assert.equal(h.events.filter(e => e.type === 'delta').length, 1);
  console.log('PASS admission response loss retains key');

  let attempts = 0; urls = [];
  h = harness(async url => { urls.push(url); return response(200, null, ++attempts === 1 ? frames([delta(1, 'a'), { type: 'heartbeat' }], true) : frames([delta(1, 'a'), delta(2, 'b'), { seq: 3, type: 'saved' }])); });
  await h.sync.attach({ generation_id: 'g' });
  assert.ok(urls[1].endsWith('after=1')); assert.equal(h.events.filter(e => e.type === 'delta').map(e => e.text).join(''), 'ab');
  console.log('PASS stream drop, duplicates and heartbeat cursor');

  attempts = 0;
  h = harness(async url => response(200, null, ++attempts === 1 ? frames([delta(2, 'gap')]) : frames([delta(1, 'a'), delta(2, 'b'), { seq: 3, type: 'saved' }])));
  await h.sync.attach({ generation_id: 'gap' });
  assert.equal(h.events.filter(e => e.type === 'delta').map(e => e.text).join(''), 'ab');
  console.log('PASS contiguous gap replay');

  attempts = 0;
  h = harness(async (url, init) => {
    if (++attempts > 1) return response(200, null, frames([{ seq: 1, type: 'saved' }]));
    return response(200, null, { read: () => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => { const e = new Error('abort'); e.name = 'AbortError'; reject(e); })), cancel: async () => {} });
  });
  const idle = h.sync.attach({ generation_id: 'idle' }); await tick();
  const timer = h.timers.find(t => t.active && t.ms === 20000); assert.ok(timer); timer.fn(); await idle;
  assert.equal(attempts, 2);
  console.log('PASS twenty second idle reconnect');

  let reconciled = 0;
  h = harness(async url => url === '/chat' ? response(409, { error: 'generation_active', generation: { generation_id: 'active' } }) : response(200, null, frames([{ type: 'heartbeat' }, { seq: 1, type: 'saved' }])), { reconcile: async () => { reconciled++; } });
  const conflict = await h.sync.start({ message: 'queued', set_id: 's' }); await tick();
  assert.equal(conflict.queued, true); assert.equal(h.sync.queued().message, 'queued'); assert.equal(reconciled, 1);
  console.log('PASS active conflict queues without sending');

  const stopped = [];
  h = harness(async (url, init) => { stopped.push([url, init]); if (url.endsWith('/stop')) return response(200, {}); return response(200, null, { read: () => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => { const e = new Error(); e.name = 'AbortError'; reject(e); })), cancel: async () => {} }); });
  const view = h.sync.attach({ generation_id: 'stop' }); await tick(); await h.sync.stop(); h.sync.detach(); await view;
  assert.equal(stopped.filter(x => x[0].endsWith('/stop')).length, 1); assert.ok(stopped.find(x => x[0].endsWith('/stop'))[1].headers['Idempotency-Key']);
  const count = stopped.length; h.sync.detach(); assert.equal(stopped.length, count);
  console.log('PASS explicit stop and quiet detach');

  h = harness(async () => response(404, {})); await h.sync.attach({ generation_id: 'missing' });
  assert.ok(h.states.includes('needs-action')); assert.equal(h.sync.interrupted(), true);
  console.log('PASS unknown worker interrupted');

  let n = 0;
  h = harness(async () => { if (++n === 1) throw new TypeError('offline'); return response(200, { sets: ['s'] }); });
  assert.deepEqual((await (await h.sync.request('/get_sets')).json()).sets, ['s']); assert.ok(h.states.includes('reconnecting'));
  assert.equal(h.waits[0], 250);
  console.log('PASS page load recovery');

  n = 0;
  h = harness(async () => { if (++n < 12) return response(503, {}); return response(200, {}); });
  await h.sync.request('/get_sets'); assert.deepEqual(h.waits.slice(0, 3), [250, 500, 1000]); assert.equal(h.waits.at(-1), 15000);
  console.log('PASS full jitter exponential capped delay');

  keys = []; let refreshes = 0; n = 0;
  h = harness(async (url, init) => { keys.push(init.headers['Idempotency-Key']); return response(++n === 1 ? 401 : 200, {}); }, { refreshSession: async () => { refreshes++; return true; } });
  await h.sync.request('/fork_set', { method: 'POST', body: '{}' }); assert.equal(keys[0], keys[1]); assert.equal(refreshes, 1);
  console.log('PASS csrf refresh and fork reuse');

  let payload;
  h = harness(async (url, init) => { payload = JSON.parse(init.body); return response(200, {}); });
  await h.sync.request('/create_set', { method: 'POST', body: '{}' }); assert.ok(payload.name);
  console.log('PASS explicit create name');

  let aborted = false;
  h = harness((url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => { aborted = true; const e = new Error(); e.name = 'AbortError'; reject(e); })));
  const read = h.sync.request('/load_set', { method: 'POST', body: '{}' }).catch(e => e.name); await tick(); h.sync.navigate('next');
  assert.equal(await read, 'AbortError'); assert.ok(aborted);
  console.log('PASS stale reads abort on navigation');

  const order = [];
  h = harness(async url => { order.push(url); return response(200, { generations: [] }); }, { refreshSession: async () => { order.push('refresh'); return true; }, reconcile: async () => { order.push('reconcile'); } });
  h.sync.navigate('s');
  await Promise.all([h.sync.recover(), h.sync.recover(), h.sync.recover()]);
  assert.deepEqual(order, ['refresh', '/activity?set_id=s', 'reconcile']);
  console.log('PASS recovery triggers coalesce and order');

  let releaseWait, sends = 0;
  h = harness(async url => {
    if (url === '/fork_set' && ++sends === 1) throw new TypeError('offline');
    return response(200, { generations: [] });
  }, { sleep: () => new Promise(resolve => { releaseWait = resolve; }) });
  const pending = h.sync.request('/fork_set', { method: 'POST', body: '{}' });
  await tick();
  const recovery = h.sync.recover(); await tick();
  assert.equal(sends, 2, 'recovery kicks pending retry before backoff expires');
  await pending; await recovery; releaseWait();
  console.log('PASS recovery wakes pending retry');

  let newKeys = [];
  h = harness(async (url, init) => {
    if (url === '/chat') { newKeys.push(init.headers['Idempotency-Key']); return response(202, { generation_id: 'new' }); }
    return response(404, {});
  });
  let r = await h.sync.generationResponse('chat', { body: JSON.stringify({ message: 'retry' }) });
  await assert.rejects(r.body.getReader().read(), /interrupted.*Retry/i);
  r = await h.sync.generationResponse('chat', { body: JSON.stringify({ message: 'retry' }) });
  await assert.rejects(r.body.getReader().read(), /interrupted.*Retry/i);
  assert.notEqual(newKeys[0], newKeys[1]);
  console.log('PASS interrupted reader and new retry identity');

  let imageAttempts = 0;
  h = harness(async () => { if (++imageAttempts === 1) throw new TypeError('image offline'); return response(200, {}); });
  await h.sync.request('/history_image/s/1/0/0?size=thumb'); assert.equal(imageAttempts, 2);
  console.log('PASS image read retry');

  let connectionKey;
  h = harness(async (url, init) => { connectionKey = init.headers['Idempotency-Key']; return response(200, {}); });
  await h.sync.request('/agent_connections', { method: 'POST', body: '{}' });
  assert.ok(connectionKey, 'connection create is a mutation');
  console.log('PASS connection create operation identity');

  let admitted;
  h = harness(url => url === '/chat' ? new Promise(resolve => { admitted = resolve; }) : response(200, null, frames([{ seq: 1, type: 'saved' }])));
  const oldStart = h.sync.start({ kind: 'chat', message: 'old' }); await tick();
  h.sync.navigate('new'); admitted(response(202, { generation_id: 'old' })); await oldStart; await tick();
  assert.equal(h.events.length, 0, 'navigation fences late admission attachments');
  console.log('PASS late admission view fence');

  let initialGets = 0;
  h = harness(async (url, init) => {
    if (url === '/chat') {
      assert.equal(init.headers['X-Generation-Mode'], 'durable');
      const res = response(202, null, frames([delta(1, 'initial'), { seq: 2, type: 'saved' }]));
      res.headers = { get: name => name === 'X-Generation-Id' ? 'initial' : null };
      return res;
    }
    initialGets++; return response(200, null, frames([{ seq: 1, type: 'saved' }]));
  });
  await h.sync.start({ kind: 'chat' }); await tick();
  assert.equal(initialGets, 0, 'clean admission consumes initial stream');
  assert.equal(h.events[0].text, 'initial');
  console.log('PASS initial durable response stream');

  let failureReads = 0;
  h = harness(async () => { failureReads++; return response(200, null, frames([{ seq: 1, type: 'error', text: 'provider failed' }, { seq: 2, type: 'ended' }])); }, { sleep: () => new Promise(() => {}) });
  const failed = h.sync.attach({ generation_id: 'failed' }); await tick();
  assert.equal(h.states.at(-1), 'needs-action', 'settled error must not reconnect');
  assert.equal(failureReads, 1); assert.equal(h.sync.interrupted(), true, 'failed settlement exposes Retry'); h.sync.detach();
  console.log('PASS terminal error needs action');

  h = harness(async url => url.endsWith('/status-failed') ? response(200, { state: 'failed' }) : response(200, null, frames([])), { sleep: () => new Promise(() => {}) });
  const statusFailed = h.sync.attach({ generation_id: 'status-failed' }); await tick();
  assert.equal(h.states.at(-1), 'needs-action', 'failed status must not reconnect'); h.sync.detach();
  console.log('PASS failed status needs action');

  let cancelReads = 0;
  h = harness(async url => { if (url === '/generations/cancel') return response(200, { state: 'running' }); cancelReads++; const reader = frames(cancelReads === 1 ? [] : [{ seq: 1, type: 'saved' }]); reader.cancel = () => new Promise(() => {}); return response(200, null, reader); });
  const hungCancel = h.sync.attach({ generation_id: 'cancel' }); await tick();
  assert.equal(cancelReads, 2, 'hung cancel must not block reconnect'); await hungCancel;
  console.log('PASS hung reader cancellation reconnects');

  const chatSource = fs.readFileSync(process.argv[3], 'utf8');
  function slice(start, end) { return chatSource.slice(chatSource.indexOf(start), chatSource.indexOf(end, chatSource.indexOf(start))); }
  let earlyStates = 0;
  const early = { renderRecoveredActivity() {}, renderInterruptedActivity() {}, window: { voiceModeActive: false }, document: { getElementById: () => ({ textContent: '' }) }, ChatActivitySync: { createActivitySync: deps => { deps.onState('reconnecting'); return {}; } }, sessionClient: { refreshSession() {}, installFetchInterceptor() {} }, chatRequests: { isGenerating: () => false }, setGeneratingState: () => { earlyStates++; vm.runInContext('loadedPrivacy', earlyCtx); } };
  const earlyCtx = vm.createContext(early);
  assert.doesNotThrow(() => vm.runInContext(slice('var activitySync =', 'window.activitySync =') + '\nlet loadedPrivacy = null;', earlyCtx), 'early recovery must not enter privacy TDZ');
  console.log('PASS recovery before privacy initialization');

  assert.ok(chatSource.includes("if (activitySync.interrupted()) replaceChildrenNative($target[0], buildAiErrorChildren(err.message));"), 'unknown regenerate must show error with Retry');
  assert.ok(chatSource.includes('onInterrupted: renderInterruptedActivity'), 'recovered unknown generation must be visible');
  assert.ok(!chatSource.includes(".attr('src', editSafeSrc)"), 'edit history preview must use retry loader');
  const rendererSource = fs.readFileSync(process.argv[3].replace('chat.js', 'chat-renderer.js'), 'utf8');
  assert.ok(rendererSource.includes('deps.loadHistoryImage(img, safeSrc)'), 'nondeferred history must use retry loader');
  console.log('PASS interruption and image routing wiring');
  let imageFetches = 0, renderedSrc;
  const imageHarness = harness(async () => { if (++imageFetches === 1) throw new TypeError('offline image'); return { ok: true, status: 200, blob: async () => ({}) }; });
  const imageCtx = vm.createContext({ activitySync: imageHarness.sync, historyWindow: { snapshot: () => ({ setGen: 1 }), isLiveGen: n => n === 1 }, URL: { createObjectURL: () => 'blob:retried-image', revokeObjectURL() {} } });
  vm.runInContext(slice('function loadHistoryImage(', 'function startDeferredThumbs('), imageCtx);
  imageCtx.image = { isConnected: true, setAttribute: (name, value) => { if (name === 'src') renderedSrc = value; } };
  vm.runInContext("loadHistoryImage(image, '/history_image/s/1/0/0')", imageCtx); await tick();
  assert.equal(imageFetches, 2); assert.equal(renderedSrc, 'blob:retried-image');
  console.log('PASS failed history image fetch retries and renders');

  let reconnectUrl;
  h = harness(async url => {
    if (url === '/regenerate') {
      const res = response(202, null, frames([delta(1, 'first')], true));
      res.headers = { get: name => name === 'X-Generation-Id' ? 'regen' : null }; return res;
    }
    reconnectUrl = url; return response(200, null, frames([delta(2, 'next'), { seq: 3, type: 'saved' }]));
  });
  await h.sync.start({ kind: 'regenerate' }); await tick();
  assert.ok(reconnectUrl.endsWith('after=1'));
  assert.equal(h.events.filter(e => e.type === 'delta').map(e => e.text).join(''), 'firstnext');
  console.log('PASS admission body drop resumes cursor');

  const voiceCalls = [];
  const voiceCtx = vm.createContext({ window: { voiceModeActive: true }, activitySync: {
    generationResponse: async (kind, init) => { voiceCalls.push(kind); return { status: 200 }; },
    queued: () => null, stop: () => { voiceCalls.push('stop'); return Promise.resolve(); }
  }, sessionClient: { fetchWithGenerateRetry: () => { throw new Error('legacy voice send'); } } });
  vm.runInContext(slice('function fetchWithGenerateRetry(', 'function setGeneratingState('), voiceCtx);
  await vm.runInContext("fetchWithGenerateRetry('/chat', {})", voiceCtx);
  assert.deepEqual(voiceCalls, ['chat'], 'voice sends must use deduplicated durable adapter');
  assert.ok(slice('  function handleBargeIn()', '  function applyVoiceAmendToUserMessage(').includes('activitySync.stop()'), 'confirmed barge-in explicitly stops server work');
  assert.ok(!chatSource.includes('if (window.voiceModeActive) noteLocalVersionBumpAfterPersist();'), 'voice durable persistence must not double bump');
  console.log('PASS voice durable send, confirmed Stop and persistence');

  keys = [];
  h = harness(async (url, init) => { keys.push(init.headers['Idempotency-Key']); return response(200, {}); });
  await h.sync.request('/tts', { method: 'POST', headers: { 'Idempotency-Key': 'sentence-1' }, body: '{}' });
  await h.sync.request('/tts', { method: 'POST', headers: { 'Idempotency-Key': 'sentence-1' }, body: '{}' });
  assert.deepEqual(keys, ['sentence-1', 'sentence-1'], 'sentence identity survives admission retries');
  console.log('PASS stable sentence admission identity');
  const voiceTransport = { activitySync: { request: async (url, init) => { assert.equal(url, '/stt'); assert.ok(init.headers); return { ok: true, status: 200, text: async () => '{"text":"once"}' }; } } };
  const voiceTransportCtx = vm.createContext(voiceTransport);
  vm.runInContext(slice('async function fetchVoiceRetry(', 'function withCsrf('), voiceTransportCtx);
  const transcript = await vm.runInContext("postVoiceSttXhr('/stt', () => ({method: 'POST', headers: {}, body: 'audio'}))", voiceTransportCtx);
  assert.equal(transcript.responseText, '{"text":"once"}');
  console.log('PASS STT uses sync retry owner');
  const ttsSource = fs.readFileSync(process.argv[3].replace('chat.js', 'tts-playback.js'), 'utf8');
  assert.ok(ttsSource.includes("'Idempotency-Key': sentenceOperation"), 'both playback paths attach sentence receipt identities');
  console.log('PASS sentence receipt wiring');

  let voiceView = 0;
  const spoken = [];
  h = harness(async url => {
    if (url === '/chat') return response(202, { generation_id: 'voice-reply' });
    return response(200, null, ++voiceView === 1
      ? frames([delta(1, 'First sentence.')], true)
      : frames([delta(1, 'First sentence.'), delta(2, ' Second sentence.'), {seq: 3, type: 'saved'}]));
  });
  const voiceResponse = await h.sync.generationResponse('chat', {body: JSON.stringify({message: 'voice'})});
  const voiceReader = voiceResponse.body.getReader();
  while (true) {
    const chunk = await voiceReader.read();
    if (chunk.done) break;
    spoken.push(new TextDecoder().decode(chunk.value));
  }
  assert.deepEqual(spoken, ['First sentence.', ' Second sentence.'], 'reconnected renderer sentence discovery receives new text only');
  assert.ok(!slice('function renderRecoveredActivity(', 'function renderInterruptedActivity(').includes('playTTS('), 'reload recovered text must not autoplay');
  console.log('PASS voice reconnect sentence cursor and silent reload recovery');
  let voiceBusy = 0;
  h = harness(async () => response(++voiceBusy === 1 ? 429 : 200, {}));
  await h.sync.request('/tts', {method: 'POST', body: '{}'});
  assert.equal(voiceBusy, 2, 'voice admission busy retries through sync policy');
  console.log('PASS voice busy sync recovery');
})().catch(e => { console.error(e); process.exitCode = 1; });
