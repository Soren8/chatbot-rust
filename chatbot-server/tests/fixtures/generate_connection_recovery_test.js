'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
// Reuse the composed adapter harness without changing its existing tests.
const source = fs.readFileSync(path.join(__dirname, 'conversation_request_application_test.js'), 'utf8');
const box = { require, process, console, TextDecoder, TextEncoder };
vm.runInNewContext(source.slice(0, source.indexOf('(async () => {')) +
  '\nglobalThis.harness = { makeWorld, flush, lastFetch, fetchBody };', box);
const { makeWorld, flush, lastFetch, fetchBody } = box.harness;

async function networkFailure() {
  const w = makeWorld();
  w.userInput._val = 'keep this message';
  w.APP_DATA.autoplayTTS = false;
  w.window.voiceModeActive = true;
  vm.runInContext('sendMessage()', w.ctx);
  await flush();
  lastFetch(w).reject(new TypeError('Failed to fetch'));
  await flush(150);
  assert.equal(w.fetchCalls.length, 1, 'network failure must not auto-resend even in voice mode');
  assert.match(w.paints[0], /connection to the server was lost/i, 'explain connection loss instead of Failed to fetch');
  assert.match(w.paints[0], /retry/i, 'explain the existing one-click retry');
  assert.match(w.paints[0], /refresh/i, 'explain recovery if retry fails');
  assert.equal(w.userInput.val(), 'keep this message', 'draft is retained');
  // The existing local-only failed-turn action passes the original composed text.
  vm.runInContext('sendMessage({reuseLastUser: true, message: "keep this message"})', w.ctx);
  await flush();
  assert.equal(fetchBody(lastFetch(w)).message, 'keep this message');
}

async function exhausted429() {
  const w = makeWorld();
  w.userInput._val = 'busy draft';
  vm.runInContext('sendMessage()', w.ctx);
  for (let i = 0; i <= 12; i++) {
    await flush(150);
    lastFetch(w).resolve({status: 429, ok: false, text: async () => JSON.stringify({error: 'Generation already in progress. Please wait.'})});
  }
  await flush(150);
  assert.equal(w.fetchCalls.length, 13, 'initial request plus twelve retries actually ran');
  assert.equal(w.paints[0], 'Generation already in progress. Please wait.', 'surface exhausted 429 server error');
  assert.equal(w.userInput.val(), 'busy draft');
}

async function regenerateNetworkFailure() {
  const v = makeWorld();
  const errors = [];
  v.ctx.buildAiErrorChildren = (text) => { errors.push(text); return {}; };
  v.ctx.__ai = v.aiFake;
  vm.runInContext('performRegeneration(__ai, "original message", 0)', v.ctx);
  await flush();
  lastFetch(v).reject(new TypeError('Failed to fetch'));
  await flush(150);
  assert.match(errors[0], /connection to the server was lost/i);
  assert.equal(v.fetchCalls.length, 1);
}

(async () => {
  const failures = [];
  for (const fn of [networkFailure, exhausted429, regenerateNetworkFailure]) {
    try { await fn(); } catch (e) { failures.push(fn.name + ': ' + e.message); }
  }
  assert.equal(failures.length, 0, failures.join('\n'));
  console.error('generation recovery: 3 behavioral scenarios passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
