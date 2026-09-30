'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
// Transport loss/replay is exercised by activity_sync_test.js. This composed
// renderer test covers terminal durable admission errors and retained drafts.
const source = fs.readFileSync(path.join(__dirname, 'conversation_request_application_test.js'), 'utf8');
const box = { require, process, console, TextDecoder, TextEncoder };
vm.runInNewContext(source.slice(0, source.indexOf('(async () => {')) +
  '\nglobalThis.harness = { makeWorld, flush, lastFetch, fetchBody };', box);
const { makeWorld, flush, lastFetch, fetchBody } = box.harness;

async function rejectedAdmission() {
  const w = makeWorld();
  w.userInput._val = 'busy draft';
  vm.runInContext('sendMessage()', w.ctx);
  await flush();
  lastFetch(w).resolve({ status: 429, ok: false, text: async () => JSON.stringify({ error: 'Rate limit exceeded.' }) });
  await flush(150);
  assert.equal(w.fetchCalls.length, 1, 'true rate limits are not generate-lock retries');
  assert.equal(w.paints[0], 'Rate limit exceeded.');
  assert.equal(w.userInput.val(), 'busy draft');
  vm.runInContext('sendMessage({reuseLastUser: true, message: "busy draft"})', w.ctx);
  await flush();
  assert.equal(fetchBody(lastFetch(w)).message, 'busy draft');
}

async function regenerateRejectedAdmission() {
  const w = makeWorld();
  const errors = [];
  w.ctx.buildAiErrorChildren = text => { errors.push(text); return {}; };
  w.ctx.__ai = w.aiFake;
  vm.runInContext('performRegeneration(__ai, "original message", 0)', w.ctx);
  await flush();
  lastFetch(w).resolve({ status: 403, ok: false, text: async () => JSON.stringify({ error: 'Model unavailable.' }) });
  await flush(150);
  assert.equal(errors[0], 'Model unavailable.');
  assert.equal(w.fetchCalls.length, 1);
}

(async () => {
  await rejectedAdmission();
  await regenerateRejectedAdmission();
  console.error('generation recovery: 2 behavioral scenarios passed');
})().catch(e => { console.error(e); process.exitCode = 1; });
