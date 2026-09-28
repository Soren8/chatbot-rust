'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const events = [];
const notice = {
  length: 1,
  text(value) { events.push(['text', value]); return this; },
  removeClass(value) { events.push(['remove', value]); return this; },
  addClass(value) { events.push(['add', value]); return this; }
};
const info = [];
const context = {
  $: function (selector) {
    if (typeof selector === 'function') return; // Skip page-ready side effects.
    assert.equal(selector, '#login-notice');
    return notice;
  },
  console: { info: value => info.push(value) }
};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);

context.showLoginNotice('<notice>');
assert.deepEqual(events, [
  ['text', '<notice>'], ['remove', 'd-none alert-danger'], ['add', 'alert-warning']
]);
events.length = 0;
context.showLoginError('<error>');
assert.deepEqual(events, [
  ['text', '<error>'], ['remove', 'd-none alert-warning'], ['add', 'alert-danger']
]);
notice.length = 0;
context.showLoginNotice('missing warning');
context.showLoginError('missing error');
assert.deepEqual(info, ['missing warning', 'missing error']);

const tts = require(process.argv[3]);
async function runQueue(kind, voiceMode) {
  const scheduled = [];
  const failures = [];
  const output = [];
  const deps = {
    isLive: () => true,
    isVoiceModeActive: () => voiceMode,
    preload: () => {},
    playOne: () => { failures.push('attempt'); return Promise.resolve(false); },
    setTimeout: (fn, ms) => { scheduled.push({ fn, ms }); return scheduled.length; },
    clearTimeout: () => {},
    onComplete: () => output.push('complete'),
    reportVoice: () => {},
    appendMessage: () => output.push('error'),
    logError: () => {},
    split: () => [{ text: 'Hello.', start: 0, end: 6 }],
    terminator: () => true,
    source: { getText: () => 'Hello.', isGenerating: () => false, subscribe: () => () => {} }
  };
  const handle = kind === 'fixed'
    ? tts.playFixedSentenceList(deps, 1, {}, ['Hello.'])
    : tts.playMessageBodyTts(deps, 1, {});
  async function flush() { await Promise.resolve(); await Promise.resolve(); }
  await flush();
  for (let index = 0; index < (voiceMode ? 9 : 3); index++) {
    assert.equal(scheduled[index].ms, Math.min(400 * (index + 1), voiceMode ? 3000 : Infinity),
      `${kind} voiceMode=${voiceMode} retry ${index + 1}`);
    scheduled[index].fn();
    await flush();
  }
  if (!voiceMode) {
    assert.equal(failures.length, 4);
    assert.deepEqual(output, ['error', 'complete']);
  } else {
    assert.equal(failures.length, 10);
    assert.deepEqual(output, []);
  }
  handle.cancel();
}

(async () => {
  await runQueue('fixed', false);
  await runQueue('stream', false);
  await runQueue('fixed', true);
  await runQueue('stream', true);
})().catch(err => { console.error(err); process.exitCode = 1; });
