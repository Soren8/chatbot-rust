'use strict';
// MOD-009-A regression: conversation-bound requests.
// Exercises the REAL owned state (static/conversation-state.js) composed as
// production adapters use it: tracker sequence + history-window generation +
// initiating set identity through payload retention and response application.
// No algorithm copies: every decision goes through the shared unit.
// No source spelling: assertions are behavioral (drops vs applies).
//
// Required scenarios:
// - delayed chat headers/chunks/completion after A->B drop; same-set applies.
// - replacement regeneration: stale seq callbacks drop, replacement applies.
// - memory/system-prompt retry across A->B retains the initiating target and
//   does not sync the stale version into the live selection; same-set retry
//   applies with the authoritative version.
// - valid same-set completion/retry (logged-in + guest).
// - pagination settlement stays generation-fenced (traced, no refactor).
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node conversation_request_binding_test.js <static/conversation-state.js>');
const C = require(modPath);

for (const api of [
  'captureConversationBinding',
  'isLiveConversationBinding',
  'captureSetBinding',
  'isLiveSetBinding',
  'snapshotSetIdentity',
  'shouldApplySetResponseForBinding',
  'shouldApplySetResponseForSetBinding',
  'buildActiveSetPayload',
  'shouldRetryVersionOnce',
  'createHistoryWindow',
  'createChatRequestTracker',
  'noteSetVersionFromResponseTo',
]) {
  assert.equal(typeof C[api], 'function', 'shared unit must own ' + api);
}

function noopController() {
  return { signal: {}, abort() {} };
}

// Delayed chat headers/chunks/completion after A->B must drop.
{
  const w = C.createHistoryWindow(40);
  const t = C.createChatRequestTracker(noopController);
  const seqA = t.begin();
  const genA = w.snapshot().setGen;
  const bindingA = C.captureConversationBinding(seqA, 'set-A', genA);
  const payloadA = C.buildActiveSetPayload({ setName: 'A', setId: 'set-A', setVersion: 5 }, { message: 'hello A' });
  assert.deepEqual(payloadA, { message: 'hello A', set_name: 'A', set_id: 'set-A', expected_version: 5 });

  // Switch to B bumps generation but leaves the tracker sequence live.
  w.beginSetLoad();
  const currentB = 'set-B';
  assert.equal(t.isLive(seqA), true, 'controller currency alone stays true after a set switch');
  assert.equal(w.isLiveGen(genA), false, 'history generation invalidates the in-flight page');
  assert.equal(
    C.isLiveConversationBinding(bindingA, t.isLive(seqA), w.isLiveGen(genA), currentB),
    false,
    'delayed headers must not render into B'
  );
  assert.equal(
    C.isLiveConversationBinding(bindingA, t.isLive(seqA), w.isLiveGen(genA), currentB),
    false,
    'delayed chunks must not append into B'
  );
  assert.equal(
    C.shouldApplySetResponseForBinding(bindingA, { set_id: 'set-A', version: 6 }, t.isLive(seqA), w.isLiveGen(genA), currentB),
    false,
    'stale completion must not bump B accounting/version'
  );

  // Same-set control stays live.
  const seqB = t.begin();
  const genB = w.snapshot().setGen;
  const bindingB = C.captureConversationBinding(seqB, 'set-B', genB);
  assert.equal(
    C.isLiveConversationBinding(bindingB, t.isLive(seqB), w.isLiveGen(genB), 'set-B'),
    true,
    'valid same-set headers/chunks must apply'
  );
  assert.equal(
    C.shouldApplySetResponseForBinding(bindingB, { set_id: 'set-B', version: 4 }, t.isLive(seqB), w.isLiveGen(genB), 'set-B'),
    true,
    'valid same-set completion must apply'
  );
}

// Replacement regeneration: stale sequence callbacks drop.
{
  const w = C.createHistoryWindow(40);
  const t = C.createChatRequestTracker(noopController);
  const gen = w.snapshot().setGen;
  const seq1 = t.begin();
  const stale = C.captureConversationBinding(seq1, 'set-A', gen);
  const seq2 = t.begin();
  const live = C.captureConversationBinding(seq2, 'set-A', w.snapshot().setGen);
  assert.equal(t.isLive(seq1), false, 'replacement invalidates the prior sequence');
  assert.equal(t.isLive(seq2), true);
  assert.equal(
    C.isLiveConversationBinding(stale, t.isLive(seq1), w.isLiveGen(stale.setGen), 'set-A'),
    false,
    'stale regenerate chunks/completion must not clobber the replacement'
  );
  assert.equal(
    C.isLiveConversationBinding(live, t.isLive(seq2), w.isLiveGen(live.setGen), 'set-A'),
    true,
    'replacement regenerate must apply'
  );
  assert.equal(
    C.shouldApplySetResponseForBinding(stale, { set_id: 'set-A', version: 7 }, t.isLive(seq1), w.isLiveGen(stale.setGen), 'set-A'),
    false,
    'stale regenerate completion must not bump version'
  );
}

// Memory/system-prompt retry across A->B retains the initiating target.
{
  const w = C.createHistoryWindow(40);
  const genA = w.snapshot().setGen;
  const snapA = C.snapshotSetIdentity({ setName: 'A', setId: 'set-A', setVersion: 5 });
  assert.deepEqual(snapA, { setName: 'A', setId: 'set-A', setVersion: 5 });

  // Retry rebuilds from the snapshot, never the live selection.
  const retryBody = C.buildActiveSetPayload(snapA, { memory: 'A-memory' });
  assert.deepEqual(
    retryBody,
    { memory: 'A-memory', set_name: 'A', set_id: 'set-A', expected_version: 5 },
    '401 retry must resend A-memory against A, not B'
  );
  const promptBody = C.buildActiveSetPayload(snapA, { system_prompt: 'A-prompt' });
  assert.equal(promptBody.set_id, 'set-A', 'system-prompt retry keeps the initiating set');

  const memBinding = C.captureSetBinding(snapA.setId, genA);
  w.beginSetLoad();
  assert.equal(
    C.isLiveSetBinding(memBinding, w.isLiveGen(memBinding.setGen), 'set-B'),
    false,
    'stale memory success must not sync into B'
  );
  assert.equal(
    C.shouldApplySetResponseForSetBinding(memBinding, { set_id: 'set-A', version: 6 }, w.isLiveGen(memBinding.setGen), 'set-B'),
    false,
    'stale memory version must not rewind/adopt into B'
  );

  // Same-set retry applies with the authoritative version.
  const w2 = C.createHistoryWindow(40);
  const genLive = w2.snapshot().setGen;
  const liveBinding = C.captureSetBinding('set-A', genLive);
  assert.equal(C.isLiveSetBinding(liveBinding, w2.isLiveGen(genLive), 'set-A'), true);
  assert.equal(
    C.shouldApplySetResponseForSetBinding(liveBinding, { set_id: 'set-A', version: 6 }, w2.isLiveGen(genLive), 'set-A'),
    true,
    'valid same-set memory retry must sync the authoritative version'
  );
  const state = { setVersion: 5, lastSetId: 'set-A' };
  C.noteSetVersionFromResponseTo(state, { current_version: 6, set_id: 'set-A' });
  assert.equal(state.setVersion, 6, 'authoritative 409 version adopts');
  assert.equal(C.shouldRetryVersionOnce(false), true, 'version conflict retries once');
  assert.equal(C.shouldRetryVersionOnce(true), false);
  const refreshed = C.buildActiveSetPayload(
    C.snapshotSetIdentity({ setName: 'A', setId: 'set-A', setVersion: state.setVersion }),
    { memory: 'A-memory' }
  );
  assert.equal(refreshed.expected_version, 6, 'retry uses the fresh authoritative version on the same set');
}

// Valid same-set completion/retry for guests (no set id).
{
  const w = C.createHistoryWindow(40);
  const t = C.createChatRequestTracker(noopController);
  const guestSnap = C.snapshotSetIdentity({ setName: '', setId: '', setVersion: '' });
  assert.deepEqual(C.buildActiveSetPayload(guestSnap, { message: 'hi' }), { message: 'hi', set_name: 'default' });
  const seq = t.begin();
  const gen = w.snapshot().setGen;
  const guestBinding = C.captureConversationBinding(seq, null, gen);
  assert.equal(
    C.isLiveConversationBinding(guestBinding, t.isLive(seq), w.isLiveGen(gen), null),
    true,
    'guest same-view completion must apply'
  );
  const guestMem = C.captureSetBinding(null, gen);
  assert.equal(C.isLiveSetBinding(guestMem, w.isLiveGen(gen), null), true, 'guest memory save must apply');
  assert.equal(C.isLiveSetBinding(guestMem, w.isLiveGen(gen), 'set-B'), false, 'guest binding must not apply into a named set');
}

// Pagination settlement stays generation-fenced (traced, no refactor).
{
  const w = C.createHistoryWindow(40);
  w.applyPage({ history: [['u', 'a']], history_start: 8, history_total: 10, has_more: true }, 'replace');
  const req = w.beginOlderLoad({ setId: 'set-A', setName: 'A' });
  assert.deepEqual(req, { before: 8, gen: 0, setId: 'set-A', setName: 'A', limit: 40 });
  w.beginSetLoad();
  assert.equal(w.isLiveGen(req.gen), false, 'stale older page must drop after a set switch');
  w.noteOlderSettled();
  const liveReq = w.beginOlderLoad({ setId: 'set-B', setName: 'B' });
  assert.equal(w.isLiveGen(liveReq.gen), true, 'live older page settles');
  w.noteOlderSettled();
}

console.error('conversation-request-binding: initiating identity/generation fences all application');
