'use strict';
// Behavior contract for static/conversation-state.js: version rewind policy,
// retry-once decisions, stale fencing (sequence + generation), ghost routing,
// pagination window, exact payload shapes, and the three abort behaviors.
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node conversation_state_test.js <static/conversation-state.js>');
const C = require(modPath);

function freshIdentity(version, setId) {
  return { setVersion: version, lastSetId: setId };
}

// Reads advance only; mutations/409 rewind.
{
  const s = freshIdentity(5, 'a');
  const r = C.applySetVersionTo(s, 3, 'a', {});
  assert.equal(r.changed, false, 'read must not rewind below observed version');
  assert.equal(s.setVersion, 5);
  assert.equal(r.syncVersion, null);
}
{
  const s = freshIdentity(5, 'a');
  const r = C.applySetVersionTo(s, 3, 'a', { allowRewind: true });
  assert.equal(r.changed, true, 'authoritative mutation/409 may rewind');
  assert.equal(s.setVersion, 3);
  assert.equal(r.syncVersion, 3);
}
{
  const s = freshIdentity(5, 'a');
  const r = C.applySetVersionTo(s, 1, 'b', {});
  assert.equal(s.lastSetId, 'b', 'set switch adopts the new set');
  assert.equal(s.setVersion, 1);
  assert.equal(r.switchedSet, true);
  assert.equal(r.syncVersion, 1);
}
{
  const s = freshIdentity(5, 'a');
  const r = C.applySetVersionTo(s, '', 'b', {});
  assert.equal(s.lastSetId, 'b');
  assert.equal(s.setVersion, 5, 'switch without version keeps observed version');
  assert.equal(r.syncVersion, null);
}
{
  const s = freshIdentity(5, 'a');
  const r = C.applySetVersionTo(s, 'not-a-number', 'a', { allowRewind: true });
  assert.equal(r.changed, false, 'non-numeric versions never apply');
  assert.equal(s.setVersion, 5);
}
{
  const s = freshIdentity(5, 'a');
  C.noteSetVersionFromReadTo(s, { version: 2, set_id: 'a' });
  assert.equal(s.setVersion, 5, 'stale-low read snapshot must not rewind');
  C.noteSetVersionFromResponseTo(s, { current_version: 2, set_id: 'a' });
  assert.equal(s.setVersion, 2, 'authoritative response adopts current_version');
}
{
  const s = freshIdentity(7, 'a');
  const r = C.noteLocalVersionBumpAfterPersistTo(s);
  assert.equal(s.setVersion, 8, 'persist advances by one so delete/reset do not race refresh');
  assert.equal(r.syncVersion, 8);
  const empty = freshIdentity(null, 'a');
  const r2 = C.noteLocalVersionBumpAfterPersistTo(empty);
  assert.equal(r2.changed, false, 'no version yet: nothing to bump');
}

// Exact payload shape.
{
  const p = C.buildActiveSetPayload({ setName: 'Work', setId: 'id-1', setVersion: '4' }, { message: 'hi' });
  assert.deepEqual(p, { message: 'hi', set_name: 'Work', set_id: 'id-1', expected_version: 4 });
  const guest = C.buildActiveSetPayload({ setName: '', setId: '', setVersion: '' }, {});
  assert.deepEqual(guest, { set_name: 'default' }, 'guest payload omits id/version');
  const nov = C.buildActiveSetPayload({ setName: 'd', setId: 'x', setVersion: null }, {});
  assert.equal('expected_version' in nov, false, 'missing version omits expected_version');
}

// Retry-once decision used by every version_conflict path.
{
  assert.equal(C.shouldRetryVersionOnce(false), true);
  assert.equal(C.shouldRetryVersionOnce(true), false);
}

// Ghost routing.
{
  assert.equal(C.isGhostTurn({ attrLocalOnly: '1', computedLocalOnly: false }), true);
  assert.equal(C.isGhostTurn({ attrLocalOnly: '0', computedLocalOnly: true }), true);
  assert.equal(C.isGhostTurn({ attrLocalOnly: '0', computedLocalOnly: false }), false);
  assert.equal(C.resolveRegenerateAction(true), 'resend-chat');
  assert.equal(C.resolveRegenerateAction(false), 'regenerate');
  assert.equal(C.canForkTurn(true), false);
  assert.equal(C.canForkTurn(false), true);
  assert.equal(C.userPairIndexForDomIndex(10, 3), 13);
}

// History window + generation fencing, through the production path.
{
  const w = C.createHistoryWindow(40);
  assert.equal(w.getPageSize(), 40);
  const page = w.applyPage({ history: [['u', 'a'], ['u2', 'a2']], history_start: 8, history_total: 10, has_more: true }, 'replace');
  assert.equal(page.start, 8);
  assert.equal(w.getOffset(), 8);
  assert.equal(w.snapshot().total, 10);
  assert.equal(w.snapshot().hasMore, true);
  const req = w.beginOlderLoad({ setId: 's', setName: 'n' });
  assert.deepEqual(req, { before: 8, gen: 0, setId: 's', setName: 'n', limit: 40 });
  assert.equal(w.snapshot().loadingOlder, true);
  assert.equal(w.beginOlderLoad({}), null, 'concurrent older loads fence');
  assert.equal(w.isLiveGen(999), false, 'stale generation stays silent');
  assert.equal(w.snapshot().loadingOlder, true, 'stale response must not clear loading by itself');
  w.noteOlderSettled();
  assert.equal(w.snapshot().loadingOlder, false);
  // Live prepend after a fresh begin, as loadOlderMessages does.
  const req2 = w.beginOlderLoad({ setId: 's', setName: 'n' });
  assert.equal(w.isLiveGen(req2.gen), true);
  w.applyPage({ history: [['o', 'a']], history_start: 7, history_total: 10, has_more: false }, 'prepend');
  assert.equal(w.getOffset(), 7);
  assert.equal(w.snapshot().hasMore, false);
  w.noteOlderSettled();
  // Set switch invalidates.
  const gen = w.beginSetLoad();
  assert.equal(w.isLiveGen(gen), true);
  assert.equal(w.isLiveGen(req2.gen), false);
  // Persist accounting.
  w.applyPage({ history: [['a', 'b']], history_start: 0, history_total: 1, has_more: false }, 'replace');
  w.noteChatPersisted(0);
  assert.equal(w.snapshot().total, 1);
  w.noteDeletedPersisted();
  assert.equal(w.snapshot().total, 0);
  w.noteDeletedPersisted();
  assert.equal(w.snapshot().total, 0, 'total never goes negative');
  w.reset();
  assert.deepEqual(w.snapshot(), { offset: 0, total: 0, hasMore: false, loadingOlder: false, setGen: gen, pageSize: 40 });
}

// Request tracker: stale fencing + three abort behaviors.
{
  let aborts = 0;
  const mk = () => ({ signal: { aborted: false }, abort() { aborts++; this.signal.aborted = true; } });
  const t = C.createChatRequestTracker(mk);
  const s1 = t.begin();
  assert.equal(t.isGenerating(), true);
  assert.equal(t.isLive(s1), true);
  const s2 = t.begin();
  assert.equal(aborts, 1, 'begin aborts the prior request');
  assert.equal(t.isLive(s1), false, 'stale sequence never validates');
  assert.equal(t.isLive(s2), true);
  assert.equal(t.finish(s1), false, 'stale finish must not clear the live controller');
  assert.equal(t.isGenerating(), true);
  assert.equal(t.finish(s2), true);
  assert.equal(t.isGenerating(), false);
}
{
  let aborts = 0;
  const mk = () => ({ signal: {}, abort() { aborts++; } });
  const t = C.createChatRequestTracker(mk);
  const s1 = t.begin();
  t.abortQuietly();
  assert.equal(t.isLive(s1), false, 'quiet replace silences the aborted /chat');
  assert.equal(aborts, 1);
  assert.equal(t.isGenerating(), false);
}
{
  let aborts = 0;
  const mk = () => ({ signal: {}, abort() { aborts++; } });
  const t = C.createChatRequestTracker(mk);
  const s1 = t.begin();
  t.stopForUser();
  assert.equal(t.isLive(s1), true, 'user stop keeps the sequence so AbortError paints [Stopped]');
  assert.equal(aborts, 1);
  assert.equal(t.isGenerating(), false);
}
{
  let aborts = 0;
  const mk = () => ({ signal: {}, abort() { aborts++; } });
  const t = C.createChatRequestTracker(mk);
  t.begin();
  assert.equal(t.interruptForVoiceTurn(), true, 'voice interrupt reports active generation');
  assert.equal(aborts, 1);
  assert.equal(t.isGenerating(), false);
  // Idle interrupt bumps nothing and stays live: the original only touched
  // the sequence inside the active-controller branch.
  let created = 0;
  const idle = C.createChatRequestTracker(() => { created++; return { signal: {}, abort() {} }; });
  const idleSeq = idle.seq();
  assert.equal(idle.interruptForVoiceTurn(), false, 'idle interrupt reports nothing to finalize');
  assert.equal(idle.seq(), idleSeq, 'idle interrupt must not bump the sequence');
  assert.equal(idle.isLive(idleSeq), true);
  assert.equal(created, 0, 'idle interrupt must not create a controller');
}

// Abort-throw parity: begin/quiet swallow like the original try/catch;
// user stop and voice interrupt let it throw with nothing yet cleared.
{
  const throwing = () => ({ signal: {}, abort() { throw new Error('abort boom'); } });
  const t = C.createChatRequestTracker(throwing);
  t.begin();
  t.begin();
  assert.equal(t.isGenerating(), true, 'begin swallows a throwing abort and owns the new signal');
  t.abortQuietly();
  assert.equal(t.isGenerating(), false, 'quiet replace swallows a throwing abort');
  const t2 = C.createChatRequestTracker(throwing);
  t2.begin();
  const s2 = t2.seq();
  assert.throws(() => t2.stopForUser(), /abort boom/);
  assert.equal(t2.isGenerating(), true, 'thrown user-stop abort leaves the controller owned');
  assert.equal(t2.isLive(s2), true);
  const t3 = C.createChatRequestTracker(throwing);
  t3.begin();
  const s3 = t3.seq();
  assert.throws(() => t3.interruptForVoiceTurn(), /abort boom/);
  assert.equal(t3.seq(), s3, 'thrown voice-interrupt abort must not bump the sequence');
  assert.equal(t3.isGenerating(), true, 'thrown voice-interrupt abort leaves the controller owned');
}

console.error('conversation-state: version/retry/fencing/ghost/pagination/abort contract holds');
