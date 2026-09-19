'use strict';
// Behavior contract for static/voice-events.js: ONE central idempotence gate
// for native voice-mode transitions delivered twice (owned Capacitor listener
// plus the evalJs fallback). Pause, resume and stop share a single monotonic
// coordinator transition ID; only strictly newer IDs apply, so duplicate
// deliveries collapse and a reordered stale event can never invalidate a
// newer session. Unsequenced legacy deliveries (no ID) still apply once.
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node voice_events_test.js <static/voice-events.js>');
const E = require(modPath);

assert.equal(typeof E.createTransitionGate, 'function', 'unit exposes createTransitionGate');

// First numeric ID applies and is tracked.
{
  const gate = E.createTransitionGate();
  assert.equal(gate.claim(1), true, 'first pause ID applies');
  assert.equal(gate.lastId(), 1, 'gate tracks the consumed ID');
}

// Duplicate pause delivery collapses to one transition.
{
  const gate = E.createTransitionGate();
  let applied = 0;
  if (gate.claim(1)) applied++;
  if (gate.claim(1)) applied++;
  assert.equal(applied, 1, 'duplicate pause ID applies exactly once');
  assert.equal(gate.lastId(), 1, 'duplicate does not advance the gate');
}

// Reordered stale pause after resume is rejected.
{
  const gate = E.createTransitionGate();
  assert.equal(gate.claim(1), true, 'pause ID 1 applies');
  assert.equal(gate.claim(2), true, 'resume ID 2 applies');
  assert.equal(gate.claim(1), false, 'delayed stale pause ID 1 must not invalidate the resume');
  assert.equal(gate.lastId(), 2, 'stale delivery does not move the gate');
}

// Full pause/resume/stop dispatcher: one owner per logical event.
{
  const gate = E.createTransitionGate();
  const applied = { pause: 0, resume: 0, stop: 0 };
  function onPause(id) { if (gate.claim(id)) applied.pause++; }
  function onResume(id) { if (gate.claim(id)) applied.resume++; }
  function onStop(id) { if (gate.claim(id)) applied.stop++; }

  onPause(1);
  onPause(1);
  onResume(2);
  onResume(2);
  onPause(1);
  onStop(3);
  onStop(3);
  onResume(2);
  onPause(4);

  assert.deepEqual(applied, { pause: 2, resume: 1, stop: 1 },
    'pause/resume/stop each apply once; only the newer pause 4 follows the stop');
  assert.equal(gate.lastId(), 4, 'gate ends on the newest consumed ID');
}

// A stop consumed once never re-applies, even before older stragglers.
{
  const gate = E.createTransitionGate();
  assert.equal(gate.claim(5), true, 'stop ID 5 applies');
  assert.equal(gate.claim(5), false, 'duplicate stop collapses');
  assert.equal(gate.claim(4), false, 'older straggler after stop is rejected');
}

// Unsequenced legacy deliveries still apply without poisoning numeric gating.
{
  const gate = E.createTransitionGate();
  assert.equal(gate.claim(undefined), true, 'legacy pause without ID applies');
  assert.equal(gate.claim(null), true, 'legacy resume without ID applies');
  assert.equal(gate.lastId(), -1, 'legacy deliveries do not consume numeric IDs');
  assert.equal(gate.claim(1), true, 'numeric gating still starts clean');
  assert.equal(gate.claim(1), false, 'numeric duplicates still collapse');
}

// Independent gates do not share consumed state.
{
  const a = E.createTransitionGate();
  const b = E.createTransitionGate();
  assert.equal(a.claim(1), true, 'first gate consumes ID 1');
  assert.equal(b.claim(1), true, 'second gate is independent');
  assert.equal(a.claim(1), false, 'first gate still rejects the duplicate');
}

console.log('voice-events gate: all 8 behaviors passed');
