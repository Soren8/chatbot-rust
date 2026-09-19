(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatVoiceEvents = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Central idempotence gate for native voice-mode transitions. Phone
  // pause/resume and notification stop each arrive twice (owned Capacitor
  // listener plus the evalJs fallback) carrying one monotonic coordinator
  // transition ID shared across the page lifetime. Only strictly newer IDs
  // apply: duplicate deliveries collapse and a reordered stale event can
  // never invalidate a newer session. Unsequenced legacy calls (no ID, e.g.
  // UI-initiated stops) still apply without consuming numeric IDs.

  function createTransitionGate() {
    var lastConsumedId = -1;

    function claim(id) {
      if (id === undefined || id === null) {
        return true;
      }
      var n = (typeof id === 'number') ? id : Number(id);
      if (!isFinite(n)) {
        return true;
      }
      if (n <= lastConsumedId) {
        return false;
      }
      lastConsumedId = n;
      return true;
    }

    function lastId() {
      return lastConsumedId;
    }

    return { claim: claim, lastId: lastId };
  }

  return { createTransitionGate: createTransitionGate };
}));
