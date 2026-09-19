(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatPlaybackSource = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Per-message TTS playback source: answer text plus generation progress
  // for one AI message, shared by the desktop and native queues.
  //
  // Text arrives via publish() from the sites that render it; progress is
  // the bound request-tracker sequence plus an explicit finished flag.
  // isGenerating() holds only while unfinished, bound, current, and
  // generating. retarget() restarts sequence, text, and finished flag
  // atomically with a single notify. projectSpeakableText() strips think
  // blocks, falls back to visible text, sanitizes, and silences
  // Thinking.../Error placeholders. No DOM access.

  function projectSpeakableText(original, fallbackVisible, sanitize) {
    var full = original || '';
    if (full) {
      full = String(full).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    }
    if (!full) {
      full = String(fallbackVisible || '').trim();
    }
    full = sanitize(full);
    if (full === 'Thinking...') return '';
    if (/^\[Error\]/.test(full) || /^Error:/.test(full)) return '';
    return full;
  }

  function createMessageSource(deps) {
    deps = deps || {};
    var sanitize = deps.sanitize;
    var isTrackerGenerating = deps.isTrackerGenerating;
    var isTrackerLive = deps.isTrackerLive;

    var original = '';
    var fallbackVisible = '';
    var finished = false;
    var boundSeq = (deps.boundSeq != null) ? deps.boundSeq : null;
    var listeners = [];

    function getText() {
      return projectSpeakableText(original, fallbackVisible, sanitize);
    }

    // Event-fed progress: terminal once finished, otherwise live only while
    // the bound request sequence is still current and generating. A null
    // bound sequence (historical/settled messages) never reports generating,
    // so finished messages cannot stall on generation happening elsewhere.
    function isGenerating() {
      if (finished) return false;
      if (boundSeq == null) return false;
      if (typeof isTrackerLive === 'function' && !isTrackerLive(boundSeq)) return false;
      if (typeof isTrackerGenerating === 'function' && !isTrackerGenerating()) return false;
      return true;
    }

    function notify() {
      var pending = listeners.slice();
      for (var i = 0; i < pending.length; i++) {
        try { pending[i](); } catch (e) { /* ignore */ }
      }
    }

    function subscribe(listener) {
      if (typeof listener !== 'function') return null;
      listeners.push(listener);
      var active = true;
      return function () {
        if (!active) return;
        active = false;
        var idx = listeners.indexOf(listener);
        if (idx !== -1) listeners.splice(idx, 1);
      };
    }

    // Text event from a producing/updating site.
    function publish(next) {
      next = next || {};
      if (next.original !== undefined) original = next.original || '';
      if (next.fallbackVisible !== undefined) fallbackVisible = next.fallbackVisible || '';
      notify();
    }

    // Terminal progress event: done, cancelled, or failed. Text is kept so
    // already-queued sentences drain.
    function finish() {
      finished = true;
      notify();
    }

    // Restart for a replacement generation on the same message: rebind the
    // sequence, replace the text, and clear the terminal flag together, then
    // notify once. Subscribers never observe the old text on the new
    // sequence, and a fresh queue never completes before chunks arrive.
    function retarget(seq, text) {
      boundSeq = (seq != null) ? seq : null;
      text = text || {};
      original = text.original || '';
      fallbackVisible = text.fallbackVisible || '';
      finished = false;
      notify();
    }

    return {
      getText: getText,
      isGenerating: isGenerating,
      subscribe: subscribe,
      publish: publish,
      finish: finish,
      retarget: retarget
    };
  }

  return {
    projectSpeakableText: projectSpeakableText,
    createMessageSource: createMessageSource
  };
}));
