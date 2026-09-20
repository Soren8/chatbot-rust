(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatConversationState = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Owned conversation/request/history-window state. Reads advance only;
  // mutations and 409 bodies are authoritative (allowRewind).

  var HISTORY_PAGE_SIZE = 40;

  // List refreshes must not rewind (an in-flight list after delete can be
  // stale). window.APP_DATA stays the single store; the result tells the
  // caller whether to sync the selected option (DOM callback in chat.js).
  function applySetVersionTo(state, version, setId, options) {
    if (!state || typeof state !== 'object') state = {};
    var allowRewind = !!(options && options.allowRewind);
    if (setId) {
      if (state.lastSetId && setId !== state.lastSetId) {
        state.lastSetId = setId;
        if (version != null && version !== '') {
          var switched = Number(version);
          if (!Number.isNaN(switched)) {
            state.setVersion = switched;
            return { changed: true, syncVersion: switched, switchedSet: true };
          }
        }
        return { changed: true, syncVersion: null, switchedSet: true };
      }
      state.lastSetId = setId;
    }
    if (version == null || version === '') {
      return { changed: false, syncVersion: null, switchedSet: false };
    }
    var next = Number(version);
    if (Number.isNaN(next)) return { changed: false, syncVersion: null, switchedSet: false };
    var current = Number(state.setVersion);
    if (!allowRewind && !Number.isNaN(current) && next < current) {
      return { changed: false, syncVersion: null, switchedSet: false };
    }
    state.setVersion = next;
    return { changed: true, syncVersion: next, switchedSet: false };
  }

  function noteSetVersionFromResponseTo(state, data) {
    if (!data) return { changed: false, syncVersion: null, switchedSet: false };
    var version = data.version != null ? data.version : data.current_version;
    return applySetVersionTo(state, version, data.set_id, { allowRewind: true });
  }

  // Advance only: a concurrent write may make the read snapshot stale-low.
  function noteSetVersionFromReadTo(state, data) {
    if (!data) return { changed: false, syncVersion: null, switchedSet: false };
    var version = data.version != null ? data.version : data.current_version;
    return applySetVersionTo(state, version, data.set_id);
  }

  // After persist the CAS version advances by one, so delete/reset do not
  // race the async loadSets() refresh.
  function noteLocalVersionBumpAfterPersistTo(state) {
    if (!state) return { changed: false, syncVersion: null, switchedSet: false };
    if (state.setVersion == null || state.setVersion === '') {
      return { changed: false, syncVersion: null, switchedSet: false };
    }
    var next = Number(state.setVersion) + 1;
    if (Number.isNaN(next)) return { changed: false, syncVersion: null, switchedSet: false };
    return applySetVersionTo(state, next, state.lastSetId);
  }

  // Exact set-identity payload shared by every mutating request.
  function buildActiveSetPayload(identity, extra) {
    var id = identity || {};
    var payload = Object.assign({}, extra || {});
    payload.set_name = id.setName || 'default';
    if (id.setId) payload.set_id = id.setId;
    if (id.setVersion != null && id.setVersion !== '') {
      payload.expected_version = Number(id.setVersion);
    }
    return payload;
  }

  function shouldRetryVersionOnce(alreadyRetried) {
    return !alreadyRetried;
  }

  // Ghost (never-saved, local-only) routing. DOM reads stay in chat.js.
  function isGhostTurn(flags) {
    var f = flags || {};
    return f.attrLocalOnly === '1' || !!f.computedLocalOnly;
  }

  function resolveRegenerateAction(isGhost) {
    return isGhost ? 'resend-chat' : 'regenerate';
  }

  function canForkTurn(isGhost) {
    return !isGhost;
  }

  // Live DOM order is the source of truth after local deletes.
  function userPairIndexForDomIndex(offset, domIndex) {
    return Number(offset || 0) + Number(domIndex || 0);
  }

  function createHistoryWindow(pageSize) {
    var size = pageSize || HISTORY_PAGE_SIZE;
    var offset = 0;
    var total = 0;
    var hasMore = false;
    var loadingOlder = false;
    var setGen = 0;

    function snapshot() {
      return {
        offset: offset,
        total: total,
        hasMore: hasMore,
        loadingOlder: loadingOlder,
        setGen: setGen,
        pageSize: size
      };
    }

    function reset() {
      offset = 0;
      total = 0;
      hasMore = false;
      loadingOlder = false;
    }

    function pageStart(data) {
      var start = data && data.history_start != null ? Number(data.history_start) : 0;
      if (Number.isNaN(start)) start = 0;
      return start;
    }

    function pagePairs(data) {
      return (data && data.history) ? data.history : [];
    }

    // Rendering stays in chat.js; this returns the page to render.
    function applyPage(data, mode) {
      var pairs = pagePairs(data);
      var start = pageStart(data);
      total = data && data.history_total != null ? Number(data.history_total) : pairs.length;
      hasMore = !!(data && data.has_more);
      offset = start;
      return { start: start, pairs: pairs, total: total, hasMore: hasMore, offset: offset, mode: mode || 'replace' };
    }

    // A set switch abandons the in-flight page and its loading flag; the
    // stale settlement below must not clear a newer load.
    function beginSetLoad() {
      setGen += 1;
      loadingOlder = false;
      return setGen;
    }

    function isLiveGen(gen) {
      return gen === setGen;
    }

    // At most one older-page request, paged before the current offset.
    // Returns the request descriptor or null; marks loading when eligible.
    function beginOlderLoad(identity) {
      if (!hasMore || loadingOlder || offset <= 0) return null;
      loadingOlder = true;
      var id = identity || {};
      return { before: offset, gen: setGen, setId: id.setId, setName: id.setName, limit: size };
    }

    function noteOlderSettled(gen) {
      if (gen !== undefined && gen !== setGen) return;
      loadingOlder = false;
    }

    function noteDeletedPersisted() {
      if (total > 0) total -= 1;
    }

    function noteChatPersisted(pairIndex) {
      total = Math.max(total, Number(pairIndex) + 1);
    }

    return {
      snapshot: snapshot,
      getPageSize: function () { return size; },
      getOffset: function () { return offset; },
      reset: reset,
      applyPage: applyPage,
      beginSetLoad: beginSetLoad,
      isLiveGen: isLiveGen,
      beginOlderLoad: beginOlderLoad,
      noteOlderSettled: noteOlderSettled,
      noteDeletedPersisted: noteDeletedPersisted,
      noteChatPersisted: noteChatPersisted
    };
  }

  // Request fencing plus the three abort behaviors. One instance owns the
  // sequence and the live AbortController.
  // - begin/quiet replace swallow a throwing abort; user stop and voice
  //   interrupt let it throw with nothing yet cleared, exactly like the
  //   original direct controller.abort() calls. Voice interrupt bumps the
  //   sequence only when generation was active.
  // Conversation-bound requests capture initiating set plus generation; a set
  // switch leaves the tracker sequence live, so application checks the
  // capture against the live selection, not the controller alone.
  function normalizeSetId(setId) {
    if (setId == null || setId === '') return null;
    return String(setId);
  }

  function captureConversationBinding(seq, setId, setGen) {
    return { seq: seq, setId: normalizeSetId(setId), setGen: setGen };
  }

  function isLiveConversationBinding(binding, isSeqLive, isGenLive, currentSetId) {
    if (!binding) return false;
    if (!isSeqLive) return false;
    if (!isGenLive) return false;
    return normalizeSetId(currentSetId) === normalizeSetId(binding.setId);
  }

  function captureSetBinding(setId, setGen) {
    return { setId: normalizeSetId(setId), setGen: setGen };
  }

  function isLiveSetBinding(binding, isGenLive, currentSetId) {
    if (!binding) return false;
    if (!isGenLive) return false;
    return normalizeSetId(currentSetId) === normalizeSetId(binding.setId);
  }

  // Retries reuse the initiating target, never the live selection.
  function snapshotSetIdentity(identity) {
    var id = identity || {};
    var snap = { setName: id.setName || 'default' };
    if (id.setId != null && id.setId !== '') snap.setId = id.setId;
    if (id.setVersion != null && id.setVersion !== '') snap.setVersion = id.setVersion;
    return snap;
  }

  function shouldApplySetResponseForBinding(binding, data, isSeqLive, isGenLive, currentSetId) {
    if (!isLiveConversationBinding(binding, isSeqLive, isGenLive, currentSetId)) return false;
    if (!data) return false;
    if (data.set_id != null && data.set_id !== '') {
      if (normalizeSetId(data.set_id) !== normalizeSetId(currentSetId)) return false;
      if (binding && normalizeSetId(data.set_id) !== normalizeSetId(binding.setId)) return false;
    }
    return true;
  }

  function shouldApplySetResponseForSetBinding(binding, data, isGenLive, currentSetId) {
    if (!isLiveSetBinding(binding, isGenLive, currentSetId)) return false;
    if (!data) return false;
    if (data.set_id != null && data.set_id !== '') {
      if (normalizeSetId(data.set_id) !== normalizeSetId(currentSetId)) return false;
      if (binding && normalizeSetId(data.set_id) !== normalizeSetId(binding.setId)) return false;
    }
    return true;
  }

  function createChatRequestTracker(createController) {
    var seq = 0;
    var controller = null;

    function makeController() {
      if (typeof createController === 'function') return createController();
      return new AbortController();
    }

    function abortCaught() {
      if (!controller) return;
      try { controller.abort(); } catch (e) { /* ignore */ }
    }

    return {
      seq: function () { return seq; },
      signal: function () { return controller ? controller.signal : null; },
      isGenerating: function () { return !!controller; },
      isLive: function (s) { return s === seq; },
      begin: function () {
        seq += 1;
        abortCaught();
        controller = makeController();
        return seq;
      },
      finish: function (s) {
        if (s !== seq) return false;
        controller = null;
        return true;
      },
      abortQuietly: function () {
        seq += 1;
        abortCaught();
        controller = null;
        return seq;
      },
      stopForUser: function () {
        if (!controller) return seq;
        controller.abort();
        controller = null;
        return seq;
      },
      interruptForVoiceTurn: function () {
        if (!controller) return false;
        controller.abort();
        controller = null;
        seq += 1;
        return true;
      }
    };
  }

  return {
    HISTORY_PAGE_SIZE: HISTORY_PAGE_SIZE,
    applySetVersionTo: applySetVersionTo,
    noteSetVersionFromResponseTo: noteSetVersionFromResponseTo,
    noteSetVersionFromReadTo: noteSetVersionFromReadTo,
    noteLocalVersionBumpAfterPersistTo: noteLocalVersionBumpAfterPersistTo,
    buildActiveSetPayload: buildActiveSetPayload,
    captureConversationBinding: captureConversationBinding,
    isLiveConversationBinding: isLiveConversationBinding,
    captureSetBinding: captureSetBinding,
    isLiveSetBinding: isLiveSetBinding,
    snapshotSetIdentity: snapshotSetIdentity,
    shouldApplySetResponseForBinding: shouldApplySetResponseForBinding,
    shouldApplySetResponseForSetBinding: shouldApplySetResponseForSetBinding,
    shouldRetryVersionOnce: shouldRetryVersionOnce,
    isGhostTurn: isGhostTurn,
    resolveRegenerateAction: resolveRegenerateAction,
    canForkTurn: canForkTurn,
    userPairIndexForDomIndex: userPairIndexForDomIndex,
    createHistoryWindow: createHistoryWindow,
    createChatRequestTracker: createChatRequestTracker
  };
}));
