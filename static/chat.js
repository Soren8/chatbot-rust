// Configure onnxruntime-web WASM path (must run before vad initializes)
if (typeof ort !== 'undefined') {
  ort.env.wasm.wasmPaths = '/static/deps/vad/ort/';
}

// Native logging helper - logs to both browser console AND adb logcat
window.nativeLog = function(tag, msg) {
  console.log('[' + tag + ']', msg);
  if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Logger) {
    window.Capacitor.Plugins.Logger.log({ tag: tag, message: msg });
  }
};

// Ship uncaught JS errors to the Android app (ClientLogReporter -> server
// /client_logs) so field failures are visible in host logs, not only adb.
// Native side no-ops outside debug builds; web browsers have no Logger plugin.
function reportClientErrorToNative(kind, message) {
  try {
    if (!window.Capacitor || !window.Capacitor.nativePromise) return;
    window.Capacitor.nativePromise('Logger', 'report', {
      level: kind,
      message: String(message || '').slice(0, 4000)
    }).catch(function () {});
  } catch (e) { /* ignore */ }
}

// Voice-pipeline telemetry for field debugging (Android debug builds only).
// reportVoice() mirrors nativeLog(): always console, plus an async upload to
// the webserver's POST /client_logs via the Logger plugin. The native side
// no-ops outside debug builds and the server rate-limits + sanitizes, so:
// - call it on lifecycle/failure events, never per-audio-frame,
// - metadata only: counts, sizes, durations, status codes. Never transcripts,
//   audio bytes, cookies, tokens, or URLs.
function reportVoice(kind, message) {
  try {
    console.log('[VOICE-REPORT ' + kind + ']', message);
  } catch (e) { /* ignore */ }
  reportClientErrorToNative(kind, 'voice: ' + message);
}
// Throttled voice reports for hot paths (e.g. dropped PCM frames): at most
// one upload per window per key; quiet periods stay fully silent.
var _voiceReportThrottle = {};
function reportVoiceThrottled(key, windowMs, kind, message) {
  var now = Date.now();
  if (_voiceReportThrottle[key] && now - _voiceReportThrottle[key] < windowMs) return;
  _voiceReportThrottle[key] = now;
  reportVoice(kind, message);
}
// Explicit global: native-audio.js (loaded earlier, separate scope) forwards
// STT codec decisions here so compression engagement is visible server-side.
window.reportVoice = reportVoice;
window.addEventListener('error', function (event) {
  var where = event && event.filename ? ' @' + event.filename + ':' + (event.lineno || 0) : '';
  reportClientErrorToNative('ERROR', 'window.onerror: '
    + (event && event.message ? event.message : 'unknown') + where);
});
window.addEventListener('unhandledrejection', function (event) {
  var reason = event && event.reason
    ? (event.reason && event.reason.message ? event.reason.message : String(event.reason))
    : 'unknown';
  reportClientErrorToNative('ERROR', 'unhandledrejection: ' + reason);
});

function ttHtml(html) {
  if (html == null || typeof html !== 'string') {
    return html;
  }
  if (window.__chatbotTt && typeof window.__chatbotTt.createHTML === 'function') {
    return window.__chatbotTt.createHTML(html);
  }
  return html;
}
// ttHtml is only for direct element.innerHTML sinks (they accept TrustedHTML).
// Never feed ttHtml output into jQuery setters: jQuery 3.6.0's .html() treats
// TrustedHTML as a non-node object and empties the element instead of
// rendering it. jQuery/vendor .html(string) calls rely on the identity
// `default` Trusted-Types policy registered in static/tt.js.

// Message rendering lives in static/chat-renderer.js; chat keeps DOM/event
// composition and thin adapters here. Explicit deps only (no generic bag):
// document, marked/highlight.js, Trusted-Types wrapper, markdown flag,
// location and the shared stream decoder.
var chatRenderer = ChatRenderer.createChatRenderer({
  document: document,
  getMarked: function () { return (typeof marked !== 'undefined') ? marked : undefined; },
  getHljs: function () { return (typeof hljs !== 'undefined') ? hljs : undefined; },
  createTrustedHtml: ttHtml,
  isMarkdownEnabled: function () { return !(window.APP_DATA && window.APP_DATA.renderMarkdown === false); },
  getLocation: function () { return window.location; },
  getStreamDecoder: function () { return ChatStreamDecoder; }
});

// Ensure config exists before any DOM-ready handlers use it
try {
  if (!window.APP_DATA || typeof window.APP_DATA !== 'object') {
    const tpl = document.getElementById('app-data');
    if (tpl) {
      const rawText = (tpl.textContent || tpl.innerHTML || '').trim();
      console.debug('Raw app-data text:', rawText);
      const cfg = JSON.parse(rawText || '{}');
      console.debug('Parsed config object:', cfg);
      window.APP_DATA = {
        userTier: (cfg && cfg.userTier) || 'free',
        availableModels: (cfg && cfg.availableModels) || [],
        loggedIn: !!(cfg && cfg.loggedIn),
        username: (cfg && cfg.username) || null,
        saveThoughts: cfg && cfg.saveThoughts !== undefined ? cfg.saveThoughts : true,
        sendThoughts: cfg && cfg.sendThoughts !== undefined ? cfg.sendThoughts : false,
        renderMarkdown: cfg && cfg.renderMarkdown !== undefined ? cfg.renderMarkdown : true,
        autoplayTTS: cfg && cfg.autoplayTTS !== undefined ? cfg.autoplayTTS : false,
        webSearch: cfg && cfg.webSearch !== undefined ? cfg.webSearch : false,
        voiceMode: cfg && cfg.voiceMode !== undefined ? cfg.voiceMode : false,
        lastSet: (cfg && cfg.lastSet) || null,
        lastModel: (cfg && cfg.lastModel) || null,
      };
      console.debug('Initialized APP_DATA:', { 
          save: window.APP_DATA.saveThoughts, 
          send: window.APP_DATA.sendThoughts,
          set: window.APP_DATA.lastSet,
          model: window.APP_DATA.lastModel
      });
      window.DEFAULT_SYSTEM_PROMPT = (cfg && cfg.defaultSystemPrompt) || window.DEFAULT_SYSTEM_PROMPT || '';
    } else {
      window.APP_DATA = { userTier: 'free', availableModels: [], loggedIn: false, saveThoughts: true, sendThoughts: false, renderMarkdown: true, autoplayTTS: false, webSearch: false, voiceMode: false };
      window.DEFAULT_SYSTEM_PROMPT = window.DEFAULT_SYSTEM_PROMPT || '';
    }
  }
  // Fallback: if template was empty or missing values, populate from DOM
  try {
    const root = document.getElementById('app-root') || document.body;
    const ds = root ? root.dataset : {};
    if (ds) {
      if ((ds.loggedIn || '').length) { window.APP_DATA.loggedIn = (ds.loggedIn === 'true'); }
      if ((ds.userTier || '').length) { window.APP_DATA.userTier = ds.userTier; }
      if ((ds.defaultSystemPrompt || '').length && !window.DEFAULT_SYSTEM_PROMPT) {
        window.DEFAULT_SYSTEM_PROMPT = ds.defaultSystemPrompt;
      }
    }
    if (!window.APP_DATA.availableModels || window.APP_DATA.availableModels.length === 0) {
      const opts = Array.from(document.querySelectorAll('#modelSelect option'));
      window.APP_DATA.availableModels = opts.map(o => ({ provider_name: o.value, tier: o.getAttribute('data-tier') || 'free' }));
    }
  } catch (_) {}
} catch (e) { /* no-op */ }

if (window.EncKey && window.EncKey.purgeNonRememberedSlots && (!window.APP_DATA || !window.APP_DATA.loggedIn)) {
  window.EncKey.purgeNonRememberedSlots();
}

// ── Native Mic Bridge ────────────────────────────────────────────────────────
(function() {
  const hasCapacitor = !!(window.Capacitor && window.Capacitor.nativePromise);
  const isAndroid = /Android/.test(navigator.userAgent);
  window.nativeMicAvailable = false;

  if (hasCapacitor && isAndroid) {
    window.NativeMic = {
      isAvailable: function() { 
        return !!(window.Capacitor && window.Capacitor.nativePromise);
      },
      requestPermission: function() {
        return window.Capacitor.nativePromise('NativeMic', 'requestPermission', {});
      },
      isRecording: function() {
        return window.Capacitor.nativePromise('NativeMic', 'isRecording', {});
      },
      start: function() {
        return window.Capacitor.nativePromise('NativeMic', 'start', {});
      },
      stop: function() {
        return window.Capacitor.nativePromise('NativeMic', 'stop', {});
      },
      enterVoiceRoute: function() {
        return window.Capacitor.nativePromise('NativeMic', 'enterVoiceRoute', {});
      },
      exitVoiceRoute: function() {
        return window.Capacitor.nativePromise('NativeMic', 'exitVoiceRoute', {});
      },
      addListener: function(eventName, callback) {
        return window.Capacitor.addListener('NativeMic', eventName, callback);
      }
    };
    window.nativeMicAvailable = true;

    window._recoverNativeVoice = function () {
      const tasks = [];
      tasks.push(window.NativeMic.stop().catch(function () {}));
      if (window.NativeMic.exitVoiceRoute) {
        tasks.push(window.NativeMic.exitVoiceRoute().catch(function () {}));
      }
      if (window.NativeVoiceTts) {
        tasks.push(window.NativeVoiceTts.stop().catch(function () {}));
      }
      return Promise.all(tasks);
    };
    window.addEventListener('pagehide', function () {
      window.NativeMic.stop().catch(function () {});
      if (window.NativeMic.exitVoiceRoute) {
        window.NativeMic.exitVoiceRoute().catch(function () {});
      }
      if (window.NativeVoiceTts) {
        window.NativeVoiceTts.stop().catch(function () {});
      }
    });

    window.NativeVoiceTts = {
      isAvailable: function () {
        return !!(window.Capacitor && window.Capacitor.nativePromise);
      },
      beginSession: function () {
        return window.Capacitor.nativePromise('NativeVoiceTts', 'beginSession', {});
      },
      enqueue: function (url) {
        return window.Capacitor.nativePromise('NativeVoiceTts', 'enqueue', { url: url });
      },
      markEndOfQueue: function () {
        return window.Capacitor.nativePromise('NativeVoiceTts', 'markEndOfQueue', {});
      },
      play: function (url) {
        return window.Capacitor.nativePromise('NativeVoiceTts', 'play', { url: url });
      },
      stop: function () {
        return window.Capacitor.nativePromise('NativeVoiceTts', 'stop', {});
      },
      addListener: function (eventName, callback) {
        return window.Capacitor.addListener('NativeVoiceTts', eventName, callback);
      }
    };
    window.nativeVoiceTtsAvailable = true;
  }
})();

// HTTP/session client (static/session-client.js): single owner of fetch
// bootstrap, CSRF refresh, 401 retry, generate retry and voice HTTP helpers.
// Chat keeps DOM callbacks (location, CSRF meta, login state) here.
const SESSION_EXPIRED_SEND_MSG = ChatSessionClient.SESSION_EXPIRED_SEND_MSG;

var sessionClient = ChatSessionClient.createSessionClient({
  getLoggedIn: function () { return !!(window.APP_DATA && window.APP_DATA.loggedIn); },
  getCsrfToken: function () { return window.CSRF_TOKEN; },
  setCsrfToken: function (token) {
    window.CSRF_TOKEN = token;
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) meta.setAttribute('content', token);
  },
  redirectHome: function () { window.location.href = '/'; }
});
sessionClient.installFetchInterceptor();

function redirectHomeOnAuthFailure() {
  return sessionClient.redirectHomeOnAuthFailure();
}

try {
  var appRoot = document.getElementById('app-root');
  if (appRoot && appRoot.dataset) {
    window.CSRF_TOKEN = appRoot.dataset.csrfToken || window.CSRF_TOKEN;
  }
  if (!window.CSRF_TOKEN) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) {
      window.CSRF_TOKEN = meta.getAttribute('content');
    }
  }
} catch (e) { /* no-op */ }

// Session bootstrap lives in the owned client (single shared attempt,
// guest bypass, error recovery). Chat keeps only the thin adapter.
function refreshSession() {
  return sessionClient.refreshSession();
}

// Rebuild a cached fetch init's X-CSRF-Token header after a session
// refresh (headers were snapshotted by withCsrf at call time).
function refreshCsrfInit(init) {
  return sessionClient.refreshCsrfInit(init);
}



function historyImageUrl(pairIndex, imageIndex) {
  var setId = (window.APP_DATA && window.APP_DATA.lastSetId) || '';
  var version = (window.APP_DATA && window.APP_DATA.setVersion != null)
    ? window.APP_DATA.setVersion : 0;
  var idx = imageIndex == null ? 0 : imageIndex;
  return '/history_image/' + encodeURIComponent(setId)
    + '/' + encodeURIComponent(String(version))
    + '/' + encodeURIComponent(String(pairIndex))
    + '/' + encodeURIComponent(String(idx));
}

function historyThumbUrl(pairIndex, imageIndex) {
  return historyImageUrl(pairIndex, imageIndex) + '?size=thumb';
}

// Voice/generate HTTP helpers live in the owned session client; chat keeps
// thin adapters so call sites and vm fixtures keep the same names.
function sleepMs(ms) {
  return sessionClient.sleepMs(ms);
}

function isRetryableVoiceStatus(status) {
  return sessionClient.isRetryableVoiceStatus(status);
}

function fetchVoiceRetry(url, buildOptions, attempts) {
  return sessionClient.fetchVoiceRetry(url, buildOptions, attempts);
}

function postVoiceSttXhr(url, buildOptions, attempts) {
  return sessionClient.postVoiceSttXhr(url, buildOptions, attempts);
}

function withCsrf(headers) {
  return sessionClient.withCsrf(headers);
}

async function withCsrfAsync(headers) {
  return sessionClient.withCsrfAsync(headers);
}


function syncSelectedOptionVersion(version) {
  var $opt = $('#set-selector option:selected');
  if ($opt.length) $opt.attr('data-version', String(version));
}

/** Version transitions live in static/conversation-state.js (reads advance
 *  only; mutations/409 authoritative). window.APP_DATA stays the single
 *  store; the option sync below is the DOM callback. */
function applySetVersion(version, setId, options) {
  if (!window.APP_DATA) window.APP_DATA = {};
  var result = ChatConversationState.applySetVersionTo(window.APP_DATA, version, setId, options);
  if (result && result.syncVersion != null) syncSelectedOptionVersion(result.syncVersion);
}

function activeSetPayload(extra) {
  var $o = $('#set-selector option:selected');
  return ChatConversationState.buildActiveSetPayload({
    setName: $o.attr('data-name') || $o.text() || 'default',
    setId: (window.APP_DATA && window.APP_DATA.lastSetId) || $o.val(),
    setVersion: window.APP_DATA ? window.APP_DATA.setVersion : undefined
  }, extra);
}

function noteSetVersionFromResponse(data) {
  if (!data) return;
  if (!window.APP_DATA) window.APP_DATA = {};
  var result = ChatConversationState.noteSetVersionFromResponseTo(window.APP_DATA, data);
  if (result && result.syncVersion != null) syncSelectedOptionVersion(result.syncVersion);
}

/** Sync version from an authoritative READ response (load_set / history_pair).
 *  Advance-only: a concurrent write may make the read snapshot stale-low, and
 *  we must never rewind below a version the client already observed. */
function noteSetVersionFromRead(data) {
  if (!data) return;
  if (!window.APP_DATA) window.APP_DATA = {};
  var result = ChatConversationState.noteSetVersionFromReadTo(window.APP_DATA, data);
  if (result && result.syncVersion != null) syncSelectedOptionVersion(result.syncVersion);
}

/** Extract a human-readable message from an error-response body. */
function apiErrorText(text, fallback) {
  var raw = String(text || '').trim();
  if (!raw) return fallback || 'Request failed';
  try {
    var data = JSON.parse(raw);
    var msg = data && (data.message || data.error);
    if (msg) {
      if (data.error === 'version_conflict') return 'Chat state changed elsewhere; syncing and retrying.';
      return String(msg);
    }
  } catch (e) { /* not JSON — show raw text */ }
  return raw.length > 300 ? raw.slice(0, 300) + '…' : raw;
}

/** After chat/regenerate persist, CAS version advances by one. Update immediately
 *  so delete/reset don't race the async loadSets() refresh. */
function noteLocalVersionBumpAfterPersist() {
  if (!window.APP_DATA) return;
  var result = ChatConversationState.noteLocalVersionBumpAfterPersistTo(window.APP_DATA);
  if (result && result.syncVersion != null) syncSelectedOptionVersion(result.syncVersion);
}

// History window and set-generation fencing (static/conversation-state.js).
// Single authority for offset/total/has-more/loading/generation.
var historyWindow = ChatConversationState.createHistoryWindow(ChatConversationState.HISTORY_PAGE_SIZE);
var HISTORY_PAGE_SIZE = ChatConversationState.HISTORY_PAGE_SIZE;

function resetHistoryWindow() {
  historyWindow.reset();
}

function liveUserPairIndex(userMessageElement) {
  var el = userMessageElement && userMessageElement.jquery ? userMessageElement[0] : userMessageElement;
  if (!el) return -1;
  var nodes = document.querySelectorAll('#chat-content .message.user-message');
  var i = Array.prototype.indexOf.call(nodes, el);
  if (i < 0) return -1;
  return ChatConversationState.userPairIndexForDomIndex(historyWindow.getOffset(), i);
}

function isLocalOnlyTurn(el) {
  var node = el && el.jquery ? el[0] : el;
  if (!node) return false;
  if (node.getAttribute('data-local-only') === '1') return true;
  var prev = node.previousElementSibling;
  if (node.classList && node.classList.contains('ai-message') && prev
      && prev.classList.contains('user-message')
      && prev.getAttribute('data-local-only') === '1') {
    return true;
  }
  return false;
}

function markLocalOnlyTurn($user, $ai) {
  if ($user && $user.length) $user.attr('data-local-only', '1');
  if ($ai && $ai.length) $ai.attr('data-local-only', '1');
}

function clearLocalOnlyTurn($user, $ai) {
  if ($user && $user.length) $user.removeAttr('data-local-only');
  if ($ai && $ai.length) $ai.removeAttr('data-local-only');
}

function removeLocalOnlyTurn($user) {
  if (!$user || !$user.length) return;
  var $ai = $user.next('.message.ai-message');
  $ai.remove();
  $user.remove();
  reindexUserPairIndices();
  if (typeof updateLoadOlderBar === 'function') updateLoadOlderBar();
}

function paintFailedAiTurn($user, errorText) {
  if (!$user || !$user.length) return $();
  var $ai = $user.next('.message.ai-message');
  if (!$ai.length) {
    appendMessage(null, 'ai-message');
    $ai = $user.next('.message.ai-message');
  }
  if (!$ai.length) return $();
  replaceChildrenNative($ai[0], buildAiErrorChildren(errorText));
  markLocalOnlyTurn($user, $ai);
  // Terminal chrome: settle the bound stream source keeping its last
  // published text, or bind a finished empty source for a fresh shell.
  var failedHost = $ai[0];
  var failedSource = messagePlaybackSources.get(failedHost) || null;
  if (failedSource) failedSource.finish();
  else bindMessagePlaybackSource(failedHost, { original: '', visible: '', boundSeq: null, finished: true });
  if (liveStreamPlaybackSource === failedSource) liveStreamPlaybackSource = null;
  return $ai;
}

function reindexUserPairIndices() {
  var nodes = document.querySelectorAll('#chat-content .message.user-message');
  for (var i = 0; i < nodes.length; i++) {
    var pairIndex = ChatConversationState.userPairIndexForDomIndex(historyWindow.getOffset(), i);
    nodes[i].setAttribute('data-pair-index', String(pairIndex));
    var img = nodes[i].querySelector('img.chat-image');
    if (img) img.setAttribute('data-pair-index', String(pairIndex));
  }
}

/** Sync CAS version from a 409 body and retry. Never ask the user to reload —
 *  Capacitor / embedded clients cannot depend on a page refresh. */
function handleVersionConflict(response, data, retryFn) {
  if (data) {
    applySetVersion(
      data.current_version != null ? data.current_version : data.version,
      data.set_id,
      { allowRewind: true }
    );
  }
  if (typeof retryFn === 'function') {
    return Promise.resolve().then(retryFn);
  }
  var draft = '';
  try { draft = $('#user-input').val() || ''; } catch (e) {}
  if (typeof loadSets === 'function') {
    return loadSets(true).then(function() {
      if (draft) {
        try { $('#user-input').val(draft); } catch (e) {}
      }
    });
  }
  return Promise.resolve();
}

function parseJsonOrEmpty(response) {
  return response.text().then(function(t) {
    if (!t) return {};
    try { return JSON.parse(t); } catch (e) { return { error: t }; }
  });
}

/** POST /reset_chat with self-healing: on 409 version_conflict, adopt the
 *  authoritative version from the body and retry once with a fresh payload. */
function submitResetChat(isRetry) {
  return fetch('/reset_chat', {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(activeSetPayload({}))
  })
    .then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })))
    .then(result => {
      if (result.data && result.data.error === 'version_conflict') {
        noteSetVersionFromResponse(result.data);
        if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return submitResetChat(true);
        appendMessage('The chat was updated elsewhere while resetting. Please try again.', 'error-message');
        return;
      }
      if (result.ok && result.data && result.data.status === 'success') {
        noteSetVersionFromResponse(result.data);
        $('#chat-content').empty();
        resetHistoryWindow();
        appendMessage('Chat history has been reset for set ' + (result.data.set_name || '') + '.', 'system-message');
        return;
      }
      const errMsg = (result.data && (result.data.message || result.data.error)) || 'Failed to reset chat';
      appendMessage(errMsg, 'error-message');
    })
    .catch(error => { appendMessage(error && error.message ? error.message : String(error), 'error-message'); });
}

function showEncKeyGateLoading(message) {
  var $encGate = $('#enc-key-gate');
  if (!$encGate.length) {
    return;
  }
  $encGate.removeClass('d-none');
  $('#enc-key-gate-spinner').show();
  $('#enc-key-gate-actions').addClass('d-none');
  $encGate.find('.enc-key-gate-message').text(message || 'Loading your sets…');
}

function showEncKeyGateError(err) {
  var $encGate = $('#enc-key-gate');
  if (!$encGate.length) {
    return;
  }
  $('#enc-key-gate-spinner').hide();
  $('#enc-key-gate-actions').removeClass('d-none');
  var msg = err && err.message ? err.message : 'Encryption key unavailable.';
  if (/authentication cancelled/i.test(msg)) {
    msg = 'Unlock cancelled. Try again or sign out and log in.';
  } else if (window.EncKey && window.EncKey.isNativeSecureStorage && window.EncKey.isNativeSecureStorage()) {
    if (/not found|unavailable|failed to read/i.test(msg)) {
      msg = 'Encryption key not found on this device. Sign out and log in again.';
    }
  }
  $encGate.find('.enc-key-gate-message').text(msg);
}

function hideEncKeyGate() {
  $('#enc-key-gate').addClass('d-none');
}

var encKeyUnlockInFlight = null;
var ENC_GATE_RELOADS_KEY = 'chatbot_enc_gate_reloads';
function beginEncKeyUnlockFlow(fromUser) {
  if (encKeyUnlockInFlight) {
    return encKeyUnlockInFlight;
  }
  if (!fromUser) {
    var reloads = 0;
    try {
      reloads = parseInt(sessionStorage.getItem(ENC_GATE_RELOADS_KEY) || '0', 10) || 0;
    } catch (e) {}
    if (reloads >= 2) {
      showEncKeyGateError(new Error('Could not load your chats. Sign out and log in with your password.'));
      return Promise.reject(new Error('enc-key gate stopped after repeated failures'));
    }
    try {
      sessionStorage.setItem(ENC_GATE_RELOADS_KEY, String(reloads + 1));
    } catch (e) {}
  }
  showEncKeyGateLoading('Loading your sets…');
  encKeyUnlockInFlight = Promise.resolve()
    .then(function() {
      if (typeof window.loadChatSets !== 'function') {
        throw new Error('Chat is still starting. Try again.');
      }
      return window.loadChatSets();
    })
    .then(function() {
      try { sessionStorage.removeItem(ENC_GATE_RELOADS_KEY); } catch (e) {}
      hideEncKeyGate();
    })
    .catch(function(err) {
      console.error('encryption key unavailable on chat load', err);
      showEncKeyGateError(err);
      throw err;
    })
    .finally(function() {
      encKeyUnlockInFlight = null;
    });
  return encKeyUnlockInFlight;
}

// 401 classification lives in the owned session client; chat keeps thin
// adapters so call sites stay unchanged.
async function response401Message(response) {
  return sessionClient.response401Message(response);
}

async function response401Kind(response) {
  return sessionClient.response401Kind(response);
}

async function handle401OrRetry(response, retryFn) {
  return sessionClient.handle401OrRetry(response, retryFn);
}

function logoutThisComputer() {
  var username = window.APP_DATA && window.APP_DATA.username;
  if (!username) {
    window.location.href = '/logout';
    return;
  }
  if (!window.confirm(
    'Forget ' + username + ' on this computer? You will need the password to sign in to it again.'
  )) {
    return;
  }
  var csrf = window.CSRF_TOKEN || '';
  var done = Promise.resolve();
  if (window.EncKey && window.EncKey.removeSlot) {
    done = window.EncKey.removeSlot(username).catch(function () {});
  }
  done
    .then(function () {
      return fetch('/login/forget', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:
          'csrf_token=' + encodeURIComponent(csrf) +
          '&username=' + encodeURIComponent(username),
      });
    })
    .catch(function () {})
    .then(function () {
      window.location.href = '/logout';
    });
}

// Settings panel behavior (collapse on small screens)
$(function() {
  $(document).on('click', '.logout-this-computer', function (e) {
    e.preventDefault();
    logoutThisComputer();
  });
  if (window.APP_DATA && window.APP_DATA.loggedIn) {
    var $hint = $('#enc-key-storage-hint');
    if ($hint.length) {
      $hint.text('Your chat key is stored in a cookie this page cannot read.');
    }
  }
  try {
    var $collapseEl = $('#settingsCollapse');
    var collapseEl = $collapseEl[0];
    var $settingsCol = $('#settings-col');
    var $chatArea = $('#chat-area');
    if (!$collapseEl.length || !$settingsCol.length || !$chatArea.length) return;

    var bsCollapse = bootstrap.Collapse.getOrCreateInstance(collapseEl, { toggle: false });

    function applyState(open) {
      if (!open) { $settingsCol.addClass('d-none'); } else { $settingsCol.removeClass('d-none'); }
      if ($(window).width() >= 768) {
        if (!open) { $chatArea.removeClass('col-md-8').addClass('col-md-12'); }
        else { $chatArea.removeClass('col-md-12').addClass('col-md-8'); }
      } else {
        $chatArea.removeClass('col-md-12').addClass('col-md-8');
      }
    }

    if ($(window).width() >= 768) { bsCollapse.show(); } else { bsCollapse.hide(); }
    applyState(bsCollapse._isShown || $collapseEl.hasClass('show'));

    $collapseEl.on('shown.bs.collapse', function() { applyState(true); });
    $collapseEl.on('hidden.bs.collapse', function() { applyState(false); });
    $(window).on('resize', function() {
      if ($(window).width() >= 768) bsCollapse.show();
      applyState($collapseEl.hasClass('show'));
    });
  } catch (e) { console.debug('settings collapse init error', e); }
});

// Global helpers and state
// Pure string replace — do NOT use createTextNode + div.innerHTML here.
// That pattern is a CodeQL js/xss-through-dom source (DOM text) that later
// flows into .html() sinks across appendMessage / system errors.
// Owned by static/chat-renderer.js; thin adapters preserve call sites.
function escapeHTML(str) {
  return ChatRenderer.escapeHTML(str);
}

// Inverse of the common entities produced by escapeHTML.
// Used only to undo pre-escaping before highlight.js (which escapes again).
function decodeHTMLEntities(str) {
  return ChatRenderer.decodeHTMLEntities(str);
}

// Copy text to the clipboard in any context. The async Clipboard API is only
// available on secure origins (HTTPS / localhost / file:// in some browsers);
// on plain HTTP the property is undefined and the call throws synchronously,
// which a Promise .catch() does not catch. Fall back to a hidden textarea
// + document.execCommand('copy'), which still works in insecure contexts.
function copyToClipboard(text) {
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function' && window.isSecureContext) {
    try {
      return navigator.clipboard.writeText(text);
    } catch (e) {
      return fallbackCopy(text, e);
    }
  }
  return fallbackCopy(text, null);

  function fallbackCopy(value, asyncErr) {
    return new Promise(function (resolve, reject) {
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.left = '0';
      ta.style.opacity = '0';
      ta.style.pointerEvents = 'none';
      document.body.appendChild(ta);
      const sel = document.getSelection();
      const previousRange = sel && sel.rangeCount > 0 ? sel.getRangeAt(0) : null;
      ta.focus();
      ta.select();
      let ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (e) {
        if (asyncErr) reject(asyncErr);
        else reject(e);
        if (ta.parentNode) ta.parentNode.removeChild(ta);
        if (previousRange && sel) { sel.removeAllRanges(); sel.addRange(previousRange); }
        return;
      }
      if (ta.parentNode) ta.parentNode.removeChild(ta);
      if (previousRange && sel) { sel.removeAllRanges(); sel.addRange(previousRange); }
      if (ok) resolve();
      else if (asyncErr) reject(asyncErr);
      else reject(new Error('execCommand("copy") returned false'));
    });
  }
}

// Accept only data:image/*;base64,... URLs for <img src>.
// Owned by static/chat-renderer.js; thin adapter preserves call sites.
function sanitizeDataImageSrc(src) {
  return ChatRenderer.sanitizeDataImageSrc(src);
}

// Build the user-message display node without interpreting message text as HTML
// (CodeQL js/xss-through-dom). Text goes through createTextNode only; images use
// a reconstructed data:image URL from sanitizeDataImageSrc.
// Rendering builders live in static/chat-renderer.js; thin adapters keep
// call sites and CodeQL separation (exception text never shares a param
// with an innerHTML sink). Chat keeps DOM/event composition.
function buildUserMessageSpan(text, imageSrc, opts) {
  return chatRenderer.buildUserMessageSpan(text, imageSrc, opts);
}

// Append plain text (with optional newlines → <br>) without HTML interpretation.
function appendPlainTextWithBreaks(parent, text) {
  return chatRenderer.appendPlainTextWithBreaks(parent, text);
}

// System/error chrome: fixed label + plain text only (createTextNode).
// Accepts only a scalar string — never options objects (CodeQL js/xss-through-exception
// is field-insensitive and would join error text with sibling fields like href).
function buildStatusMessageContent(className, text) {
  return chatRenderer.buildStatusMessageContent(className, text);
}

// Dedicated sets-load failure UI. Exception text is textContent only; the logout
// href is a string literal so it cannot be joined with error.message by analysis.
function buildSetsLoadErrorContent(errorText) {
  return chatRenderer.buildSetsLoadErrorContent(errorText);
}

// AI chrome builders — kept as separate functions so exception strings never
// share a parameter/object with an innerHTML sink (CodeQL js/xss-through-exception).

function buildAiLabelFragment() {
  return chatRenderer.buildAiLabelFragment();
}

// History load only. `safeHtml` must already be produced by formatAiMessage /
// renderMarkdown (escapeHTML). Do not pass err.message here.
function buildAiHistoryChildren(safeHtml) {
  return chatRenderer.buildAiHistoryChildren(safeHtml);
}

// Failed regenerate/chat: exception text via textContent only (never innerHTML).
function buildAiErrorChildren(errorText) {
  return chatRenderer.buildAiErrorChildren(errorText);
}

// Streaming / regenerate placeholder shell (static chrome only).
function buildAiStreamChildren() {
  return chatRenderer.buildAiStreamChildren();
}

// Mount a pre-built message node into #chat-content (shared chrome, no content).
function mountChatMessage(hostEl, mountOpts) {
  const $chatContent = $('#chat-content');
  const parent = $chatContent[0];
  // Sample before insert: a new bubble taller than the at-bottom slop would
  // otherwise unpin and skip the scroll (voice transcripts are often a paragraph).
  const follow = !(mountOpts && mountOpts.skipScroll) && shouldStickChatToBottom();
  if (parent && hostEl) {
    if (mountOpts && mountOpts.fragment) {
      mountOpts.fragment.appendChild(hostEl);
    } else if (mountOpts && mountOpts.before) {
      parent.insertBefore(hostEl, mountOpts.before);
    } else {
      parent.appendChild(hostEl);
    }
  }
  if (follow) {
    scrollToBottom();
  }
}

// History AI bubble — separate entry point from appendMessage so exception text
// that flows into appendMessage(message, 'error-message') cannot reach innerHTML
// via field-insensitive joining of the shared `message` parameter.
function appendAiHistoryMessage(safeHtml, mountOpts) {
  const $messageElement = $('<div>').addClass('message ai-message');
  replaceChildrenNative($messageElement[0], buildAiHistoryChildren(safeHtml));
  mountChatMessage($messageElement[0], mountOpts);
  return $messageElement;
}

// Sets-load failure with logout affordance — not routed through appendMessage.
function appendSetsLoadError(errorText) {
  const $messageElement = $('<div>').addClass('message error-message');
  replaceChildrenNative($messageElement[0], buildSetsLoadErrorContent(errorText));
  mountChatMessage($messageElement[0]);
  return $messageElement;
}

function buildAiRegenerateContainer(enabled) {
  return chatRenderer.buildAiRegenerateContainer(enabled);
}

// Marked/highlight.js wiring lives in the owned renderer; chat keeps the
// single configuration call so code fences highlight exactly as before.
chatRenderer.configureMarked();

function renderMarkdown(text) {
  return chatRenderer.renderMarkdown(text);
}

// Top-level on purpose: appendHistoryPair / applyHistoryPage run outside the
// logged-in document.ready closure (a nested helper is ReferenceError there).
// History adapter: whole-text projection, no console stripping.
function formatAiMessage(text) {
  return chatRenderer.formatAiMessage(text);
}

// Scroll helpers for the chat content container
let chatScrollGeneration = 0;
let lastChatScrollTop = null;

function isAtBottom() {
  const container = document.getElementById('chat-content');
  if (!container) return false;
  // Voice-mode WebView layout can land a few dozen px short; stay sticky there.
  const threshold = window.voiceModeActive ? 120 : 30;
  return (container.scrollTop + container.clientHeight) >= (container.scrollHeight - threshold);
}

function shouldStickChatToBottom() {
  return isAtBottom();
}

function scrollToBottom() {
  const container = document.getElementById('chat-content');
  if (!container) return;
  const generation = chatScrollGeneration;
  // Direct scrollTop: scrollTo({ behavior: 'instant' }) can no-op or stop short
  // in Android WebView. Pin again after layout so markdown/images settle.
  const pin = function (force) {
    if (!force && generation !== chatScrollGeneration) return;
    container.scrollTop = container.scrollHeight;
    lastChatScrollTop = container.scrollTop;
  };
  pin(true);
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(function () {
      pin(false);
      requestAnimationFrame(function () { pin(false); });
    });
  } else {
    setTimeout(function () { pin(false); }, 0);
  }
}

// Voice lifecycle lives in static/voice-lifecycle.js; rendering lives in
// static/chat-renderer.js; sentence queues live in static/tts-playback.js.
// Chat keeps DOM/event composition with explicit adapters here.
var voiceLifecycle = ChatVoiceLifecycle.createVoiceLifecycle({
  now: function () { return Date.now(); },
  createAudio: function () { return new Audio(); },
  createAbortController: function () { return new AbortController(); },
  revokeUrl: function (url) { try { URL.revokeObjectURL(url); } catch (e) { /* ignore */ } },
  resetPlayButton: function (button) { resetPlayButtonUi(button); },
  clearMessageUi: function () { clearMessageTtsPlayingUi(); },
  syncSendButton: function () {
    if (typeof syncSendButtonState === 'function') syncSendButtonState();
  },
  isVoiceModeActive: function () { return !!window.voiceModeActive; },
  stopNativePlayback: function () {
    if (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) {
      window.NativeVoiceTts.stop().catch(function () {});
    }
  }
});
// Thresholds are owned; chat keeps read-only aliases.
const TTS_LISTEN_COOLDOWN_MS = ChatVoiceLifecycle.TTS_LISTEN_COOLDOWN_MS;
const BARGE_IN_FRAMES_DESKTOP = ChatVoiceLifecycle.BARGE_IN_FRAMES_DESKTOP;
const BARGE_IN_SPEECH_PROB = ChatVoiceLifecycle.BARGE_IN_SPEECH_PROB;
/** In-flight desktop voice-mode STT upload; top-level so playTTS can abort it. */
let voiceSttAbortController = null;
/** Sentence/clip bounds live in the owned TTS playback unit; chat keeps read-only aliases. */
const MAX_TTS_SENTENCE_RETRIES = ChatTtsPlayback.MAX_TTS_SENTENCE_RETRIES;
/** Includes token requests, downloads, ready clips, and the clip being written to AudioTrack. */
const MAX_NATIVE_TTS_LOOKAHEAD = ChatTtsPlayback.MAX_NATIVE_TTS_LOOKAHEAD;
/** Total attempts to fetch one clip from /tts_stream (within the server's replay budget). */
const MAX_TTS_CLIP_ATTEMPTS = ChatTtsPlayback.MAX_TTS_CLIP_ATTEMPTS;
/** Backoff between clip GET retries; grows with the attempt number. */
const TTS_CLIP_RETRY_BACKOFF_MS = ChatTtsPlayback.TTS_CLIP_RETRY_BACKOFF_MS;

// Desktop clip pipeline (owned sentence/clip loops in static/tts-playback.js
// using the single voice lifecycle + voice-text; explicit HTTP/audio adapters).
var desktopTtsClip = ChatTtsPlayback.createDesktopClipPipeline({
  isLive: function (sessionId) { return desktopTtsIsLive(sessionId); },
  sanitize: function (text) { return sanitizeForTTS(text); },
  hasPreload: function (key) { return voiceLifecycle.hasPreload(key); },
  getPreload: function (key) { return voiceLifecycle.getPreload(key); },
  setPreload: function (key, promise) { voiceLifecycle.setPreload(key, promise); },
  deletePreload: function (key) { voiceLifecycle.deletePreload(key); },
  getAbortSignal: function () { return voiceLifecycle.getDesktopAbortSignal(); },
  fetchVoiceRetry: function (url, buildOptions, attempts) { return fetchVoiceRetry(url, buildOptions, attempts); },
  withCsrf: function (headers) { return withCsrf(headers); },
  getAudio: function () { return getDesktopTtsAudio(); },
  createObjectUrl: function (blob) { return URL.createObjectURL(blob); },
  revokeObjectUrl: function (url) { try { URL.revokeObjectURL(url); } catch (e) { /* ignore */ } },
  adoptBlobUrl: function (url) { voiceLifecycle.adoptBlobUrl(url); },
  releaseBlobUrl: function (url) { voiceLifecycle.releaseBlobUrlIfCurrent(url); },
  isVoiceModeActive: function () { return !!window.voiceModeActive; },
  noteClipStarted: function () { voiceLifecycle.noteDesktopClipStarted(); },
  noteClipFinished: function () { voiceLifecycle.noteDesktopClipFinished(); },
  notifyStarted: function () {
    if (typeof window.notifyVoiceModeTtsStarted === 'function') window.notifyVoiceModeTtsStarted();
  },
  notifyEnded: function () {
    if (typeof window.notifyVoiceModeTtsEnded === 'function') window.notifyVoiceModeTtsEnded();
  },
  logError: function () { console.error.apply(console, arguments); },
  setTimeout: function (fn, ms) { return setTimeout(fn, ms); }
});

function clearDesktopTtsPreloads() {
  voiceLifecycle.clearPreloads();
}


function armTtsListenCooldown() {
  voiceLifecycle.armListenCooldown();
}

function resetPlayButtonUi(button) {
  if (!button) return;
  $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
}

function getDesktopTtsAudio() {
  return voiceLifecycle.getDesktopAudio();
}

/**
 * Reset the shared <audio> between utterances/sessions.
 * Important: do NOT call audio.load() after every stop — that re-arms autoplay
 * blocking so the 1st play works and the 2nd (after async /tts) silently fails.
 */
function resetDesktopTtsAudioElement() {
  voiceLifecycle.resetDesktopAudioElement();
}

/**
 * Must run synchronously inside a click/tap handler before any await/fetch.
 * Primes the shared Audio element so later play() after /tts is allowed.
 * Only clears the element if it still holds the silent unlock clip — never
 * pauses a real /tts_stream that may already have been assigned.
 */
function primeDesktopTtsAudioFromGesture() {
  const audio = getDesktopTtsAudio();
  if (audio.dataset && audio.dataset.ttsPrimed === '1') return;
  // Minimal valid silent WAV (very short).
  var silent =
    'data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEAESsAACJWAAACABAAZGF0YQQAAAAAAA==';
  try {
    audio.muted = true;
    audio.src = silent;
    var p = audio.play();
    if (p && typeof p.then === 'function') {
      p.then(function () {
        // If real TTS already replaced src, leave it alone.
        var src = audio.currentSrc || audio.src || '';
        if (src.indexOf('data:audio/wav') !== 0) {
          audio.muted = false;
          if (audio.dataset) audio.dataset.ttsPrimed = '1';
          return;
        }
        try { audio.pause(); } catch (e1) { /* ignore */ }
        audio.muted = false;
        try { audio.removeAttribute('src'); audio.src = ''; } catch (e2) { /* ignore */ }
        if (audio.dataset) audio.dataset.ttsPrimed = '1';
      }).catch(function () {
        audio.muted = false;
      });
    } else {
      audio.muted = false;
      if (audio.dataset) audio.dataset.ttsPrimed = '1';
    }
  } catch (e) {
    try { audio.muted = false; } catch (e3) { /* ignore */ }
  }
}

/**
 * Stop desktop TTS completely. Safe to call when idle.
 * Always bumps the owned desktop session so any prior async chain becomes a no-op.
 */
function stopCurrentDesktopTts() {
  voiceLifecycle.stopDesktopPlayback();
}

function completeDesktopTtsPlayback(button) {
  voiceLifecycle.completeDesktopPlayback(button);
}


function desktopTtsIsLive(sessionId) {
  return voiceLifecycle.isLiveDesktop(sessionId);
}

function disablePremiumModels() {
  const $selector = $('#modelSelect');
  if ($selector.length === 0) return;
  $selector.find('option').each(function() {
    const isPremium = $(this).data('tier') === 'premium';
    const userTier = (window.APP_DATA && window.APP_DATA.userTier) ? window.APP_DATA.userTier : 'free';
    $(this).css('opacity', isPremium && userTier !== 'premium' ? '0.6' : '1');
  });
}

let previousModel = 'default';
window.validateModelTier = function validateModelTier() {
  const $selected = $('#modelSelect option:checked');
  const $premiumAlert = $('#premium-alert');
  const $modelSelect = $('#modelSelect');
  const userTier = (window.APP_DATA && window.APP_DATA.userTier) ? window.APP_DATA.userTier : 'free';
  if ($selected.data('tier') === 'premium' && userTier !== 'premium') {
    $premiumAlert.show();
    setTimeout(() => $premiumAlert.hide(), 3000);
    $modelSelect.val(previousModel);
    $modelSelect.css('backgroundColor', '#3a1a1a');
    setTimeout(() => { $modelSelect.css('backgroundColor', '#2c3e50'); }, 500);
  } else {
    $premiumAlert.hide();
    $modelSelect.css('backgroundColor', '#2c3e50');
  }
  previousModel = $modelSelect.val();
  updateSearchToggleVisibility();
}

function updateSearchToggleVisibility() {
    const $selected = $('#modelSelect option:checked');
    const $searchToggle = $('#web-search-toggle');
    if ($selected.data('search') === true || $selected.data('search') === 'true') {
        $searchToggle.show();
        // Reflect the per-account preference stored on the server.
        if (window.APP_DATA && window.APP_DATA.webSearch) {
            $searchToggle.removeClass('btn-outline-secondary').addClass('btn-primary');
            $searchToggle.attr('title', 'Web Search: ON');
        } else {
            $searchToggle.removeClass('btn-primary').addClass('btn-outline-secondary');
            $searchToggle.attr('title', 'Web Search: OFF');
        }
    } else {
        $searchToggle.hide();
        // Reset search to OFF if not supported
        $searchToggle.removeClass('btn-primary').addClass('btn-outline-secondary');
        $searchToggle.attr('title', 'Web Search: OFF');
    }
}

// Wire format: plain text + optional [IMAGE:data:image/...;base64,...] tag.
// Keep image payload out of the edit textarea (1MB+ base64 freezes the browser).
var USER_IMAGE_TAG_RE = /\[IMAGE:(data:image\/[^;]+;base64,[^\]]+)\]/;
var USER_IMAGE_ANY_RE = /\[IMAGE:([^\]]*)\]/;

function parseUserMessageContent(originalText) {
  var raw = originalText == null ? '' : String(originalText);
  var anyMatch = raw.match(USER_IMAGE_ANY_RE);
  var payload = anyMatch ? anyMatch[1] : '';
  var imageSrc = payload ? sanitizeDataImageSrc(payload) : null;
  var deferred = !!anyMatch && !imageSrc && payload !== 'unavailable';
  var text = raw.replace(/\[IMAGE:[^\]]*\]/g, '').trim();
  return { text: text, imageSrc: imageSrc, deferred: deferred, hasImage: !!anyMatch };
}

/** Join a late voice fragment onto the previous user utterance. */
function joinVoiceUtterances(previous, next) {
  return ChatVoiceText.joinVoiceUtterances(previous, next);
}

/** False end-of-speech / quick add-on window. After this, start a new turn. */
const VOICE_AMEND_WINDOW_MS = 2000;
let lastVoiceSpeechEndedAt = 0;
let lastVoiceUtteranceStartedAt = 0;

/** True when a new STT result is a continuation of the in-flight voice turn. */
function shouldAmendLastVoiceTurn(state) {
  state = state || {};
  return ChatVoiceText.shouldAmendLastVoiceTurn({
    lastUserExists: state.lastUserExists,
    generating: state.generating,
    ttsActive: state.ttsActive,
    lastSpeechEndedAt: state.lastSpeechEndedAt,
    utteranceStartedAt: state.utteranceStartedAt
  }, VOICE_AMEND_WINDOW_MS);
}

function composeUserMessageContent(text, imageSrc, hasImage) {
  var body = (text == null ? '' : String(text)).trim();
  var safeSrc = sanitizeDataImageSrc(imageSrc);
  if (safeSrc) {
    return body + (body ? '\n' : '') + '[IMAGE:' + safeSrc + ']';
  }
  if (hasImage || (imageSrc && String(imageSrc).indexOf('/history_image/') === 0)) {
    return body + (body ? '\n' : '') + '[IMAGE:]';
  }
  return body;
}

function fetchHistoryPair(pairIndex, extra) {
  return withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
    return fetch('/history_pair', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(activeSetPayload(Object.assign({ pair_index: pairIndex }, extra || {})))
    });
  }).then(function(r) {
    if (r.status === 401) {
      redirectHomeOnAuthFailure();
      throw new Error('Session expired');
    }
    if (!r.ok) throw new Error('Failed to load message');
    return r.json();
  }).then(function(data) {
    noteSetVersionFromRead(data);
    return data;
  });
}

function ensureLoadOlderBar() {
  var existing = document.getElementById('load-older-bar');
  if (existing) return existing;
  var chat = document.getElementById('chat-content');
  if (!chat) return null;
  var bar = document.createElement('div');
  bar.id = 'load-older-bar';
  bar.className = 'load-older-bar';
  bar.hidden = true;
  var btn = document.createElement('button');
  btn.type = 'button';
  btn.id = 'load-older-btn';
  btn.className = 'btn btn-sm btn-outline-secondary load-older-btn';
  btn.textContent = 'Load older messages';
  btn.addEventListener('click', function() { loadOlderMessages(); });
  bar.appendChild(btn);
  chat.insertBefore(bar, chat.firstChild);
  return bar;
}

function updateLoadOlderBar() {
  var bar = ensureLoadOlderBar();
  if (!bar) return;
  var btn = document.getElementById('load-older-btn');
  var snap = historyWindow.snapshot();
  if (snap.hasMore && snap.offset > 0) {
    bar.hidden = false;
    if (btn) {
      btn.disabled = !!snap.loadingOlder;
      btn.textContent = snap.loadingOlder
        ? 'Loading…'
        : (snap.offset === 1
          ? 'Load older message'
          : 'Load older messages (' + snap.offset + ' earlier)');
    }
  } else {
    bar.hidden = true;
  }
}

function startDeferredThumbs(root, newestFirst) {
  var scope = root || document;
  var imgs = scope.querySelectorAll
    ? scope.querySelectorAll('img.chat-image[data-pending-src]')
    : [];
  var list = Array.prototype.slice.call(imgs);
  if (newestFirst) list.reverse();
  for (var i = 0; i < list.length; i++) {
    var url = list[i].getAttribute('data-pending-src');
    list[i].removeAttribute('data-pending-src');
    // DOM attribute text is a js/xss-through-dom source; only assign a
    // reconstructed data:image URL or same-origin /history_image/... path.
    var safeUrl = sanitizeLightboxSrc(url);
    if (newestFirst && i === 0) {
      list[i].setAttribute('fetchpriority', 'high');
    }
    if (safeUrl) list[i].setAttribute('src', safeUrl);
  }
}

function appendHistoryPair(userMsg, aiMsg, pairIndex, mountOpts) {
  var opts = Object.assign({ thumbnail: true, deferSrc: true }, mountOpts || {});
  appendMessage(userMsg, 'user-message', pairIndex, opts);
  var formattedAi = formatAiMessage(aiMsg);
  var $aiMsg = appendAiHistoryMessage(formattedAi, opts);
  $aiMsg.attr('data-original', aiMsg);
  // Settled history seeds its source from the known message data; the null
  // sequence means it never reports generating, however busy the tracker is.
  bindMessagePlaybackSource($aiMsg[0], { original: aiMsg, visible: '', boundSeq: null, finished: true });
}

function applyHistoryPage(data, mode) {
  var page = historyWindow.applyPage(data, mode);
  var pairs = page.pairs;
  var start = page.start;

  if (page.mode === 'prepend') {
    var chat = document.getElementById('chat-content');
    var prevHeight = chat ? chat.scrollHeight : 0;
    var prevTop = chat ? chat.scrollTop : 0;
    var frag = document.createDocumentFragment();
    for (var i = 0; i < pairs.length; i++) {
      appendHistoryPair(pairs[i][0], pairs[i][1], start + i, {
        fragment: frag,
        thumbnail: true,
        skipScroll: true
      });
    }
    var bar = ensureLoadOlderBar();
    var before = bar && bar.nextSibling ? bar.nextSibling : (chat ? chat.firstChild : null);
    if (chat) chat.insertBefore(frag, before);
    if (chat) chat.scrollTop = prevTop + (chat.scrollHeight - prevHeight);
    startDeferredThumbs(chat, false);
    updateLoadOlderBar();
    return;
  }

  var $chat = $('#chat-content');
  // Replacing the page detaches every bubble; finish the live stream source
  // so its queue completes instead of following the detached stream.
  if (liveStreamPlaybackSource) liveStreamPlaybackSource.finish();
  liveStreamPlaybackSource = null;
  $chat.empty();
  ensureLoadOlderBar();
  for (var j = 0; j < pairs.length; j++) {
    appendHistoryPair(pairs[j][0], pairs[j][1], start + j, { thumbnail: true, deferSrc: true });
  }
  updateLoadOlderBar();
  setTimeout(function() {
    scrollToBottom();
    startDeferredThumbs(document.getElementById('chat-content'), true);
  }, 0);
}

function loadOlderMessages() {
  if (!window.APP_DATA || !window.APP_DATA.loggedIn) return;
  var req = historyWindow.beginOlderLoad({
    setId: window.APP_DATA.lastSetId,
    setName: window.APP_DATA.lastSet
  });
  if (!req) return;
  updateLoadOlderBar();
  var before = req.before;
  var gen = req.gen;
  var setId = req.setId;
  var setName = req.setName;
  withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
    return fetch('/load_set', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({
        set_id: setId,
        set_name: setName,
        limit: req.limit,
        before: before,
        thumbnails: true
      })
    });
  }).then(function(r) {
    if (r.status === 401) return handle401OrRetry(r, function() { return Promise.reject(new Error('unauthorized')); });
    if (!r.ok) throw new Error('Failed to load older messages');
    return r.json();
  }).then(function(data) {
    if (!historyWindow.isLiveGen(gen)) return;
    noteSetVersionFromRead(data);
    applyHistoryPage(data, 'prepend');
  }).catch(function(err) {
    console.error('Failed to load older messages:', err);
  }).then(function() {
    historyWindow.noteOlderSettled();
    updateLoadOlderBar();
  });
}

function sizeEditTextarea(textarea) {
  if (!textarea) return;
  // Grow with content (capped) so long multiline messages are usable while editing.
  textarea.style.height = 'auto';
  var minPx = 140;
  var maxPx = 420;
  var next = Math.max(minPx, Math.min(maxPx, textarea.scrollHeight));
  textarea.style.height = next + 'px';
}

function ensureImageLightbox() {
  let $overlay = $('#image-lightbox');
  if ($overlay.length) return $overlay;
  $overlay = $(
    '<div id="image-lightbox" class="image-lightbox" hidden role="dialog" aria-modal="true" aria-label="Expanded image">' +
      '<button type="button" class="image-lightbox-close" aria-label="Close">&times;</button>' +
      '<img class="image-lightbox-img" alt="Expanded attachment">' +
    '</div>'
  );
  $('body').append($overlay);
  $overlay.on('click', function(e) {
    // Close when clicking backdrop or the close control; ignore clicks on the image itself.
    if (e.target === this || $(e.target).closest('.image-lightbox-close').length) {
      closeImageLightbox();
    }
  });
  return $overlay;
}

function sanitizeLightboxSrc(src) {
  return chatRenderer.sanitizeLightboxSrc(src);
}

function openImageLightbox(src) {
  // src may come from img.getAttribute('src') (DOM text). Only assign a
  // reconstructed data:image URL or same-origin /history_image/... path
  // (CodeQL js/xss-through-dom).
  const safeSrc = sanitizeLightboxSrc(src);
  if (!safeSrc) return;
  const $overlay = ensureImageLightbox();
  $overlay.find('.image-lightbox-img').attr('src', safeSrc);
  $overlay.removeAttr('hidden').addClass('is-open');
  document.body.classList.add('image-lightbox-open');
}

function closeImageLightbox() {
  const $overlay = $('#image-lightbox');
  if (!$overlay.length) return;
  $overlay.removeClass('is-open').attr('hidden', true);
  $overlay.find('.image-lightbox-img').removeAttr('src');
  document.body.classList.remove('image-lightbox-open');
}

// Native-only attach: never jQuery .append(value) with a caller-controlled value.
// jQuery treats strings as HTML (CodeQL js/xss-through-dom); appendChild does not.
function replaceChildrenNative(parent, node) {
  if (!parent) return;
  while (parent.firstChild) parent.removeChild(parent.firstChild);
  if (node) parent.appendChild(node);
}

// Append a message to the chat content.
//
// Content rules (CodeQL — never feed DOM/exception text into HTML sinks):
// - user-message: plain wire text (optional [IMAGE:data:...] tag)
// - system-message / error-message: plain text scalar only (textContent)
// - ai-message: streaming shell only — history HTML uses appendAiHistoryMessage
function appendMessage(message, className, pairIndex, mountOpts) {
  const $messageElement = $('<div>').addClass('message ' + className);
  const host = $messageElement[0];
  const isUser = className && className.indexOf('user-message') !== -1;
  const isAi = className && className.indexOf('ai-message') !== -1;
  const asThumbnail = !!(mountOpts && mountOpts.thumbnail);

  if (isUser) {
    let originalText = message;
    // Wire format is plain text; some legacy callers may still pass display HTML
    // with a leading <strong>You:</strong> label. Strip only that known prefix
    // with string ops — never assign the message to innerHTML (CodeQL js/xss-through-dom).
    if (typeof message === 'string' && /^\s*<strong>\s*You:\s*<\/strong>/i.test(message)) {
      originalText = message
        .replace(/^\s*<strong>\s*You:\s*<\/strong>\s*/i, '')
        .replace(/^\s*You:\s*/, '')
        .trim();
    }

    // Handle image attachments [IMAGE:data:...] or deferred [IMAGE:] markers.
    const parsed = parseUserMessageContent(originalText);
    let displaySrc = parsed.imageSrc;
    if (!displaySrc && parsed.deferred && pairIndex != null
        && window.APP_DATA && window.APP_DATA.loggedIn) {
      displaySrc = asThumbnail
        ? historyThumbUrl(pairIndex, 0)
        : historyImageUrl(pairIndex, 0);
    }
    replaceChildrenNative(host, buildUserMessageSpan(parsed.text, displaySrc, {
      pairIndex: pairIndex,
      thumbnail: asThumbnail,
      deferSrc: !!(mountOpts && mountOpts.deferSrc && displaySrc)
    }));
    // Wire-format plain text only (not HTML); setAttribute does not parse markup.
    host.setAttribute('data-original', composeUserMessageContent(
      parsed.text, displaySrc, parsed.hasImage || parsed.deferred
    ));
    if (asThumbnail) host.setAttribute('data-thumb', '1');
  } else if (isAi) {
    // Stream shell only — never accept bodyHtml here (exception text also enters
    // appendMessage via error-message calls; keep that param off the HTML path).
    replaceChildrenNative(host, buildAiStreamChildren());
  } else {
    // system-message / error-message: textContent path only (scalar string)
    replaceChildrenNative(host, buildStatusMessageContent(className, message));
  }

  if (typeof pairIndex !== 'undefined' && pairIndex !== null) {
    host.setAttribute('data-pair-index', String(pairIndex));
  }

  if (isUser) {
    try {
      const deleteContainer = document.createElement('div');
      deleteContainer.className = 'regenerate-container';

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'edit-button';
      editBtn.title = 'Edit message';
      const editIcon = document.createElement('i');
      editIcon.className = 'bi bi-pencil-fill';
      editBtn.appendChild(editIcon);

      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'delete-button';
      deleteBtn.title = 'Delete message';
      const delWrap = document.createElement('span');
      delWrap.className = 'delete-icon';
      const delIcon = document.createElement('i');
      delIcon.className = 'bi bi-trash-fill';
      delWrap.appendChild(delIcon);
      deleteBtn.appendChild(delWrap);

      const branchBtn = document.createElement('button');
      branchBtn.type = 'button';
      branchBtn.className = 'branch-button';
      branchBtn.title = 'Branch from here';
      branchBtn.setAttribute('aria-label', 'Branch conversation from here');
      const branchIcon = document.createElement('i');
      branchIcon.className = 'bi bi-diagram-2';
      branchBtn.appendChild(branchIcon);

      deleteContainer.appendChild(editBtn);
      deleteContainer.appendChild(branchBtn);
      deleteContainer.appendChild(deleteBtn);
      host.appendChild(deleteContainer);
    } catch (e) { console.debug('Failed to add buttons:', e); }
  }

  mountChatMessage(host, mountOpts);
  return $messageElement;
}

// Request fencing and aborts (static/conversation-state.js): single owner
// of the sequence and the live AbortController.
var chatRequests = ChatConversationState.createChatRequestTracker();

function beginChatRequest() {
  var seq = chatRequests.begin();
  setGeneratingState(true);
  return seq;
}

function isLiveChatRequest(seq) {
  return chatRequests.isLive(seq);
}

function finishChatRequest(seq) {
  if (!chatRequests.finish(seq)) return false;
  syncSendButtonState();
  return true;
}

function isVoiceTtsActive() {
  return voiceLifecycle.isTtsActive();
}

function syncSendButtonState() {
  const generating = chatRequests.isGenerating();
  const voiceTts = !!window.voiceModeActive && isVoiceTtsActive();
  setGeneratingState(generating || voiceTts);
}

function abortChatRequestQuietly() {
  chatRequests.abortQuietly();
}

function fetchWithGenerateRetry(url, init, attempt, afterRefresh) {
  return sessionClient.fetchWithGenerateRetry(url, init, attempt, afterRefresh);
}

function setGeneratingState(isGenerating) {
  const $btn = $('#send-button');
  if (isGenerating) {
    $btn.removeClass('btn-outline-primary').addClass('btn-danger').text('Stop').addClass('is-generating');
  } else {
    $btn.removeClass('btn-danger').addClass('btn-outline-primary').text('Send').removeClass('is-generating');
  }
}

function handleStopClick() {
  if (typeof window.stopAllTtsPlayback === 'function') {
    window.stopAllTtsPlayback();
  }
  chatRequests.stopForUser();
  syncSendButtonState();
}

// Sanitize raw markdown text for TTS: strip URLs, citations, code blocks, and formatting
function sanitizeForTTS(text) {
  return ChatVoiceText.sanitizeForTTS(text);
}

// Per-message TTS playback sources, keyed by AI message host. Stream sites
// publish the strings they render; begin/finish/cancel/failure sites bind
// or settle against the request-tracker sequence. No progress is inferred
// from buttons or rendered text; the adapter observer stays a text-change
// wakeup backstop only.
var messagePlaybackSources = new WeakMap();
var liveStreamPlaybackSource = null;

function messagePlaybackSourceDeps(boundSeq) {
  return {
    sanitize: function (text) { return sanitizeForTTS(text); },
    isTrackerGenerating: function () { return chatRequests.isGenerating(); },
    isTrackerLive: function (s) { return chatRequests.isLive(s); },
    boundSeq: boundSeq
  };
}

// Bind a host to a sequence, ending any prior source so replaced sessions
// do not leak.
function bindMessagePlaybackSource(hostEl, site) {
  site = site || {};
  var prev = hostEl ? messagePlaybackSources.get(hostEl) : null;
  if (prev) prev.finish();
  var source = ChatPlaybackSource.createMessageSource(
    messagePlaybackSourceDeps(site.boundSeq != null ? site.boundSeq : null));
  source.publish({ original: site.original || '', fallbackVisible: site.visible || '' });
  if (site.finished) source.finish();
  if (hostEl) messagePlaybackSources.set(hostEl, source);
  return source;
}

// Migrate a host's source to a replacement generation in one atomic restart.
function retargetMessagePlaybackSource(hostEl, seq) {
  var source = hostEl ? messagePlaybackSources.get(hostEl) : null;
  if (!source) return bindMessagePlaybackSource(hostEl, { original: '', visible: '', boundSeq: seq });
  source.retarget(seq, { original: '', fallbackVisible: '' });
  return source;
}

function lookupMessagePlaybackSource(hostEl) {
  var source = hostEl ? messagePlaybackSources.get(hostEl) : null;
  if (source) return source;
  // Every AI bubble with a play button is bound at its creation site; a
  // missing entry plays silent instead of inferring from the DOM.
  var silent = ChatPlaybackSource.createMessageSource(messagePlaybackSourceDeps(null));
  silent.finish();
  return silent;
}

// Text event from a producing/updating site; drops when nothing is bound.
function publishMessagePlaybackText($messageElement, original, visible) {
  var host = $messageElement && $messageElement[0];
  var source = host && messagePlaybackSources.get(host);
  if (source) source.publish({ original: original || '', fallbackVisible: visible || '' });
}

// Terminal progress event; text is kept so queued sentences drain.
function finishMessagePlayback($messageElement) {
  var host = $messageElement && $messageElement[0];
  var source = host && messagePlaybackSources.get(host);
  if (source) source.finish();
  if (liveStreamPlaybackSource === source) liveStreamPlaybackSource = null;
}

// Canonical wire shape for data-original and source publishes alike.
function combinedAiOriginal(fullVisibleText, fullThinkingText) {
  return fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : '');
}

/**
 * Plain text for an element matching TreeWalker / Range offset math.
 * Must use textContent (NOT innerText): innerText inserts layout newlines
 * that do not exist in text nodes, which desyncs highlight ranges and TTS.
 */
function getDomPlainText(element) {
  return element ? (element.textContent || '') : '';
}

/**
 * Speakable-complete trailing fragment while generation continues.
 * Owned by static/voice-text.js; desktop/native discover share it here.
 */
function sentenceEndsWithTerminator(sentenceText) {
  return ChatVoiceText.sentenceEndsWithTerminator(sentenceText);
}



/**
 * Split plain text into sentences ({start, end, text}[]).
 * Owned by static/voice-text.js; hover, click-to-play and voice-mode
 * discover share it through this adapter. Do NOT sanitize before
 * splitting (sanitize changes boundaries).
 */
function splitSentences(text) {
  return ChatVoiceText.splitSentences(text);
}


/** Index of the sentence containing caret offset, or -1. */
function sentenceIndexAtOffset(sentences, offset) {
  return ChatVoiceText.sentenceIndexAtOffset(sentences, offset);
}

/**
 * Character offset within element's textContent at a client point.
 * Uses the same text-node walk as createRangeFromTextOffsets.
 */
function getCaretOffsetInElement(element, clientX, clientY) {
  if (!element) return null;
  let caretNode = null;
  let caretOffset = 0;

  if (document.caretRangeFromPoint) {
    const range = document.caretRangeFromPoint(clientX, clientY);
    if (range && element.contains(range.startContainer)) {
      caretNode = range.startContainer;
      caretOffset = range.startOffset;
    }
  } else if (document.caretPositionFromPoint) {
    const pos = document.caretPositionFromPoint(clientX, clientY);
    if (pos && pos.offsetNode && element.contains(pos.offsetNode)) {
      caretNode = pos.offsetNode;
      caretOffset = pos.offset;
    }
  }
  if (!caretNode) return null;

  // If caret is on an element node, map to a nearby text node.
  if (caretNode.nodeType !== Node.TEXT_NODE) {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
    let best = null;
    let bestDist = Infinity;
    let t;
    while ((t = walker.nextNode())) {
      const r = document.createRange();
      r.selectNodeContents(t);
      const rects = r.getClientRects();
      for (let i = 0; i < rects.length; i++) {
        const rect = rects[i];
        const cx = Math.max(rect.left, Math.min(clientX, rect.right));
        const cy = Math.max(rect.top, Math.min(clientY, rect.bottom));
        const dist = (cx - clientX) * (cx - clientX) + (cy - clientY) * (cy - clientY);
        if (dist < bestDist) {
          bestDist = dist;
          best = t;
        }
      }
    }
    if (!best) return null;
    caretNode = best;
    // Binary search offset within that text node by geometry.
    const len = best.nodeValue ? best.nodeValue.length : 0;
    let lo = 0;
    let hi = len;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      const pr = document.createRange();
      pr.setStart(best, 0);
      pr.setEnd(best, mid);
      const br = pr.getBoundingClientRect();
      if (br.right < clientX) lo = mid + 1;
      else hi = mid;
    }
    caretOffset = lo;
  }

  // Sum lengths of all text nodes before caretNode, plus caretOffset.
  // This matches textContent / TreeWalker offsets exactly.
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
  let total = 0;
  let node;
  while ((node = walker.nextNode())) {
    if (node === caretNode) {
      return total + Math.min(Math.max(0, caretOffset), (node.nodeValue || '').length);
    }
    total += node.nodeValue ? node.nodeValue.length : 0;
  }
  return null;
}

/** Build a DOM Range covering [start, end) textContent offsets inside element. */
function createRangeFromTextOffsets(element, start, end) {
  if (!element || start == null || end == null || end <= start) return null;
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
  let pos = 0;
  let startNode = null;
  let startOff = 0;
  let endNode = null;
  let endOff = 0;
  let lastNode = null;
  let node;
  while ((node = walker.nextNode())) {
    const len = node.nodeValue ? node.nodeValue.length : 0;
    lastNode = node;
    if (len === 0) continue;
    if (startNode === null && pos + len >= start) {
      startNode = node;
      startOff = start - pos;
    }
    if (startNode !== null && pos + len >= end) {
      endNode = node;
      endOff = end - pos;
      break;
    }
    pos += len;
  }
  if (!startNode) return null;
  if (!endNode) {
    if (!lastNode) return null;
    endNode = lastNode;
    endOff = (lastNode.nodeValue || '').length;
  }
  const range = document.createRange();
  try {
    range.setStart(startNode, Math.min(Math.max(0, startOff), (startNode.nodeValue || '').length));
    range.setEnd(endNode, Math.min(Math.max(0, endOff), (endNode.nodeValue || '').length));
  } catch (e) {
    return null;
  }
  return range;
}

function clearTtsHoverHighlight() {
  document.querySelectorAll('.tts-sentence-highlight, .tts-hover-play-icon').forEach(function (el) {
    el.remove();
  });
}

function clearMessageTtsPlayingUi() {
  document.querySelectorAll('.ai-message-text.tts-is-playing').forEach(function (el) {
    el.classList.remove('tts-is-playing');
  });
  document.querySelectorAll('.message.tts-is-playing').forEach(function (el) {
    el.classList.remove('tts-is-playing');
  });
}

/** Highlight the sentence under the caret. Returns the sentence record or null. */
function highlightSentenceInElement(element, text, caretOffset, isPlaying) {
  clearTtsHoverHighlight();
  if (!element || !text) return null;
  const sentences = splitSentences(text);
  const idx = sentenceIndexAtOffset(sentences, caretOffset);
  if (idx < 0) return null;
  const sentence = sentences[idx];
  if (!sentence || sentence.end <= sentence.start) return null;

  const range = createRangeFromTextOffsets(element, sentence.start, sentence.end);
  if (!range) return null;

  const rects = range.getClientRects();
  let firstRect = null;
  for (let i = 0; i < rects.length; i++) {
    const rect = rects[i];
    if (rect.width < 1 || rect.height < 1) continue;
    if (!firstRect) firstRect = rect;
    const div = document.createElement('div');
    div.className = 'tts-sentence-highlight' + (isPlaying ? ' tts-sentence-highlight-playing' : '');
    div.setAttribute('aria-hidden', 'true');
    div.style.left = rect.left + 'px';
    div.style.top = rect.top + 'px';
    div.style.width = rect.width + 'px';
    div.style.height = rect.height + 'px';
    document.body.appendChild(div);
  }
  if (firstRect) {
    const badge = document.createElement('div');
    badge.className = 'tts-hover-play-icon' + (isPlaying ? ' is-stop' : '');
    badge.setAttribute('aria-hidden', 'true');
    badge.innerHTML = ttHtml(isPlaying
      ? '<i class="bi bi-stop-fill"></i>'
      : '<i class="bi bi-play-fill"></i>');
    const badgeSize = 22;
    badge.style.left = Math.max(0, firstRect.left - badgeSize - 4) + 'px';
    badge.style.top = (firstRect.top + (firstRect.height - badgeSize) / 2) + 'px';
    document.body.appendChild(badge);
  }
  return sentence;
}

// Desktop clip fetch/preload live in the owned TTS playback unit using the
// single voice lifecycle + voice-text; explicit HTTP/audio adapters above.
function fetchDesktopTtsClip(sessionId, text) {
  return desktopTtsClip.fetchClip(sessionId, text);
}

function preloadDesktopTtsSentence(sessionId, text) {
  return desktopTtsClip.preloadSentence(sessionId, text);
}

/**
 * Fetch one TTS token and play it on the shared HTMLAudioElement.
 * Owned by static/tts-playback.js via the shared desktop clip pipeline;
 * thin adapter preserves the call site.
 */
function playOneTtsUtterance(sessionId, text) {
  return desktopTtsClip.playOne(sessionId, text);
}

/**
 * Play a fixed list of sentences (click-a-sentence path).
 * Sentences are already split from DOM text; we only sanitize per item for the API.
 */
/**
 * Play a fixed list of sentences (click-a-sentence path).
 * Owned by static/tts-playback.js; DOM/event composition stays here via
 * explicit progress callbacks (visible text is already split; queue owns
 * retries/backoff/termination exactly).
 */
function playFixedSentenceList(sessionId, button, sentences) {
  return ChatTtsPlayback.playFixedSentenceList({
    isLive: function (id) { return desktopTtsIsLive(id); },
    onComplete: function (btn) { completeDesktopTtsPlayback(btn); },
    preload: function (id, text) { preloadDesktopTtsSentence(id, text); },
    playOne: function (id, text) { return playOneTtsUtterance(id, text); },
    reportVoice: function (kind, msg) { reportVoice(kind, msg); },
    appendMessage: function (text, cls) { appendMessage(text, cls); },
    logError: function () { console.error.apply(console, arguments); },
    setTimeout: function (fn, ms) { return setTimeout(fn, ms); },
    isVoiceModeActive: function () { return !!window.voiceModeActive; }
  }, sessionId, button, sentences);
}


/**
 * Play from message body (play button). Supports streaming generation.
 */
function playMessageBodyTts(sessionId, button, $messageElement) {
  // Streaming desktop queue lives in static/tts-playback.js using the single
  // voice lifecycle + voice-text. Answer text/progress arrive via the shared
  // per-message source bound at this message's creation/update/settle sites;
  // this adapter only looks the source up by message host. The
  // MutationObserver below stays solely as a text-change wakeup backstop for
  // the queue (existing latency behavior) and never supplies progress.
  var textEl = $messageElement.find('.ai-message-text')[0];
  var source = lookupMessagePlaybackSource($messageElement[0]);
  return ChatTtsPlayback.playMessageBodyTts({
    isLive: function (id) { return desktopTtsIsLive(id); },
    onComplete: function (btn) { completeDesktopTtsPlayback(btn); },
    source: source,
    split: function (text) { return splitSentences(text); },
    terminator: function (text) { return sentenceEndsWithTerminator(text); },
    preload: function (id, text) { preloadDesktopTtsSentence(id, text); },
    playOne: function (id, text) { return playOneTtsUtterance(id, text); },
    reportVoice: function (kind, msg) { reportVoice(kind, msg); },
    appendMessage: function (text, cls) { appendMessage(text, cls); },
    logError: function () { console.error.apply(console, arguments); },
    setTimeout: function (fn, ms) { return setTimeout(fn, ms); },
    clearTimeout: function (id) { clearTimeout(id); },
    isVoiceModeActive: function () { return !!window.voiceModeActive; },
    observeChanges: function (onChange) {
      if (textEl && typeof MutationObserver === 'function') {
        var obs = new MutationObserver(function () { onChange(); });
        obs.observe(textEl, { childList: true, subtree: true, characterData: true });
        return function () { try { obs.disconnect(); } catch (e) { /* ignore */ } };
      }
      return null;
    }
  }, sessionId, button);
}

/**
 * Play TTS for an AI message.
 * options.sentences — string[] already split from the clicked DOM sentence onward.
 *   When provided, those exact strings are spoken in order (highlight === audio).
 * Without options: speak full message from data-original / DOM (play button).
 */
window.playTTS = function playTTS(button, options) {
  if (window.nativeVoiceTtsAvailable && window.NativeVoiceTts
      && typeof window.playNativeVoiceModeTts === 'function') {
    window.playNativeVoiceModeTts(button, options);
    return;
  }
  options = options || {};

  // Toggle stop when this control is already the active speaker.
  if (voiceLifecycle.isCurrentButton(button)) {
    if (typeof window.stopAllTtsPlayback === 'function') {
      window.stopAllTtsPlayback();
    } else {
      stopCurrentDesktopTts();
    }
    return;
  }

  // Always fully reset before starting so 2nd/3rd play cannot inherit dead state.
  stopCurrentDesktopTts();

  // Prime HTMLAudio inside this call stack (user click) before any fetch.
  // Without this, only the first play after reload tends to work.
  primeDesktopTtsAudioFromGesture();

  const $messageElement = $(button).closest('.message');
  // stopCurrentDesktopTts bumped the session; this play owns the new value.
  const sessionId = voiceLifecycle.beginDesktopPlayback(button, function () {
    if (voiceSttAbortController) {
      try { voiceSttAbortController.abort(); } catch (e) { /* ignore */ }
      voiceSttAbortController = null;
    }
  });

  $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
  $messageElement.addClass('tts-is-playing');
  $messageElement.find('.ai-message-text').addClass('tts-is-playing');

  if (options.sentences && options.sentences.length) {
    playFixedSentenceList(sessionId, button, options.sentences);
    return;
  }
  playMessageBodyTts(sessionId, button, $messageElement);
}

window.playTTSVoiceMode = function playTTSVoiceMode(button, options) {
  if (window.nativeVoiceTtsAvailable && window.NativeVoiceTts
      && typeof window.playNativeVoiceModeTts === 'function') {
    window.playNativeVoiceModeTts(button, options);
    return;
  }
  window.playTTS(button, options);
};

/** Voice mode uses the same playTTS / HTML Audio path as the play button. */
function playMessageTts(button, options) {
  if (window.nativeVoiceTtsAvailable && window.NativeVoiceTts
      && typeof window.playNativeVoiceModeTts === 'function') {
    window.playNativeVoiceModeTts(button, options);
    return;
  }
  if (window.voiceModeActive && typeof window.playTTSVoiceMode === 'function') {
    window.playTTSVoiceMode(button, options);
    return;
  }
  window.playTTS(button, options);
}
window.playMessageTts = playMessageTts;

window.regenerateMessage = function regenerateMessage(button) {
  if (window.APP_DATA && (window.APP_DATA.autoplayTTS || window.voiceModeActive)) {
    primeDesktopTtsAudioFromGesture();
  }
  const $aiMessageElement = $(button).closest('.message');
  const $previousUserMessage = $aiMessageElement.prev('.message.user-message');
  if ($previousUserMessage.length === 0) return;
  let userText = ($previousUserMessage.attr('data-original') || ($previousUserMessage.find('.user-message-text').text() || $previousUserMessage.text() || '').replace(/^\s*You:\s*/, '')).trim();
  // Ghost (never-saved) turns resend via /chat; only saved turns regenerate.
  if (ChatConversationState.resolveRegenerateAction($previousUserMessage.attr('data-local-only') === '1') === 'resend-chat') {
    if (typeof window.sendMessage === 'function') {
      window.sendMessage({ reuseLastUser: true, message: userText });
    }
    return;
  }
  const pairIndex = liveUserPairIndex($previousUserMessage);
  if (pairIndex < 0) return;
  const needsFull = $previousUserMessage.attr('data-thumb') === '1' || /\[IMAGE:/.test(userText);
  if (needsFull && window.APP_DATA && window.APP_DATA.loggedIn) {
    fetchHistoryPair(pairIndex).then(function(full) {
      if (full && full.user) userText = full.user;
      window.performRegeneration($aiMessageElement[0], userText, pairIndex);
    }).catch(function() {
      window.performRegeneration($aiMessageElement[0], userText, pairIndex);
    });
    return;
  }
  window.performRegeneration($aiMessageElement[0], userText, pairIndex);
};

window.performRegeneration = function performRegeneration(aiMessageElement, userText, pairIndex, opts) {
  opts = opts || {};
  const $target = $(aiMessageElement);
  $target.removeAttr('data-original');
  replaceChildrenNative($target[0], buildAiStreamChildren());

if (window.APP_DATA.autoplayTTS || window.voiceModeActive) {
    const playBtn = $target.find('.play-button')[0];
    if (playBtn) setTimeout(() => playMessageTts(playBtn), 50);
  }

  const seq = beginChatRequest();
  // Same bubble, replacement generation: migrate its playback source so an
  // active queue continues seamlessly into the new text, and autoplay finds
  // the fresh sequence.
  liveStreamPlaybackSource = retargetMessagePlaybackSource($target[0], seq);

  fetchWithGenerateRetry('/regenerate', {
    method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }),
    signal: chatRequests.signal(),
    body: JSON.stringify(activeSetPayload({
      message: userText,
      system_prompt: $('#user-system-prompt').val(),
      model_name: $('#modelSelect').val(),
      pair_index: pairIndex,
      web_search: $('#web-search-toggle').hasClass('btn-primary'),
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    }))
  })
  .then(response => {
    if (response.status === 401) { redirectHomeOnAuthFailure(); throw new Error('Session expired'); }
    if (!response.ok) {
      return response.text().then(t => {
        let errData = null;
        try { errData = t ? JSON.parse(t) : null; } catch (e) { errData = null; }
        if (errData && errData.error === 'version_conflict' && isLiveChatRequest(seq)) {
          // Adopt the authoritative version and replay the regeneration once.
          noteSetVersionFromResponse(errData);
          if (ChatConversationState.shouldRetryVersionOnce(opts.versionRetried)) {
            return window.performRegeneration(aiMessageElement, userText, pairIndex, { versionRetried: true });
          }
          throw new Error('Chat state changed elsewhere; please try again.');
        }
        throw new Error(apiErrorText(t, 'Network response was not ok'));
      });
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    const $msgText = $target.find('.ai-message-text');
    const $thinkingWrap = $target.find('.thinking-container');
    const $thinkingContent = $target.find('.thinking-content');
    // Regenerate adapter: no console stripping, no EOF flush (residual is
    // dropped; console detail stays visible).
    const streamState = ChatStreamDecoder.createStreamState();
    let hasWrittenToDOM = false;
    let fullVisibleText = '';
    let fullThinkingText = '';
    let wasSearching = false;
    let wasRateLimited = false;

    function appendVisible(content) {
      if (!content) return;
      fullVisibleText += content;
      $msgText.html(renderMarkdown(fullVisibleText));
      hasWrittenToDOM = true;
      if (wasSearching) {
          const $toggle = $target.find('.toggle-thinking');
          if ($target.find('.thinking-content').css('display') === 'none') {
             $toggle.html('<i class="bi bi-caret-right-fill"></i> Search completed.');
          }
      } else if (wasRateLimited) {
          const $toggle = $target.find('.toggle-thinking');
          if ($target.find('.thinking-content').css('display') === 'none') {
             $toggle.html('<i class="bi bi-caret-right-fill"></i> Show Thinking');
          }
      }
      $target.attr('data-original', combinedAiOriginal(fullVisibleText, fullThinkingText));
      publishMessagePlaybackText($target, combinedAiOriginal(fullVisibleText, fullThinkingText), fullVisibleText);
    }
    function appendThinking(content) {
      if (!content) return;
      fullThinkingText += content;
      $thinkingWrap.show();
      const $toggle = $thinkingWrap.find('.toggle-thinking');
      $toggle.show();

      if (!wasSearching && (content.includes('Searching') || content.includes('web search'))) {
          wasSearching = true;
          if ($target.find('.thinking-content').css('display') === 'none') {
             $toggle.html('<i class="bi bi-caret-right-fill"></i> Searching the web...');
          }
      }

      if (content.toLowerCase().includes('rate limited')) {
          wasRateLimited = true;
          if ($target.find('.thinking-content').css('display') === 'none') {
             $toggle.html('<i class="bi bi-caret-right-fill"></i> Rate limited — retrying...');
          }
      }

      $thinkingContent.text(fullThinkingText);
      if (!hasWrittenToDOM) { $msgText.text(''); hasWrittenToDOM = true; }
      $target.attr('data-original', combinedAiOriginal(fullVisibleText, fullThinkingText));
      publishMessagePlaybackText($target, combinedAiOriginal(fullVisibleText, fullThinkingText), fullVisibleText);
    }
    function processBuffer(chunk) {
      ChatStreamDecoder.pushChunk(streamState, chunk, {
        onVisible: appendVisible,
        onThinking: appendThinking,
        stripConsoleDetail: false
      });
    }
            function read() {
          reader.read().then(({done, value}) => {
            if (done) {
              // Regenerate does not flush: the residual stays dropped.
              const finalAiOriginal = combinedAiOriginal(fullVisibleText, fullThinkingText);
              $target.attr('data-original', finalAiOriginal);
              
              try {
                $target.find('.regenerate-button').prop('disabled', false);
                const playBtn = $target.find('.play-button').prop('disabled', false);
                if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
              } catch (e) {}
              finishChatRequest(seq);
              finishMessagePlayback($target);
              var $regenUser = $target.prev('.message.user-message');
              clearLocalOnlyTurn($regenUser, $target);
              noteLocalVersionBumpAfterPersist();
              if (typeof loadSets === 'function') loadSets(false);
              return;
            }
            const chunk = decoder.decode(value, {stream:true});
            const nearBottom = shouldStickChatToBottom();
            processBuffer(chunk);
            if (nearBottom) {
              scrollToBottom();
            }
            read();
          }).catch(err => {
            if (!isLiveChatRequest(seq)) return;
            try {
              $target.find('.regenerate-button').prop('disabled', false);
              const playBtn = $target.find('.play-button').prop('disabled', false);
              if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            finishChatRequest(seq);
            finishMessagePlayback($target);
          });
        }
        read();
      })
      .catch(err => {
        if (!isLiveChatRequest(seq)) return;
        if (err.name === 'AbortError') {
          $target.find('.ai-message-text').append(' [Stopped]');
        } else {
          // Dedicated builder: exception text → textContent only (js/xss-through-exception).
          replaceChildrenNative($target[0], buildAiErrorChildren(err.message));
        }
        try {
          $target.find('.regenerate-button').prop('disabled', false);
          const playBtn = $target.find('.play-button').prop('disabled', false);
          if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
        } catch (e) {}
        finishChatRequest(seq);
        // The [Stopped] suffix lives in visible DOM only; the source keeps
        // the last published original, so it is never spoken. Error chrome
        // likewise keeps the last published partial text.
        finishMessagePlayback($target);
      });
};

function handleDeleteMessage(buttonElement, isRetry) {
  const deleteBtn = $(buttonElement);
  const userMessageElement = deleteBtn.closest('.message.user-message');
  if (userMessageElement.length === 0) return;

  const aiMessageElement = userMessageElement.next('.ai-message');
  if (userMessageElement.attr('data-local-only') === '1' || isLocalOnlyTurn(userMessageElement)) {
    removeLocalOnlyTurn(userMessageElement);
    return;
  }
  if (aiMessageElement.length === 0) {
    removeLocalOnlyTurn(userMessageElement);
    return;
  }

  const userText = (userMessageElement.attr('data-original') || userMessageElement.find('.user-message-text').text() || userMessageElement.text() || '').replace(/^\s*You:\s*/, '').trim();
  if (!userText) {
    console.error('Cannot delete: missing message text');
    return;
  }

  // Live DOM order is the source of truth after local deletes. Stale
  // data-pair-index from load_set caused every delete after the first to 409.
  const pairIndex = liveUserPairIndex(userMessageElement);
  if (pairIndex < 0) {
    console.error('Cannot delete: could not resolve pair index');
    return;
  }
  userMessageElement.attr('data-pair-index', String(pairIndex));

  console.debug('Deleting message pair:', { pairIndex, userTextLen: userText.length, isRetry: !!isRetry });

  // Server matches pair_index + user_message only (ai_message is ignored). Do not
  // send aiText — image-bearing user_message alone can approach the body limit.
  fetch('/delete_message', {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(activeSetPayload({
      pair_index: pairIndex,
      user_message: userText
    }))
  })
  .then(r => {
    if (r.status === 401) { redirectHomeOnAuthFailure(); return null; }
    return r.json().then(data => ({ ok: r.ok, status: r.status, data }));
  })
  .then(result => {
    if (!result) return;
    if (result.data && result.data.error === 'version_conflict') {
      applySetVersion(result.data.current_version, result.data.set_id, { allowRewind: true });
      if (ChatConversationState.shouldRetryVersionOnce(isRetry)) {
        return handleDeleteMessage(buttonElement, true);
      }
      return handleVersionConflict(null, result.data);
    }
    if (result.status === 409) {
      const mismatch = result.data && /content mismatch/i.test(String(result.data.error || ''));
      if (mismatch) {
        reindexUserPairIndices();
        if (!isRetry) {
          return handleDeleteMessage(buttonElement, true);
        }
        var users = document.querySelectorAll('#chat-content .message.user-message');
        var isLast = users.length && users[users.length - 1] === userMessageElement[0];
        if (isLast) {
          removeLocalOnlyTurn(userMessageElement);
          return;
        }
      }
      const errMsg = (result.data && result.data.error) || 'delete conflict';
      console.error('Server failed to delete message:', errMsg);
      appendMessage('Failed to delete message: ' + errMsg, 'error-message');
      return;
    }
    if (result.ok && result.data && result.data.status === 'success') {
      noteSetVersionFromResponse(result.data);
      aiMessageElement.remove();
      userMessageElement.remove();
      historyWindow.noteDeletedPersisted();
      reindexUserPairIndices();
      updateLoadOlderBar();
      return;
    }
    const errMsg = (result.data && result.data.error) || `delete failed (${result.status})`;
    if (result.status === 404 || (errMsg && /out of range/i.test(errMsg))) {
      // Pair was never saved server-side (failed/stopped AI response) and only
      // existed client-side in the DOM. Remove it locally without error.
      aiMessageElement.remove();
      userMessageElement.remove();
      reindexUserPairIndices();
      console.debug('Removed client-side-only message pair (server reported out of range)');
      return;
    }
    console.error('Server failed to delete message:', errMsg);
    appendMessage('Failed to delete message: ' + errMsg, 'error-message');
  })
  .catch(err => {
    console.error('Error deleting message:', err);
    appendMessage('Failed to delete message: ' + (err && err.message ? err.message : String(err)), 'error-message');
  });
}

// Fork the conversation at a user turn: copies history up to and including
// that pair into a new chat and switches to it. Source stays untouched.
function handleForkMessage(buttonElement, isRetry) {
  const $user = $(buttonElement).closest('.message.user-message');
  if (!$user.length) return;
  // Only saved turns can be branched; ghost turns must send first.
  if (!ChatConversationState.canForkTurn(ChatConversationState.isGhostTurn({
    attrLocalOnly: $user.attr('data-local-only'),
    computedLocalOnly: isLocalOnlyTurn($user)
  }))) {
    appendMessage('Send this message first — only saved turns can be branched.', 'error-message');
    return;
  }
  const pairIndex = liveUserPairIndex($user);
  if (pairIndex < 0) return;
  const $btn = $(buttonElement).prop('disabled', true);
  fetch('/fork_set', {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(activeSetPayload({ pair_index: pairIndex }))
  })
  .then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })))
  .then(result => {
    if (result.data && result.data.error === 'version_conflict') {
      applySetVersion(result.data.current_version, result.data.set_id, { allowRewind: true });
      if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return handleForkMessage(buttonElement, true);
      return handleVersionConflict(null, result.data);
    }
    if (result.ok && result.data && result.data.status === 'success') {
      window.APP_DATA.lastSetId = result.data.set_id;
      window.APP_DATA.lastSet = result.data.name;
      if (typeof loadSets === 'function') {
        loadSets(false).then(function() {
          $('#set-selector').val(result.data.set_id);
          $('#set-selector').trigger('change');
        });
      }
      appendMessage('Branched to ' + (result.data.name || 'new chat') + '.', 'system-message');
      return;
    }
    const errMsg = (result.data && (result.data.error || result.data.message)) || ('fork failed (' + result.status + ')');
    appendMessage('Failed to branch: ' + errMsg, 'error-message');
  })
  .catch(err => {
    appendMessage('Failed to branch: ' + (err && err.message ? err.message : String(err)), 'error-message');
  })
  .then(function() { $btn.prop('disabled', false); });
}

// Long press logic for delete button
let deleteTimer = null;
const LONG_PRESS_DURATION = 800;

$(document).on('mousedown touchstart', '.delete-button', function(e) {
  // Only left click or touch
  if (e.type === 'mousedown' && e.which !== 1) return;
  
  const $btn = $(this);
  clearTimeout(deleteTimer);
  $btn.removeClass('long-pressing');
  
  // Force a reflow if needed, or just add class
  // Using setTimeout(0) helps with some transition quirks but direct add is usually fine
  $btn.addClass('long-pressing');
  
  deleteTimer = setTimeout(() => {
    $btn.removeClass('long-pressing');
    // Vibrate if supported
    if (navigator.vibrate) navigator.vibrate(50);
    handleDeleteMessage($btn[0]);
  }, LONG_PRESS_DURATION);
});

$(document).on('mouseup touchend mouseleave touchcancel touchmove', '.delete-button', function(e) {
  const $btn = $(this);
  clearTimeout(deleteTimer);
  if ($btn.hasClass('long-pressing')) {
    $btn.removeClass('long-pressing');
  }
});

$(document).on('click', '.delete-button', function(e) {
  e.preventDefault();
  e.stopPropagation();
});

// Main ready block
$(document).ready(function() {
  $('#reload-ui').on('click', function() {
    if (window._recoverNativeVoice) {
      window._recoverNativeVoice().finally(function () {
        window.location.reload();
      });
      return;
    }
    window.location.reload();
  });

  disablePremiumModels();
  updateSearchToggleVisibility();

  // Initialize checkboxes
  if (window.APP_DATA) {
    $('#check-save-thoughts').prop('checked', window.APP_DATA.saveThoughts);
    $('#check-send-thoughts').prop('checked', window.APP_DATA.sendThoughts);
    $('#check-render-markdown').prop('checked', window.APP_DATA.renderMarkdown);
    $('#check-autoplay-tts').prop('checked', window.APP_DATA.autoplayTTS);
  }

  // Image attachment handling
  let pendingImageData = null;
  let pendingImagePreview = null;

  $('#attach-button').on('click', function() {
    $('#image-input').trigger('click');
  });

  $('#image-input').on('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      appendMessage('Please select an image file.', 'error-message');
      return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
      const imgData = sanitizeDataImageSrc(event.target.result);
      if (!imgData) {
        appendMessage('Could not read image file.', 'error-message');
        $('#image-input').val('');
        return;
      }
      pendingImageData = imgData;

      // Show preview in the UI
      const $preview = $('<div class="image-preview-container" style="position: relative; display: inline-block; margin: 5px 0;"></div>');
      const $img = $('<img>').attr('src', imgData).css({'max-width': '200px', 'max-height': '150px', 'border-radius': '8px', 'border': '1px solid #444'});
      const $removeBtn = $('<button class="btn btn-sm btn-danger" style="position: absolute; top: -8px; right: -8px; border-radius: 50%; width: 24px; height: 24px; padding: 0; line-height: 24px;">&times;</button>');
      $preview.append($img).append($removeBtn);

      // Remove existing preview if any
      $('#image-preview').remove();
      pendingImagePreview = $preview;

      // Insert preview before the input group
      $('#chat-area .input-group').before($preview);

      $removeBtn.on('click', function() {
        pendingImageData = null;
        pendingImagePreview = null;
        $preview.remove();
        $('#image-input').val('');
      });
    };
    reader.readAsDataURL(file);
  });

  // Validate model tier on selection change (replacing inline onchange)
  $('#modelSelect').on('change', function() {
      validateModelTier();
      savePreferences();
  });

  $('#check-autoplay-tts').on('change', function() {
    window.APP_DATA.autoplayTTS = $(this).is(':checked');
    savePreferences();
  });

  $('#check-render-markdown').on('change', function() {
    window.APP_DATA.renderMarkdown = $(this).is(':checked');
    savePreferences();
    // Re-render all AI messages
    $('.ai-message').each(function() {
      const $msgText = $(this).find('.ai-message-text');
      const $thinkingContent = $(this).find('.thinking-content');
      
      // We need the original text. We don't store it explicitly in the DOM for AI messages 
      // currently in a clean way without parsing thinking tags again.
      // For now, let's just trigger a reload of the current set to re-render everything
      // as that's the most reliable way without adding more data attributes.
    });
    $('#set-selector').trigger('change');
  });

  // Restore last model if available
  if (window.APP_DATA.lastModel) {
      const $modelSelect = $('#modelSelect');
      if ($modelSelect.find(`option[value="${window.APP_DATA.lastModel}"]`).length > 0) {
          $modelSelect.val(window.APP_DATA.lastModel);
          previousModel = window.APP_DATA.lastModel;
          validateModelTier();
      }
  }

  function savePreferences() {
      if (!window.APP_DATA.loggedIn) return;
      
      const currentModel = $('#modelSelect').val();
      const currentSet = $('#set-selector').val();
      const renderMarkdown = $('#check-render-markdown').is(':checked');
      const autoplayTTS = $('#check-autoplay-tts').is(':checked');

      window.APP_DATA.lastModel = currentModel;
      window.APP_DATA.lastSet = currentSet;
      window.APP_DATA.renderMarkdown = renderMarkdown;
      window.APP_DATA.autoplayTTS = autoplayTTS;

      const preferences = {
          last_model: currentModel,
          last_set: currentSet,
          render_markdown: renderMarkdown,
          autoplay_tts: autoplayTTS,
          web_search: window.APP_DATA.webSearch,
          voice_mode: window.APP_DATA.voiceMode
      };

      withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
          return fetch('/update_preferences', {
              method: 'POST',
              headers: headers,
              body: JSON.stringify(preferences)
          });
      }).catch(err => console.debug('Failed to save preferences:', err));
  }

  // Scroll to bottom button logic
  const $chatContent = $('#chat-content');
  const $scrollToBottomBtn = $('#scroll-to-bottom');

  $chatContent.on('scroll', function() {
    if (lastChatScrollTop !== null && this.scrollTop < lastChatScrollTop) {
      chatScrollGeneration++;
    }
    lastChatScrollTop = this.scrollTop;
    if (isAtBottom()) {
      $scrollToBottomBtn.fadeOut(200);
    } else if ($scrollToBottomBtn.is(':hidden')) {
      $scrollToBottomBtn.css('display', 'flex').hide().fadeIn(200);
    }
    if (this.scrollTop < 80) {
      loadOlderMessages();
    }
  });

  $scrollToBottomBtn.on('click', function() {
    scrollToBottom();
  });

  // Expand chat image attachments to full size. Thumbs use a GET /history_image
  // URL so the browser/WebView HTTP cache handles repeat views.
  $(document).on('click', 'img.chat-image', function(e) {
    e.preventDefault();
    e.stopPropagation();
    const img = this;
    const thumb = img.getAttribute('data-thumb') === '1';
    const pairIndex = img.getAttribute('data-pair-index');
    if (thumb && pairIndex != null && window.APP_DATA && window.APP_DATA.loggedIn) {
      openImageLightbox(historyImageUrl(Number(pairIndex), 0));
      return;
    }
    openImageLightbox(img.getAttribute('src'));
  });
  $(document).on('keydown', function(e) {
    if (e.key === 'Escape' && $('#image-lightbox').hasClass('is-open')) {
      closeImageLightbox();
    }
  });

  // Speak-from-sentence:
  // - hover: highlight sentence under pointer (same splitSentences as play)
  // - click: recompute sentence from click coords ONLY (never stale hover text)
  // - while playing this message: click stops
  let ttsTextMouseDown = null;
  let ttsHoverRaf = null;

  function refreshTtsHoverAtPoint(el, clientX, clientY) {
    if (!el || !el.classList.contains('ai-message-text')) {
      clearTtsHoverHighlight();
      return;
    }
    if (ttsTextMouseDown && ttsTextMouseDown.el === el) {
      const dx = Math.abs(clientX - ttsTextMouseDown.x);
      const dy = Math.abs(clientY - ttsTextMouseDown.y);
      if (dx > 4 || dy > 4) {
        clearTtsHoverHighlight();
        el.classList.remove('tts-can-play');
        return;
      }
    }
    const offset = getCaretOffsetInElement(el, clientX, clientY);
    if (offset == null) {
      clearTtsHoverHighlight();
      el.classList.remove('tts-can-play');
      return;
    }
    const domText = getDomPlainText(el);
    if (!domText.trim() || domText.trim() === 'Thinking...') {
      clearTtsHoverHighlight();
      el.classList.remove('tts-can-play');
      return;
    }
    const isPlaying = voiceLifecycle.isCurrentButton($(el).closest('.message').find('.play-button')[0]);
    el.classList.add('tts-can-play');
    el.setAttribute(
      'title',
      isPlaying ? 'Click to stop speech' : 'Click to speak from this sentence'
    );
    highlightSentenceInElement(el, domText, offset, isPlaying);
  }

  $(document).on('mousedown', '.ai-message-text', function (e) {
    if (e.button !== 0) return;
    ttsTextMouseDown = { x: e.clientX, y: e.clientY, el: this };
  });
  $(document).on('mouseup', function () {
    setTimeout(function () { ttsTextMouseDown = null; }, 0);
  });

  $(document).on('mousemove', '.ai-message-text', function (e) {
    const el = this;
    const clientX = e.clientX;
    const clientY = e.clientY;
    if (ttsHoverRaf) cancelAnimationFrame(ttsHoverRaf);
    ttsHoverRaf = requestAnimationFrame(function () {
      ttsHoverRaf = null;
      refreshTtsHoverAtPoint(el, clientX, clientY);
    });
  });

  $(document).on('mouseleave', '.ai-message-text', function () {
    if (ttsHoverRaf) {
      cancelAnimationFrame(ttsHoverRaf);
      ttsHoverRaf = null;
    }
    this.classList.remove('tts-can-play');
    if (voiceLifecycle.isCurrentButton($(this).closest('.message').find('.play-button')[0])) {
      this.setAttribute('title', 'Click to stop speech');
    } else {
      this.removeAttribute('title');
    }
    clearTtsHoverHighlight();
  });

  $('#chat-content').on('scroll', function () {
    clearTtsHoverHighlight();
  });

  $(document).on('click', '.ai-message-text', function (e) {
    // Ignore 2nd/3rd events of a double/triple click (word/paragraph select).
    if (e.detail !== 1) return;
    if (e.target.closest && e.target.closest('a, button, .copy-code-button, input, textarea, pre code')) {
      return;
    }
    // Ignore drag-selects (moved pointer between mousedown and click).
    if (ttsTextMouseDown) {
      const dx = Math.abs(e.clientX - ttsTextMouseDown.x);
      const dy = Math.abs(e.clientY - ttsTextMouseDown.y);
      if (dx > 5 || dy > 5) return;
    }

    const textEl = this;
    const $message = $(textEl).closest('.message.ai-message');
    if (!$message.length) return;
    const playBtn = $message.find('.play-button')[0];
    if (!playBtn) return;

    // While this message is speaking: click always stops (do not start another).
    if (voiceLifecycle.isCurrentButton(playBtn)) {
      clearTtsHoverHighlight();
      if (typeof window.stopAllTtsPlayback === 'function') {
        window.stopAllTtsPlayback();
      } else {
        stopCurrentDesktopTts();
      }
      return;
    }

    // Resolve the sentence from the click coordinates only — never from hover cache.
    const offset = getCaretOffsetInElement(textEl, e.clientX, e.clientY);
    if (offset == null) return;
    const domText = getDomPlainText(textEl);
    if (!domText.trim() || domText.trim() === 'Thinking...') return;

    const sentences = splitSentences(domText);
    const idx = sentenceIndexAtOffset(sentences, offset);
    if (idx < 0) return;

    // Exact DOM sentence strings from the click point through the end.
    // Sanitize happens later per utterance inside playOneTtsUtterance.
    const toPlay = [];
    for (let i = idx; i < sentences.length; i++) {
      const t = sentences[i].text;
      if (t && t.trim()) toPlay.push(t);
    }
    if (!toPlay.length) return;

    clearTtsHoverHighlight();
    playMessageTts(playBtn, { sentences: toPlay });
  });

  // Delegation for play, delete, and edit
  $(document).on('click', function(event) {
    const target = event.target;
    const playBtn = target.closest && target.closest('.play-button');
    if (playBtn) {
      playMessageTts(playBtn);
      return;
    }

    const removeEditImageBtn = target.closest && target.closest('.remove-edit-image');
    if (removeEditImageBtn) {
      const $messageElement = $(removeEditImageBtn).closest('.message.user-message');
      $messageElement.data('editImageSrc', null);
      $(removeEditImageBtn).closest('.edit-image-preview').remove();
      return;
    }

    const editBtn = target.closest && target.closest('.edit-button');
    if (editBtn) {
      const $messageElement = $(editBtn).closest('.message.user-message');
      const $textSpan = $messageElement.find('.user-message-text');
      const originalText = $messageElement.attr('data-original') || $textSpan.text().replace(/^You:\s*/, '').trim();

      if ($messageElement.find('.edit-message-container').length > 0) return;

      // Text only in the textarea; keep base64 image out of the input for performance.
      const parsed = parseUserMessageContent(originalText);
      let editSafeSrc = sanitizeDataImageSrc(parsed.imageSrc);
      if (!editSafeSrc && parsed.deferred && window.APP_DATA && window.APP_DATA.loggedIn) {
        const idx = liveUserPairIndex($messageElement);
        if (idx >= 0) editSafeSrc = historyThumbUrl(idx, 0);
      }
      $messageElement.data('editImageSrc', editSafeSrc);

      const $editContainer = $('<div>').addClass('edit-message-container');
      if (editSafeSrc) {
        const $imgPreview = $('<div>').addClass('edit-image-preview');
        const $img = $('<img>')
          .addClass('edit-image-thumb')
          .attr('src', editSafeSrc)
          .attr('alt', 'Attached image')
          .attr('title', 'Attached image (kept when you save)');
        const $removeImg = $('<button type="button" class="btn btn-sm btn-danger remove-edit-image" title="Remove image">&times;</button>');
        $imgPreview.append($img).append($removeImg);
        $editContainer.append($imgPreview);
      }

      const $textarea = $('<textarea>')
        .addClass('edit-textarea form-control')
        .attr('rows', 8)
        .attr('placeholder', 'Edit message…')
        .val(parsed.text);
      const $actions = $('<div>').addClass('edit-actions mt-2');
      const $saveBtn = $('<button type="button">').addClass('btn btn-sm btn-primary save-edit').text('Save');
      const $cancelBtn = $('<button type="button">').addClass('btn btn-sm btn-secondary cancel-edit ms-2').text('Cancel');

      $actions.append($saveBtn).append($cancelBtn);
      $editContainer.append($textarea).append($actions);
      $textSpan.hide();
      $messageElement.find('.regenerate-container').hide();
      $messageElement.prepend($editContainer);
      sizeEditTextarea($textarea[0]);
      $textarea.on('input', function() { sizeEditTextarea(this); });
      $textarea.focus();
      return;
    }

    const saveEditBtn = target.closest && target.closest('.save-edit');
    if (saveEditBtn) {
      const $messageElement = $(saveEditBtn).closest('.message.user-message');
      const textOnly = $messageElement.find('.edit-textarea').val();
      // jQuery .data() returns undefined if never set; null means user removed the image.
      const rawEditSrc = $messageElement.data('editImageSrc');
      const imageSrc = sanitizeDataImageSrc(rawEditSrc)
        || sanitizeLightboxSrc(rawEditSrc)
        || null;
      const newText = composeUserMessageContent(textOnly, imageSrc);
      if (!newText) return;

      const pairIndex = liveUserPairIndex($messageElement);
      if (pairIndex < 0) return;

      const finishEdit = function(finalText) {
        const saved = parseUserMessageContent(finalText);
        $messageElement.attr('data-original', finalText);
        $messageElement.find('.user-message-text').replaceWith(buildUserMessageSpan(saved.text, saved.imageSrc, {
          pairIndex: pairIndex,
          thumbnail: $messageElement.attr('data-thumb') === '1'
        }));
        $messageElement.find('.edit-message-container').remove();
        $messageElement.removeData('editImageSrc');
        $messageElement.find('.regenerate-container').show();

        const $aiMessageElement = $messageElement.next('.message.ai-message');
        if ($aiMessageElement.length > 0) {
          window.performRegeneration($aiMessageElement[0], finalText, pairIndex);
        }
      };

      if (imageSrc && window.APP_DATA && window.APP_DATA.loggedIn && $messageElement.attr('data-thumb') === '1') {
        fetchHistoryPair(pairIndex).then(function(full) {
          const storedImg = full && parseUserMessageContent(full.user).imageSrc;
          finishEdit(composeUserMessageContent(textOnly, storedImg || imageSrc));
        }).catch(function() {
          finishEdit(newText);
        });
        return;
      }

      finishEdit(newText);
      return;
    }

    const cancelEditBtn = target.closest && target.closest('.cancel-edit');
    if (cancelEditBtn) {
      const $messageElement = $(cancelEditBtn).closest('.message.user-message');
      $messageElement.find('.edit-message-container').remove();
      $messageElement.removeData('editImageSrc');
      $messageElement.find('.user-message-text').show();
      $messageElement.find('.regenerate-container').show();
      return;
    }
  });

  // Delegated handlers replacing inline onclicks
  $(document).on('click', '.regenerate-button', function() { window.regenerateMessage(this); });
  $(document).on('click', '.branch-button', function() { handleForkMessage(this, false); });
  $(document).on('click', '.toggle-thinking', function() { window.toggleThinking(this); });

  // Copy code block logic
  $(document).on('click', '.copy-code-button', function() {
    const $btn = $(this);
    const $container = $btn.closest('.code-block-container');
    const code = $container.find('pre code').text();
    const originalHtml = $btn.html();

    copyToClipboard(code).then(function() {
      $btn.addClass('copied').html('<i class="bi bi-check2"></i>');
      setTimeout(function() {
        if ($btn.is(':visible')) {
          $btn.removeClass('copied').html(originalHtml);
        }
      }, 2000);
    }).catch(function(err) {
      console.error('Failed to copy code:', err);
      $btn.addClass('copy-failed').html('<i class="bi bi-x-lg"></i>').attr('title', 'Copy failed — select and copy manually');
      setTimeout(function() {
        if ($btn.is(':visible')) {
          $btn.removeClass('copy-failed').html(originalHtml).attr('title', 'Copy to clipboard');
        }
      }, 2000);
    });
  });

  // Load sets for logged-in users (HttpOnly enc_key cookie is sent automatically)
  if (window.APP_DATA.loggedIn) {
    function loadSets(shouldTriggerChange = true) {
      async function fetchSets() {
        return fetch('/get_sets', { headers: await withCsrfAsync() });
      }
      return fetchSets()
        .then(function(r) {
          if (r.status === 401) {
            return handle401OrRetry(r, fetchSets);
          }
          return r;
        })
        .then(async function(r) {
          if (r.status === 401) {
            var msg = await response401Message(r);
            throw new Error(msg || 'Unauthorized');
          }
          if (!r.ok) {
            throw new Error('Failed to load sets');
          }
          return r.json();
        })
        .then(data => {
          if (!Array.isArray(data)) {
            throw new Error('Unexpected sets response');
          }
          const $selector = $('#set-selector');
          $selector.empty();
          let setExists = false;
          let preferredId = window.APP_DATA.lastSetId || null;
          let preferredName = window.APP_DATA.lastSet || null;
          $.each(data, function(_, setInfo) {
            const setName = setInfo.name;
            const setId = setInfo.set_id || setName;
            const $opt = $('<option>')
              .val(setId)
              .text(setName)
              .attr('data-name', setName)
              .attr('data-version', setInfo.version != null ? setInfo.version : '');
            $opt.appendTo($selector);
            if (preferredId && setId === preferredId) setExists = true;
            else if (!preferredId && preferredName && setName === preferredName) {
              setExists = true;
              preferredId = setId;
            }
          });
          
          if (setExists && preferredId) {
              $selector.val(preferredId);
          } else if (preferredName || preferredId) {
              console.debug('Last set not found, falling back to default');
          }

          // Sync setVersion from the selected option, but never rewind a version
          // we already observed (in-flight get_sets after delete/chat persist).
          const $selectedOpt = $selector.find('option:selected');
          if ($selectedOpt.length) {
            applySetVersion($selectedOpt.attr('data-version'), $selectedOpt.val());
          }

          if (shouldTriggerChange) {
            $selector.trigger('change');
          }
        })
        .catch(function(error) {
          console.error('Failed to load sets:', error);
          appendSetsLoadError(error && error.message ? error.message : String(error));
          throw error;
        });
    }

    window.loadChatSets = loadSets;

    $('#set-selector').on('change', function() {
      const $opt = $(this).find('option:selected');
      const setId = $(this).val();
      const setName = $opt.attr('data-name') || setId;
      // Rewind-safe sync: a genuine set switch adopts the new set's version;
      // same-set refreshes never rewind below a version we already observed.
      const rawVersion = $opt.attr('data-version');
      if (rawVersion != null && rawVersion !== '') {
        applySetVersion(rawVersion, setId);
      } else {
        window.APP_DATA.setVersion = null;
      }
      window.APP_DATA.lastSetId = setId;
      window.APP_DATA.lastSet = setName;
      var loadGen = historyWindow.beginSetLoad();
      savePreferences();
      function fetchSet() {
        return withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
          return fetch('/load_set', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
              set_id: setId,
              set_name: setName,
              limit: historyWindow.getPageSize(),
              thumbnails: true
            })
          });
        });
      }
      fetchSet()
        .then(async r => {
          if (r.status === 401) {
            r = await handle401OrRetry(r, fetchSet);
          }
          if (r.status === 401) {
            var msg = await response401Message(r);
            throw new Error(msg || 'Unauthorized');
          }
          if (!r.ok) {
            try { const err = await r.json(); throw new Error(err && (err.error || err.message) || 'Failed to load set'); }
            catch (_) { throw new Error('Failed to load set'); }
          }
          return r;
        })
        .then(r => r.json())
        .then(data => {
          if (!historyWindow.isLiveGen(loadGen)) return;
          if (data.name) window.APP_DATA.lastSet = data.name;
          noteSetVersionFromResponse(data);
          if (data.name) $opt.attr('data-name', data.name).text(data.name);
          $('#user-system-prompt').val(data.system_prompt || '');
          $('#user-memory').val(data.memory || '');
          applyHistoryPage(data, 'replace');
          appendMessage('Loaded set: ' + setName, 'system-message');
        })
        .catch(error => { appendMessage('Failed to load set: ' + (error && error.message ? error.message : String(error)), 'error-message'); });
      });

    beginEncKeyUnlockFlow();
    $('#enc-key-retry').on('click', function() {
      try { sessionStorage.removeItem(ENC_GATE_RELOADS_KEY); } catch (e) {}
      beginEncKeyUnlockFlow(true);
    });

    $('#new-set').on('click', function() {
      // One click: server assigns `New Chat` / `New Chat 2` and renames it
      // from the first message. Rename button still covers manual names.
      fetch('/create_set', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({}) })
        .then(r => r.json())
        .then(data => {
          if (data.status === 'success') {
            const newId = data.set_id;
            window.APP_DATA.lastSetId = newId;
            window.APP_DATA.lastSet = data.name || 'New Chat';
            loadSets(false).then(() => {
              if (newId) $('#set-selector').val(newId);
              $('#set-selector').trigger('change');
            });
            appendMessage('Created new set: ' + (data.name || 'New Chat'), 'system-message');
          } else {
            appendMessage(data.error || 'Failed to create set', 'error-message');
          }
        });
    });

    $('#rename-set').on('click', function() {
      const $opt = $('#set-selector option:selected');
      const setId = $('#set-selector').val();
      const oldName = $opt.attr('data-name') || setId;
      if (oldName === 'default' || $opt.attr('data-name') === 'default') {
        appendMessage('Cannot rename default set', 'error-message');
        return;
      }
      const newName = prompt('Enter new name for set:', oldName);
      if (newName && newName !== oldName) {
        submitRenameSet(setId, oldName, newName, false);
      }
    });

    function submitRenameSet(setId, oldName, newName, isRetry) {
      fetch('/rename_set', {
        method: 'POST',
        headers: withCsrf({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          set_id: setId,
          old_name: oldName,
          new_name: newName,
          expected_version: window.APP_DATA.setVersion != null ? Number(window.APP_DATA.setVersion) : undefined
        })
      })
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          window.APP_DATA.lastSet = newName;
          window.APP_DATA.lastSetId = data.set_id || setId;
          noteSetVersionFromResponse(data);
          loadSets(false).then(() => {
            $('#set-selector').val(window.APP_DATA.lastSetId);
            appendMessage('Renamed set to: ' + newName, 'system-message');
          });
        } else if (data.error === 'version_conflict') {
          noteSetVersionFromResponse(data);
          if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return submitRenameSet(setId, oldName, newName, true);
          appendMessage('The chat was updated elsewhere. Please try renaming again.', 'error-message');
        } else {
          appendMessage(data.error || 'Failed to rename set', 'error-message');
        }
      })
      .catch(err => {
        appendMessage(err && err.message ? err.message : String(err), 'error-message');
      });
    }

    $('#delete-set').on('click', function() {
      const $opt = $('#set-selector option:selected');
      const setId = $('#set-selector').val();
      const setName = $opt.attr('data-name') || setId;
      if (setName === 'default') { appendMessage('Cannot delete default set', 'error-message'); return; }
      if (confirm('Are you sure you want to delete set: ' + setName + '?')) {
        submitDeleteSet(setId, setName, false);
      }
    });

    function submitDeleteSet(setId, setName, isRetry) {
      fetch('/delete_set', {
        method: 'POST',
        headers: withCsrf({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          set_id: setId,
          set_name: setName,
          expected_version: window.APP_DATA.setVersion != null ? Number(window.APP_DATA.setVersion) : undefined
        })
      })
        .then(r => r.json())
        .then(data => {
          if (data.status === 'success') { loadSets(); appendMessage('Deleted set: ' + setName, 'system-message'); }
          else if (data.error === 'version_conflict') {
            noteSetVersionFromResponse(data);
            if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return submitDeleteSet(setId, setName, true);
            appendMessage('The chat was updated elsewhere. Please try deleting again.', 'error-message');
          }
          else { appendMessage(data.error || 'Failed to delete set', 'error-message'); }
        })
        .catch(err => {
          appendMessage(err && err.message ? err.message : String(err), 'error-message');
        });
    }
  }

  function activeSetName() {
    const $opt = $('#set-selector option:selected');
    return $opt.attr('data-name') || $opt.text() || 'default';
  }

  // Save buttons
  function saveSystemPromptNow(sysPromptText, isRetry) {
    return fetch('/update_system_prompt', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(activeSetPayload({
        system_prompt: sysPromptText,
        logged_in: window.APP_DATA && window.APP_DATA.loggedIn
      }))
    })
      .then(function (r) {
        if (r.status === 401 && !isRetry) {
          return refreshSession().then(function (restored) {
            if (!restored) {
              redirectHomeOnAuthFailure();
              return null;
            }
            return saveSystemPromptNow(sysPromptText, true).then(function () { return null; });
          });
        }
        return r.json();
      })
      .then(data => {
        if (!data) return;
        if (data.status === 'success') {
          noteSetVersionFromResponse(data);
          appendMessage('System prompt saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          // Sync the authoritative version and retry once — e.g. a chat turn
          // finalized (or a prompt updated from another tab) since page load.
          noteSetVersionFromResponse(data);
          if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return saveSystemPromptNow(sysPromptText, true);
          appendMessage('The chat was updated elsewhere. Please try saving again.', 'error-message');
        }
        else appendMessage(data.error || 'Failed to save system prompt.', 'error-message');
      })
      .catch(error => { appendMessage(error && error.message ? error.message : String(error), 'error-message'); });
  }

  function saveMemoryNow(memText, isRetry) {
    return fetch('/update_memory', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(activeSetPayload({
        memory: memText,
        logged_in: window.APP_DATA && window.APP_DATA.loggedIn
      }))
    })
      .then(function (r) {
        if (r.status === 401 && !isRetry) {
          return refreshSession().then(function (restored) {
            if (!restored) {
              redirectHomeOnAuthFailure();
              return null;
            }
            return saveMemoryNow(memText, true).then(function () { return null; });
          });
        }
        return r.json();
      })
      .then(data => {
        if (!data) return;
        if (data.status === 'success') {
          noteSetVersionFromResponse(data);
          appendMessage('Memory saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          noteSetVersionFromResponse(data);
          if (ChatConversationState.shouldRetryVersionOnce(isRetry)) return saveMemoryNow(memText, true);
          appendMessage('The chat was updated elsewhere. Please try saving again.', 'error-message');
        }
        else appendMessage(data.error || 'Failed to save memory.', 'error-message');
      })
      .catch(error => { appendMessage(error && error.message ? error.message : String(error), 'error-message'); });
  }

  $('#save-system-prompt').on('click', function() {
    saveSystemPromptNow($('#user-system-prompt').val(), false);
  });

  $('#save-memory').on('click', function() {
    saveMemoryNow($('#user-memory').val(), false);
  });

  function sendMessage(opts) {
    opts = opts || {};
    if (window.APP_DATA && (window.APP_DATA.autoplayTTS || window.voiceModeActive)) {
      primeDesktopTtsAudioFromGesture();
    }
    const $systemPromptElement = $('#user-system-prompt');
    const $userInputElement = $('#user-input');
    if ($systemPromptElement.length === 0 || $userInputElement.length === 0) {
      appendMessage('Chat system not properly initialized. Please refresh the page.', 'error-message');
      return;
    }
    const message = (opts.message != null ? String(opts.message) : $userInputElement.val()).trim();
    if (!message && !pendingImageData) return;
    const systemPrompt = $systemPromptElement.val() || window.DEFAULT_SYSTEM_PROMPT;
    const activeSet = (typeof activeSetName === 'function' ? activeSetName() : ($('#set-selector option:selected').attr('data-name') || 'default'));

    // Same wire format as durable history: plain text + optional [IMAGE:data:...] tag.
    // appendMessage parses that tag into a preview <img> (same path as load_set).
    // Do not pre-build HTML with <img> here — textContent extraction would strip it and
    // leave no [IMAGE:...] tag to reconstruct, so the image only appeared after reload.
    // reuseLastUser retries already carry the composed text — do not append twice.
    let fullMessage = message;
    if (pendingImageData && !opts.reuseLastUser) {
      fullMessage = message + '\n[IMAGE:' + pendingImageData + ']';
    }

    const reuseLastUser = !!opts.reuseLastUser;
    let pairIndex;
    let $pendingUserMessage;
    if (reuseLastUser) {
      $pendingUserMessage = $('#chat-content .message.user-message').last();
      pairIndex = liveUserPairIndex($pendingUserMessage);
    } else {
      const $ghost = $('#chat-content .message.user-message').last();
      if (ChatConversationState.isGhostTurn({
        attrLocalOnly: $ghost.attr('data-local-only'),
        computedLocalOnly: false
      })) {
        removeLocalOnlyTurn($ghost);
      }
      pairIndex = ChatConversationState.userPairIndexForDomIndex(
        historyWindow.getOffset(),
        document.querySelectorAll('#chat-content .message.user-message').length);
      appendMessage(fullMessage, 'user-message', pairIndex);
      $pendingUserMessage = $('#chat-content .message.user-message').last();
    }

    const requestData = activeSetPayload({
      message: fullMessage,
      system_prompt: systemPrompt,
      model_name: $('#modelSelect').val(),
      web_search: $('#web-search-toggle').hasClass('btn-primary'),
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    });

    const seq = beginChatRequest();

    fetchWithGenerateRetry('/chat', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      signal: chatRequests.signal(),
      body: JSON.stringify(requestData)
    })
      .then(response => {
        if (response.status === 401) throw new Error(SESSION_EXPIRED_SEND_MSG);
        if (!response.ok) {
          return response.text().then(t => {
            let errData = null;
            try { errData = t ? JSON.parse(t) : null; } catch (e) { errData = null; }
            if (errData && errData.error === 'version_conflict' && isLiveChatRequest(seq)) {
              // Server rejected our stale version (e.g. the system prompt was
              // updated, or a turn finalized, elsewhere mid-flight). Adopt the
              // authoritative version and replay this turn once.
              noteSetVersionFromResponse(errData);
              if (ChatConversationState.shouldRetryVersionOnce(opts.versionRetried)) {
                return sendMessage({
                  reuseLastUser: true,
                  message: fullMessage,
                  versionRetried: true
                });
              }
              throw new Error('Chat state changed elsewhere; please try again.');
            }
            throw new Error(apiErrorText(t, 'Network response was not ok'));
          });
        }
        $userInputElement.val('');
        if (pendingImagePreview) {
          pendingImagePreview.remove();
          pendingImagePreview = null;
        }
        pendingImageData = null;
        $('#image-input').val('');
        if ($pendingUserMessage.length) $pendingUserMessage.removeAttr('data-local-only');
        return response;
      })
      .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        appendMessage(null, 'ai-message');

        const $targetElement = $('.ai-message:last-child');
        // Bind this bubble's playback source to the new request sequence
        // before any text streams or autoplay fires.
        liveStreamPlaybackSource = bindMessagePlaybackSource($targetElement[0], { original: '', visible: '', boundSeq: seq });

        if (window.APP_DATA.autoplayTTS || window.voiceModeActive) {
          const playBtn = $targetElement.find('.play-button')[0];
          if (playBtn) setTimeout(() => playMessageTts(playBtn), 50);
        }

        // Initial scroll to bottom when AI starts responding
        scrollToBottom();
        const $messageTextElement = $targetElement.find('.ai-message-text');
        const $thinkingContainerWrapper = $targetElement.find('.thinking-container');
        const $thinkingContentElement = $targetElement.find('.thinking-content');
        // Chat adapter: strips console detail to the console and flushes the
        // residual at EOF/interrupt.
        const streamState = ChatStreamDecoder.createStreamState();
        let hasWrittenToDOM = false;
        let fullVisibleText = '';
        let fullThinkingText = '';
        let wasSearching = false;
        let wasRateLimited = false;

        function appendVisible(content) {
          if (!content) return;
          fullVisibleText += content;
          $messageTextElement.html(renderMarkdown(fullVisibleText));
          hasWrittenToDOM = true;
          if (wasSearching) {
              const $toggle = $targetElement.find('.toggle-thinking');
              if ($targetElement.find('.thinking-content').css('display') === 'none') {
                 $toggle.html('<i class="bi bi-caret-right-fill"></i> Search completed.');
              }
          } else if (wasRateLimited) {
              const $toggle = $targetElement.find('.toggle-thinking');
              if ($targetElement.find('.thinking-content').css('display') === 'none') {
                 $toggle.html('<i class="bi bi-caret-right-fill"></i> Show Thinking');
              }
          }
          $targetElement.attr('data-original', combinedAiOriginal(fullVisibleText, fullThinkingText));
          publishMessagePlaybackText($targetElement, combinedAiOriginal(fullVisibleText, fullThinkingText), fullVisibleText);
        }
        function appendThinking(content) {
          if (!content) return;
          fullThinkingText += content;
          $thinkingContainerWrapper.show();
          const $toggle = $thinkingContainerWrapper.find('.toggle-thinking');
          $toggle.show();

          if (!wasSearching && (content.includes('Searching') || content.includes('web search'))) {
              wasSearching = true;
              if ($thinkingContentElement.css('display') === 'none') {
                 $toggle.html('<i class="bi bi-caret-right-fill"></i> Searching the web...');
              }
          }

          if (content.toLowerCase().includes('rate limited')) {
              wasRateLimited = true;
              if ($thinkingContentElement.css('display') === 'none') {
                 $toggle.html('<i class="bi bi-caret-right-fill"></i> Rate limited — retrying...');
              }
          }

          $thinkingContentElement.text(fullThinkingText);
          if (!hasWrittenToDOM) { $messageTextElement.text(''); hasWrittenToDOM = true; }
          $targetElement.attr('data-original', combinedAiOriginal(fullVisibleText, fullThinkingText));
          publishMessagePlaybackText($targetElement, combinedAiOriginal(fullVisibleText, fullThinkingText), fullVisibleText);
        }
        function processChunk(chunk) {
          ChatStreamDecoder.pushChunk(streamState, chunk, {
            onVisible: appendVisible,
            onThinking: appendThinking,
            stripConsoleDetail: true,
            onConsoleDetail(detail) { try { console.error(detail); } catch (e) {} }
          });
        }
        function flushStreamRemainder() {
          ChatStreamDecoder.flushRemainder(streamState, {
            onVisible: appendVisible,
            onThinking: appendThinking
          });
        }
        function readStream() {
          return reader.read().then(({ done, value }) => {
            if (done) {
              flushStreamRemainder();
              
              const finalAiOriginal = combinedAiOriginal(fullVisibleText, fullThinkingText);
              $targetElement.attr('data-original', finalAiOriginal);

              try {
                $targetElement.find('.regenerate-button').prop('disabled', false);
                const playBtn = $targetElement.find('.play-button').prop('disabled', false);
                if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
              } catch (e) {}
              finishChatRequest(seq);
              finishMessagePlayback($targetElement);
              historyWindow.noteChatPersisted(pairIndex);
              clearLocalOnlyTurn($pendingUserMessage, $targetElement);
              noteLocalVersionBumpAfterPersist();
              if (typeof loadSets === 'function') loadSets(false);
              return;
            }
            const chunk = decoder.decode(value, { stream: true });
            const nearBottom = shouldStickChatToBottom();
            processChunk(chunk);
            if (nearBottom) {
              scrollToBottom();
            }
            return readStream();
          }).catch(err => {
            if (!isLiveChatRequest(seq)) return;
            try {
              $targetElement.find('.regenerate-button').prop('disabled', false);
              const playBtn = $targetElement.find('.play-button').prop('disabled', false);
              if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            try { console.error('Stream read failed:', err); } catch (e) {}
            const errText = err && err.message ? err.message : String(err);
            flushStreamRemainder();
            appendVisible('\n[Error] The response stream was interrupted.');
            finishChatRequest(seq);
            finishMessagePlayback($targetElement);
          });
        }
        readStream();
      })
      .catch(error => {
        if (!isLiveChatRequest(seq)) return;
        try { console.error('Chat request failed:', error); } catch (e) {}
        if (error.name === 'AbortError') {
          const $lastAI = $('.ai-message:last-child');
          $lastAI.find('.ai-message-text').append(' [Stopped]');
          try {
            $lastAI.find('.regenerate-button').prop('disabled', false);
            const playBtn = $lastAI.find('.play-button').prop('disabled', false);
            if (!playBtn.is(voiceLifecycle.getCurrentButton())) playBtn.html('<i class="bi bi-play-fill"></i>');
          } catch (e) {}
          // Visible-only suffix; the source keeps the last published
          // original so it is never spoken.
          finishMessagePlayback($lastAI);
        } else {
          const errText = error && error.message ? error.message : String(error);
          if ($pendingUserMessage.length) {
            paintFailedAiTurn($pendingUserMessage, errText);
            if (window.voiceModeActive && !opts.voiceRetried) {
              sendMessage({
                reuseLastUser: true,
                message: fullMessage,
                voiceRetried: true
              });
              return;
            }
          } else {
            appendMessage(errText, 'error-message');
          }
        }
        finishChatRequest(seq);
      });
  }
  window.sendMessage = sendMessage;

  $('#user-input').on('keypress', function(e) { if (e.key === 'Enter') { e.preventDefault(); if (!$('#send-button').hasClass('is-generating')) sendMessage(); } });
  $('#send-button').on('click', function() {
    if ($(this).hasClass('is-generating')) {
      handleStopClick();
    } else {
      sendMessage();
    }
  });

  $('#reset-chat').on('click', function() {
    const setName = typeof activeSetName === 'function' ? activeSetName() : 'default';
    if (confirm(`Are you sure you want to reset the chat history for set: ${setName}?`)) {
      submitResetChat(false);
    }
  });

  // Web Search Toggle
  const $searchToggle = $('#web-search-toggle');
  $searchToggle.on('click', function() {
      const isActive = $(this).hasClass('btn-primary');
      if (isActive) {
          $(this).removeClass('btn-primary').addClass('btn-outline-secondary');
          $(this).attr('title', 'Web Search: OFF');
          window.APP_DATA.webSearch = false;
      } else {
          $(this).removeClass('btn-outline-secondary').addClass('btn-primary');
          $(this).attr('title', 'Web Search: ON');
          window.APP_DATA.webSearch = true;
      }
      persistWebSearchPref();
  });

  // Persist the web-search preference to the server (per-account) so it
  // survives refreshes and follows the user across devices.
  function persistWebSearchPref() {
      if (!window.APP_DATA || !window.APP_DATA.loggedIn) return;
      withCsrfAsync({ 'Content-Type': 'application/json' }).then(function (headers) {
          return fetch('/update_preferences', {
              method: 'POST',
              headers: headers,
              body: JSON.stringify({ web_search: window.APP_DATA.webSearch }),
          });
      }).catch(function (err) {
          console.debug('Failed to save web search preference:', err);
      });
  }

  // Microphone / STT
  const $micBtn = $('#mic-button');
  const useNativeMic = !!(window.NativeMic && window.NativeMic.isAvailable());
  const useBrowserMic = !useNativeMic && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;

  if (useNativeMic || useBrowserMic) {
    $micBtn.show();
  }

  let _nativeMicPcmChunks = []; // Int16Array chunks from NativeMic
  let _mediaRecorder = null;
  let _audioChunks = [];

  // Native mic push-to-talk
  if (useNativeMic) {
    let _nativeMicListener = null;

    $micBtn.on('click', function () {
      if ($micBtn.hasClass('recording')) {
        // Stop recording
        $micBtn.removeClass('recording').text('\u{1F399}').attr('title', 'Voice Input');

        if (_nativeMicListener) {
          _nativeMicListener.remove();
          _nativeMicListener = null;
        }

        window.NativeMic.stop().then(async function () {
          if (_nativeMicPcmChunks.length === 0) return;
          const pcm16 = NativeAudio.mergePcm16Chunks(_nativeMicPcmChunks);
          _nativeMicPcmChunks = [];

          const audioPayload = await NativeAudio.encodeAudioForStt(pcm16, NativeAudio.NATIVE_MIC_SAMPLE_RATE);
          nativeLog('VAD', 'STT push-to-talk encoded format=' + audioPayload.filename + ' bytes=' + audioPayload.blob.size);

          fetchVoiceRetry('/stt', function () {
            const retryForm = new FormData();
            retryForm.append('audio', audioPayload.blob, audioPayload.filename);
            return { method: 'POST', headers: withCsrf({}), body: retryForm };
          })
            .then(function (res) {
              return res.json();
            })
            .then(function (data) {
              const current = $('#user-input').val();
              const separator = current.trim() ? ' ' : '';
              $('#user-input').val(current + separator + (data.text || '')).focus();
            })
            .catch(function (err) {
              appendMessage(err && err.message ? err.message : String(err), 'error-message');
            });
        }).catch(function (err) {
          appendMessage(err && err.message ? err.message : String(err), 'error-message');
        });
        return;
      }

      // Start recording
      _nativeMicPcmChunks = [];

      window.NativeMic.requestPermission().then(function (result) {
        if (!result.granted) throw new Error('Microphone permission denied');
        _nativeMicListener = window.NativeMic.addListener('nativeMicData', function (data) {
          if (data && data.data) {
            _nativeMicPcmChunks.push(NativeAudio.decodeNativePcmBase64(data.data));
          }
        });
        return window.NativeMic.start();
      }).then(function () {
        $micBtn.addClass('recording').html('&#x23F9;').attr('title', 'Stop Recording');
      }).catch(function (err) {
        appendMessage('Microphone access denied: ' + (err && err.message ? err.message : String(err)), 'error-message');
      });
    });
  }

  // Browser mic push-to-talk (fallback)
  if (useBrowserMic) {
    $micBtn.on('click', function () {
      if (_mediaRecorder && _mediaRecorder.state === 'recording') {
        _mediaRecorder.stop();
        return;
      }

      navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
        _audioChunks = [];
        _mediaRecorder = new MediaRecorder(stream);

        _mediaRecorder.ondataavailable = function (e) {
          if (e.data.size > 0) _audioChunks.push(e.data);
        };

        _mediaRecorder.onstop = function () {
          stream.getTracks().forEach(function (t) { t.stop(); });

          $micBtn.removeClass('recording').text('\u{1F399}').attr('title', 'Voice Input');

          const blob = new Blob(_audioChunks, { type: _mediaRecorder.mimeType || 'audio/webm' });

          fetchVoiceRetry('/stt', function () {
            const retryForm = new FormData();
            retryForm.append('audio', blob, 'recording.webm');
            return { method: 'POST', headers: withCsrf({}), body: retryForm };
          })
            .then(function (res) {
              return res.json();
            })
            .then(function (data) {
              const current = $('#user-input').val();
              const separator = current.trim() ? ' ' : '';
              $('#user-input').val(current + separator + (data.text || '')).focus();
            })
            .catch(function (err) {
              appendMessage(err && err.message ? err.message : String(err), 'error-message');
            });
        };

        _mediaRecorder.start();
        $micBtn.addClass('recording').html('&#x23F9;').attr('title', 'Stop Recording');
      }).catch(function (err) {
        appendMessage('Microphone access denied: ' + (err && err.message ? err.message : String(err)), 'error-message');
      });
    });
  }

  // ── Voice Mode ─────────────────────────────────────────────────────────────
  const $voiceModeBtn = $('#voice-mode-btn');
  window.voiceModeActive = false;
  let voiceModeVAD = null;
  let voiceModeStream = null;
  let vadSttInProgress = false;
  let voiceModeSessionGeneration = 0;
  // Barge-in thresholds live in the owned voice lifecycle (top-level aliases
  // above); the VAD frame gate delegates via voiceLifecycle.noteFrameProcessed.
  const isMobile = /Mobi|Android/i.test(navigator.userAgent);
  // Native mic bridge for Voice Mode on Android
  let nativeMicBridge = null;
  let nativeMicStopPromise = null;

  const hasNativeMicVoice = window.nativeMicAvailable && isMobile && typeof vad !== 'undefined';
  if ((navigator.mediaDevices && navigator.mediaDevices.getUserMedia && typeof vad !== 'undefined') || hasNativeMicVoice) {
    $voiceModeBtn.show();
  }

  $voiceModeBtn.on('click', function () {
    if (window.voiceModeActive) {
      stopVoiceMode();
    } else {
      if (!isMobile) primeDesktopTtsAudioFromGesture();
      startVoiceMode();
    }
  });

  // Capacitor voice mode: native PCM VAD (not Silero; WebView AudioContext breaks during TTS).
  // Record at speech-like start (_beginUtterance). Stop TTS only in _maybeBargeIn
  // after REAL_SPEECH_MS of confirmed speech. Coughs/"hey" may start capture; they
  // must not barge in. Do not glue the gates.
  function ensureNativeMicPermission() {
    if (!window.NativeMic || typeof window.NativeMic.requestPermission !== 'function') {
      return Promise.resolve();
    }
    return window.NativeMic.requestPermission().then(function (result) {
      if (!result || !result.granted) {
        throw new Error('Microphone permission denied');
      }
    });
  }

  // Native capture lives in static/voice-capture.js (single owner of the
  // utterance state machine and the desktop Silero factory). Chat keeps
  // platform composition — the bridge pointer, the stop rendezvous, the
  // permission helper — and wires explicit adapters here. Every capture need
  // (audio thresholds, lifecycle gates, clock, log/report, recorder, bridge
  // registry) arrives as a named hook; thresholds and phase gates are
  // unchanged from shipped behavior.
  function createNativeVadHost() {
    return {
      nativeAudio: NativeAudio,
      voiceLifecycle: voiceLifecycle,
      now: function () { return Date.now(); },
      log: function (tag, msg) { nativeLog(tag, msg); },
      report: function (kind, msg) { reportVoice(kind, msg); },
      reportThrottled: function (key, windowMs, kind, msg) { reportVoiceThrottled(key, windowMs, kind, msg); },
      isVoiceModeActive: function () { return !!window.voiceModeActive; },
      onBargeIn: function () { handleBargeIn(); },
      onUtteranceEnd: function () { handleSpeechEnd(); },
      onUtteranceStartedAt: function (ts) { lastVoiceUtteranceStartedAt = ts; },
      recorder: {
        ensurePermission: function () { return ensureNativeMicPermission(); },
        start: function () { return window.NativeMic.start(); },
        stop: function () { return window.NativeMic.stop(); },
        addListener: function (eventName, callback) { return window.NativeMic.addListener(eventName, callback); }
      },
      registry: {
        isCurrent: function (inst) { return nativeMicBridge === inst; },
        getStopPromise: function () { return nativeMicStopPromise; },
        setStopPromise: function (promise) { nativeMicStopPromise = promise; }
      }
    };
  }

  function createDesktopVadHost() {
    return {
      vadLib: vad,
      log: function (tag, msg) { nativeLog(tag, msg); },
      voiceLifecycle: voiceLifecycle,
      onBargeIn: function () { handleBargeIn(); },
      onSpeechEnd: function (audio) { handleSpeechEnd(audio); },
      onSpeechStart: function () { lastVoiceUtteranceStartedAt = Date.now(); },
      isTtsActive: function () { return isVoiceTtsActive(); }
    };
  }

  function onVoiceModeTtsStarted() {
    voiceLifecycle.notePlaybackStarted();
    if (nativeMicBridge && nativeMicBridge.onTtsPlaybackStarted) {
      nativeMicBridge.onTtsPlaybackStarted();
    }
    nativeLog('VAD', 'TTS playback started');
  }

  function onVoiceModeTtsEnded() {
    voiceLifecycle.notePlaybackEnded();
    nativeLog('VAD', 'TTS playback ended');
  }

  window.notifyVoiceModeTtsStarted = onVoiceModeTtsStarted;
  window.notifyVoiceModeTtsEnded = onVoiceModeTtsEnded;

  let nativeVoiceTtsSessionListener = null;
  let nativeVoiceTtsSessionPromise = null;

  function nativeVoiceTtsStreamUrl(token) {
    return window.location.origin + '/tts_stream/' + encodeURIComponent(token);
  }

  function cancelNativeTtsToken(token) {
    if (!token) return Promise.resolve();
    return fetch('/tts_stream/' + encodeURIComponent(token), {
      method: 'DELETE',
      headers: withCsrf({}),
      keepalive: true
    }).catch(function () {});
  }

  function invalidateNativeVoiceTts() {
    voiceLifecycle.invalidateNativeSession();
    if (nativeVoiceTtsSessionListener) {
      const listener = nativeVoiceTtsSessionListener;
      nativeVoiceTtsSessionListener = null;
      Promise.resolve(listener).then(function (handle) {
        if (handle && typeof handle.remove === 'function') {
          handle.remove();
        }
      }).catch(function () {});
    }
    nativeVoiceTtsSessionPromise = null;
  }

  function finishNativeVoiceTts(generation, button) {
    voiceLifecycle.finishNativePlayback(generation, button, {
      onEnded: onVoiceModeTtsEnded,
      cleanup: function () {
        if (nativeVoiceTtsSessionListener) {
          const listener = nativeVoiceTtsSessionListener;
          nativeVoiceTtsSessionListener = null;
          Promise.resolve(listener).then(function (handle) {
            if (handle && typeof handle.remove === 'function') {
              handle.remove();
            }
          }).catch(function () {});
        }
        nativeVoiceTtsSessionPromise = null;
      }
    });
  }

  // Native sentence queue lives in static/tts-playback.js using the single
  // voice lifecycle + voice-text. DOM/event composition (message identity,
  // text-change wakeup, button UI, STT abort, VAD reset) stays here via
  // explicit source callbacks; protocols/retries are not rewritten.
  function playNativeVoiceModeTts(button, options) {
    options = options || {};
    // The message host is associated inside the owned queue at the exact
    // original point (after teardown/stop/reset, before queue fields), so
    // the bridge-availability/toggle early paths touch no DOM. The lookup
    // below resolves the source bound at this message's creation/update
    // sites; every text/progress read goes through that source.
    var messageContext = null;
    var queueDeps = {
      voiceLifecycle: voiceLifecycle,
      split: function (text) { return splitSentences(text); },
      terminator: function (text) { return sentenceEndsWithTerminator(text); },
      sanitize: function (text) { return sanitizeForTTS(text); },
      // Published by initMessageContext at the original association point.
      source: null,
      initMessageContext: function () {
        var $messageElement = $(button).closest('.message');
        messageContext = {
          element: $messageElement,
          textEl: $messageElement.find('.ai-message-text')[0]
        };
        queueDeps.source = lookupMessagePlaybackSource($messageElement[0]);
      },
      fetchVoiceRetry: function (url, buildOptions, attempts) { return fetchVoiceRetry(url, buildOptions, attempts); },
      // Wake-only backstop for text changes; progress comes from the source.
      observeChanges: function (onChange) {
        var textEl = messageContext.textEl;
        if (textEl && typeof MutationObserver === 'function') {
          var obs = new MutationObserver(function () {
            onChange();
          });
          obs.observe(textEl, { childList: true, subtree: true, characterData: true });
          return function () { try { obs.disconnect(); } catch (e) { /* ignore */ } };
        }
        return null;
      },
      withCsrf: function (headers) { return withCsrf(headers); },
      sleepMs: function (ms) { return sleepMs(ms); },
      isRetryableVoiceStatus: function (status) { return isRetryableVoiceStatus(status); },
      getNativeBridge: function () {
        return (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) ? window.NativeVoiceTts : null;
      },
      streamUrl: function (token) { return nativeVoiceTtsStreamUrl(token); },
      cancelToken: function (token) { return cancelNativeTtsToken(token); },
      stopDesktop: function () { stopCurrentDesktopTts(); },
      stopAll: function (opts) { stopAllTtsPlayback(opts); },
      abortStt: function () {
        if (voiceSttAbortController) {
          try { voiceSttAbortController.abort(); } catch (e) { /* ignore */ }
          voiceSttAbortController = null;
        }
      },
      vadReset: function () {
        if (nativeMicBridge && typeof nativeMicBridge.onTtsPlaybackStarted === 'function') {
          nativeMicBridge.onTtsPlaybackStarted();
        }
      },
      resetPlayButton: function (btn) { resetPlayButtonUi(btn); },
      clearMessageUi: function () { clearMessageTtsPlayingUi(); },
      syncSendButton: function () { syncSendButtonState(); },
      setButtonPlaying: function (btn) {
        $(btn).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
        messageContext.element.addClass('tts-is-playing');
        messageContext.element.find('.ai-message-text').addClass('tts-is-playing');
      },
      notifyStarted: function () { onVoiceModeTtsStarted(); },
      notifyEnded: function () { onVoiceModeTtsEnded(); },
      reportVoice: function (kind, msg) { reportVoice(kind, msg); },
      appendMessage: function (text, cls) { appendMessage(text, cls); },
      logError: function () { console.error.apply(console, arguments); },
      setTimeout: function (fn, ms) { return setTimeout(fn, ms); },
      clearTimeout: function (id) { clearTimeout(id); },
      isVoiceModeActive: function () { return !!window.voiceModeActive; },
      getSessionPromise: function () { return nativeVoiceTtsSessionPromise; },
      setSessionPromise: function (pr) { nativeVoiceTtsSessionPromise = pr; },
      setSessionListener: function (l) { nativeVoiceTtsSessionListener = l; },
      nativeStop: function () { return window.NativeVoiceTts.stop().catch(function () {}); },
      invalidateNative: function () { invalidateNativeVoiceTts(); },
      finishNative: function (gen, btn) { finishNativeVoiceTts(gen, btn); },
      fallbackPlay: function (btn, opts) { window.playTTS(btn, opts); },
      createAbortController: function () { return new AbortController(); }
    };
    return ChatTtsPlayback.playNativeVoiceModeTts(queueDeps, button, options);
  }
  window.playNativeVoiceModeTts = playNativeVoiceModeTts;

  let voiceScreenWakeLock = null;

  function releaseVoiceScreenWakeLock() {
    const lock = voiceScreenWakeLock;
    voiceScreenWakeLock = null;
    if (lock && lock.release) {
      try { lock.release(); } catch (e) { /* ignore */ }
    }
  }

  function acquireVoiceScreenWakeLock() {
    if (!navigator.wakeLock || typeof navigator.wakeLock.request !== 'function') {
      return Promise.resolve();
    }
    if (document.hidden || !window.voiceModeActive) {
      return Promise.resolve();
    }
    return navigator.wakeLock.request('screen').then(function (lock) {
      if (!window.voiceModeActive) {
        try { lock.release(); } catch (e) { /* ignore */ }
        return;
      }
      releaseVoiceScreenWakeLock();
      voiceScreenWakeLock = lock;
      lock.addEventListener('release', function () {
        if (voiceScreenWakeLock === lock) {
          voiceScreenWakeLock = null;
        }
      });
    }).catch(function () {
      voiceScreenWakeLock = null;
    });
  }

  function persistVoiceModeWanted(on) {
    window.APP_DATA.voiceMode = on;
    if (!window.APP_DATA || !window.APP_DATA.loggedIn) return;
    withCsrfAsync({ 'Content-Type': 'application/json' }).then(function (headers) {
      return fetch('/update_preferences', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ voice_mode: on }),
      });
    }).catch(function (err) {
      console.debug('Failed to save voice mode preference:', err);
    });
  }

  function voiceModeWanted() {
    return !!(window.APP_DATA && window.APP_DATA.voiceMode);
  }

  async function startVoiceMode(attempt) {
    attempt = attempt || 0;
    const sessionGeneration = ++voiceModeSessionGeneration;
    if (voiceSttAbortController) {
      try { voiceSttAbortController.abort(); } catch (e) { /* ignore */ }
    }
    const sttAbortController = new AbortController();
    voiceSttAbortController = sttAbortController;
    vadSttInProgress = false;
    persistVoiceModeWanted(true);
    let startingNativeBridge = null;
    let candidateStream = null;
    let candidateVAD = null;
    try {
      const useNativeMicVAD = window.nativeMicAvailable && isMobile;
      reportVoice('VOICE', 'startVoiceMode attempt=' + attempt + ' gen=' + sessionGeneration
        + ' native=' + (!!useNativeMicVAD));

      if (useNativeMicVAD) {
        if (nativeMicBridge) {
          const previousBridge = nativeMicBridge;
          try { await previousBridge.stop(); } catch (e) { /* ignore */ }
          if (nativeMicBridge === previousBridge) nativeMicBridge = null;
        }
        if (window._recoverNativeVoice && attempt > 0) {
          await window._recoverNativeVoice();
        }
        await ensureNativeMicPermission();
        if (window.NativeMic && window.NativeMic.enterVoiceRoute) {
          const routeRes = await window.NativeMic.enterVoiceRoute();
          reportVoice('VOICE', 'enterVoiceRoute ok active=' + (routeRes && routeRes.active)
            + ' bluetooth=' + (routeRes && routeRes.bluetooth)
            + ' foreground=' + (routeRes && routeRes.foreground));
        }
        startingNativeBridge = new ChatVoiceCapture.NativeMicUtteranceVAD(createNativeVadHost(), function (err) {
          nativeLog('VAD', err == null ? 'Native mic error' : String(err));
        });
        nativeMicBridge = startingNativeBridge;
        await startingNativeBridge.start();
      } else {
        // Use browser getUserMedia on desktop
        candidateStream = await navigator.mediaDevices.getUserMedia({
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true,
            channelCount: 1
          }
        });

        candidateVAD = await createVAD(candidateStream);
        await candidateVAD.start();
      }

      if (sessionGeneration !== voiceModeSessionGeneration || !voiceModeWanted()) {
        reportVoice('VOICE', 'startVoiceMode gen=' + sessionGeneration + ' superseded, tearing down');
        if (startingNativeBridge && nativeMicBridge === startingNativeBridge) {
          try { await startingNativeBridge.stop(); } catch (e) { /* ignore */ }
          if (nativeMicBridge === startingNativeBridge) nativeMicBridge = null;
        }
        if (candidateVAD) {
          try { candidateVAD.pause(); } catch (e) { /* ignore */ }
          try { candidateVAD.destroy(); } catch (e) { /* ignore */ }
          candidateVAD = null;
        }
        if (candidateStream) {
          candidateStream.getTracks().forEach(function (track) { track.stop(); });
          candidateStream = null;
        }
        if (sessionGeneration === voiceModeSessionGeneration) {
          if (voiceModeVAD) {
            try { voiceModeVAD.pause(); } catch (e) { /* ignore */ }
            try { voiceModeVAD.destroy(); } catch (e) { /* ignore */ }
            voiceModeVAD = null;
          }
          if (voiceModeStream) {
            voiceModeStream.getTracks().forEach(function (track) { track.stop(); });
            voiceModeStream = null;
          }
          if (window.NativeMic && window.NativeMic.exitVoiceRoute) {
            window.NativeMic.exitVoiceRoute().catch(function () {});
          }
        }
        return;
      }

      if (candidateVAD) {
        voiceModeVAD = candidateVAD;
        candidateVAD = null;
      }
      if (candidateStream) {
        voiceModeStream = candidateStream;
        candidateStream = null;
      }
      window.voiceModeActive = true;
      reportVoice('VOICE', 'voice session active gen=' + sessionGeneration);
      $voiceModeBtn.addClass('active');
      $micBtn.prop('disabled', true);
      acquireVoiceScreenWakeLock();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      nativeLog('VAD', 'startVoiceMode failed attempt=' + attempt + ' ' + msg);
      reportVoice('VOICE-ERROR', 'startVoiceMode failed attempt=' + attempt + ' gen='
        + sessionGeneration + ' ' + msg);
      if (candidateVAD) {
        try { candidateVAD.pause(); } catch (e) { /* ignore */ }
        try { candidateVAD.destroy(); } catch (e) { /* ignore */ }
      }
      if (candidateStream) {
        candidateStream.getTracks().forEach(function (track) { track.stop(); });
      }
      if (startingNativeBridge && nativeMicBridge === startingNativeBridge) {
        try { await startingNativeBridge.stop(); } catch (e) { /* ignore */ }
        if (nativeMicBridge === startingNativeBridge) nativeMicBridge = null;
      }
      if (sessionGeneration !== voiceModeSessionGeneration) return;
      window.voiceModeActive = false;
      $voiceModeBtn.removeClass('active');
      $micBtn.prop('disabled', false);
      if (nativeMicBridge) {
        const failedBridge = nativeMicBridge;
        try { failedBridge.stop(); } catch (e) { /* ignore */ }
        if (nativeMicBridge === failedBridge) nativeMicBridge = null;
      }
      const permissionDenied = /permission/i.test(msg);
      if (!permissionDenied && attempt < 5 && voiceModeWanted()) {
        setTimeout(function () {
          if (sessionGeneration !== voiceModeSessionGeneration || !voiceModeWanted()) return;
          startVoiceMode(attempt + 1);
        }, 400 * (attempt + 1));
        return;
      }
      persistVoiceModeWanted(false);
      if (window.NativeMic && window.NativeMic.exitVoiceRoute) {
        window.NativeMic.exitVoiceRoute().catch(function () {});
      }
      appendMessage(permissionDenied
        ? ('Microphone access denied: ' + msg)
        : ('Voice mode failed: ' + msg), 'error-message');
    }
  }

  function recoverAndMaybeResumeVoiceMode() {
    const resume = function () {
      if (voiceModeWanted() && !window.voiceModeActive) {
        startVoiceMode();
      }
    };
    if (window._recoverNativeVoice) {
      window._recoverNativeVoice().then(resume).catch(resume);
    } else {
      resume();
    }
  }
  recoverAndMaybeResumeVoiceMode();

  // Desktop Silero factory lives in static/voice-capture.js; this adapter
  // supplies the message-specific callbacks (utterance timestamps, TTS-active
  // gate, STT handoff) and the frame gate. Thresholds/paths/model unchanged.
  function createVAD(stream, hooks) {
    return ChatVoiceCapture.createVAD(createDesktopVadHost(), stream, hooks);
  }

  async function reinitializeVAD() {
    if (!window.voiceModeActive) return;
    if (nativeMicBridge) {
      await nativeMicBridge.reinitialize();
      return;
    }
    if (!voiceModeStream || !voiceModeVAD) return;
    try {
      voiceModeVAD.pause();
      voiceModeVAD.start();
    } catch (e) {
      console.error('VAD reinitialize failed:', e);
      nativeLog('VAD', 'VAD reinitialize failed: ' + (e && e.message ? e.message : e));
      if (window.voiceModeActive) startVoiceMode(1);
    }
  }

  function stopAllTtsPlayback(opts) {
    voiceLifecycle.stopAllPlayback(opts);
  }
  window.stopAllTtsPlayback = stopAllTtsPlayback;

  function stopVoicePlaybackOnly() {
    stopAllTtsPlayback({ preserveListen: true });
  }

  function stopVoiceMode() {
    voiceModeSessionGeneration += 1;
    reportVoice('VOICE', 'voice session stopped');
    if (voiceSttAbortController) {
      try { voiceSttAbortController.abort(); } catch (e) { /* ignore */ }
      voiceSttAbortController = null;
    }
    window.voiceModeActive = false;
    stopAllTtsPlayback();
    if (nativeMicBridge) {
      const bridge = nativeMicBridge;
      bridge.stop();
      if (nativeMicBridge === bridge) nativeMicBridge = null;
    }
    if (voiceModeVAD) {
      voiceModeVAD.pause();
      voiceModeVAD.destroy();
      voiceModeVAD = null;
    }
    if (voiceModeStream) {
      voiceModeStream.getTracks().forEach(track => track.stop());
      voiceModeStream = null;
    }
    if (window.NativeMic && window.NativeMic.exitVoiceRoute) {
      window.NativeMic.exitVoiceRoute().catch(function () {});
    }
    voiceLifecycle.resetBargeFrames();
    lastVoiceSpeechEndedAt = 0;
    lastVoiceUtteranceStartedAt = 0;
    persistVoiceModeWanted(false);
    releaseVoiceScreenWakeLock();
    $voiceModeBtn.removeClass('active');
    $micBtn.prop('disabled', false);
    syncSendButtonState();
  }
  window.stopVoiceMode = stopVoiceMode;

  function pauseVoiceModeForPhoneCall() {
    if (!window.voiceModeActive && !voiceModeWanted()) return;
    voiceModeSessionGeneration += 1;
    if (voiceSttAbortController) {
      try { voiceSttAbortController.abort(); } catch (e) { /* ignore */ }
      voiceSttAbortController = null;
    }
    stopAllTtsPlayback();
    if (nativeMicBridge) {
      const bridge = nativeMicBridge;
      bridge.stop();
      if (nativeMicBridge === bridge) nativeMicBridge = null;
    }
    if (voiceModeVAD) {
      try { voiceModeVAD.pause(); } catch (e) { /* ignore */ }
      try { voiceModeVAD.destroy(); } catch (e) { /* ignore */ }
      voiceModeVAD = null;
    }
    if (voiceModeStream) {
      voiceModeStream.getTracks().forEach(function (track) { track.stop(); });
      voiceModeStream = null;
    }
  }
  window.pauseVoiceModeForPhoneCall = pauseVoiceModeForPhoneCall;

  function resumeVoiceModeAfterPhoneCall() {
    if (!voiceModeWanted()) return;
    startVoiceMode(1);
  }
  window.resumeVoiceModeAfterPhoneCall = resumeVoiceModeAfterPhoneCall;

  if (window.NativeMic && window.NativeMic.addListener) {
    window.NativeMic.addListener('voiceModeStopRequested', function () {
      // Always invalidate a start already waiting on permission/native setup.
      stopVoiceMode();
    });
    window.NativeMic.addListener('voiceModePhoneCall', function (data) {
      if (data && data.active) pauseVoiceModeForPhoneCall();
      else resumeVoiceModeAfterPhoneCall();
    });
  }

  function interruptVoiceReplyForNewTurn(opts) {
    opts = opts || {};
    if (!opts.ttsAlreadyStopped) {
      stopAllTtsPlayback();
    }
    if (chatRequests.interruptForVoiceTurn()) {
      const $lastAI = $('#chat-content .message.ai-message').last();
      if ($lastAI.length) {
        const $text = $lastAI.find('.ai-message-text');
        const raw = ($text.text() || '');
        if (raw.indexOf('[Stopped]') === -1) {
          $text.append(' [Stopped]');
        }
        $lastAI.find('.regenerate-button').prop('disabled', false);
        $lastAI.find('.play-button').prop('disabled', false);
        // Interrupted turn settles here; its source ends with the last
        // published text while the replacement request binds fresh.
        finishMessagePlayback($lastAI);
      }
    }
    if (voiceAmendTimer) {
      clearTimeout(voiceAmendTimer);
      voiceAmendTimer = null;
      pendingVoiceAmend = '';
    }
    syncSendButtonState();
  }

  function handleBargeIn() {
    stopAllTtsPlayback({ preserveListen: true });
    const endedAt = lastVoiceSpeechEndedAt || 0;
    const startedAt = lastVoiceUtteranceStartedAt || Date.now();
    if (endedAt && (startedAt - endedAt) > VOICE_AMEND_WINDOW_MS) {
      interruptVoiceReplyForNewTurn({ ttsAlreadyStopped: true });
    }
  }

  function applyVoiceAmendToUserMessage($el, extraText) {
    const original = $el.attr('data-original') || '';
    const parsed = parseUserMessageContent(original);
    const combinedPlain = joinVoiceUtterances(parsed.text, extraText);
    const finalText = composeUserMessageContent(
      combinedPlain, parsed.imageSrc, parsed.hasImage || parsed.deferred
    );
    const pairIndex = liveUserPairIndex($el);
    $el.attr('data-original', finalText);
    const $span = $el.find('.user-message-text');
    if ($span.length) {
      $span.replaceWith(buildUserMessageSpan(combinedPlain, parsed.imageSrc, {
        pairIndex: pairIndex,
        thumbnail: $el.attr('data-thumb') === '1'
      }));
    }
    scrollToBottom();
    return finalText;
  }

  let pendingVoiceAmend = '';
  let voiceAmendTimer = null;

  function queueVoiceContinuation(text) {
    pendingVoiceAmend = joinVoiceUtterances(pendingVoiceAmend, text);
    stopVoicePlaybackOnly();
    abortChatRequestQuietly();
    if (voiceAmendTimer) clearTimeout(voiceAmendTimer);
    voiceAmendTimer = setTimeout(flushVoiceContinuation, 350);
  }

  function flushVoiceContinuation() {
    voiceAmendTimer = null;
    const extra = pendingVoiceAmend;
    pendingVoiceAmend = '';
    if (!extra) return;
    const $lastUser = $('#chat-content .message.user-message').last();
    if (!$lastUser.length) {
      $('#user-input').val(extra);
      sendMessage();
      return;
    }
    const finalText = applyVoiceAmendToUserMessage($lastUser, extra);
    const pairIndex = liveUserPairIndex($lastUser);
    $('#user-input').val('');

    function tryRegen(attempt) {
      if (!window.voiceModeActive && !voiceModeWanted()) return;
      let $ai = $lastUser.next('.message.ai-message');
      if ($ai.length && pairIndex >= 0) {
        window.performRegeneration($ai[0], finalText, pairIndex);
        return;
      }
      if (attempt < 8 && pairIndex >= 0) {
        setTimeout(function () { tryRegen(attempt + 1); }, 200);
        return;
      }
      if (pairIndex >= 0 && !$ai.length) {
        appendMessage(null, 'ai-message');
        $ai = $lastUser.next('.message.ai-message');
        if ($ai.length) {
          window.performRegeneration($ai[0], finalText, pairIndex);
          return;
        }
      }
      sendMessage({ reuseLastUser: true, message: finalText });
    }
    tryRegen(0);
  }

  function submitVoiceUtterance(text, timing) {
    text = (text || '').trim();
    if (!text) return;
    timing = timing || {};
    const $lastUser = $('#chat-content .message.user-message').last();
    const generating = chatRequests.isGenerating() || $('#send-button').hasClass('is-generating');
    const ttsActive = voiceLifecycle.hasActiveVoiceSession();
    if (shouldAmendLastVoiceTurn({
      lastUserExists: $lastUser.length > 0,
      generating: generating,
      ttsActive: ttsActive,
      lastSpeechEndedAt: timing.lastSpeechEndedAt,
      utteranceStartedAt: timing.utteranceStartedAt
    })) {
      queueVoiceContinuation(text);
      return;
    }
    if (generating || ttsActive) {
      interruptVoiceReplyForNewTurn();
    }
    $('#user-input').val(text);
    sendMessage();
    scrollToBottom();
  }

  async function handleSpeechEnd(vadAudio) {
    console.log('[VAD] handleSpeechEnd called, vadSttInProgress=', vadSttInProgress);
    if (vadSttInProgress) {
      // A stuck flag deadlocks voice with the button green; make it visible.
      reportVoiceThrottled('stt-overlap', 30000, 'VOICE',
        'handleSpeechEnd skipped: STT already in flight');
      return;
    }
    if (!window.voiceModeActive) {
      reportVoiceThrottled('stt-inactive', 30000, 'VOICE',
        'handleSpeechEnd skipped: voice mode inactive');
      return;
    }
    const sessionGeneration = voiceModeSessionGeneration;
    const sttSignal = voiceSttAbortController ? voiceSttAbortController.signal : undefined;
    vadSttInProgress = true;
    const prevSpeechEndedAt = lastVoiceSpeechEndedAt;
    const utteranceStartedAt = (nativeMicBridge && nativeMicBridge.utteranceStartedAt)
      || lastVoiceUtteranceStartedAt
      || Date.now();
    lastVoiceSpeechEndedAt = Date.now();
    // Desktop only: pause VAD during STT; reinitializeVAD() resumes before TTS.
    // Native bridge must NEVER pause — Silero cannot restart in Android WebView, and
    // barge-in during TTS requires continuous VAD.
    if (voiceModeVAD) voiceModeVAD.pause();

    try {
      let audioPayload;
      if (nativeMicBridge && nativeMicBridge.hasSpeechCapture()) {
        const pcm16 = nativeMicBridge.takeSpeechPcm16 ? nativeMicBridge.takeSpeechPcm16() : null;
        if (!pcm16 || pcm16.length * 2 < NativeAudio.SPEECH_MIN_PCM_BYTES) {
          nativeLog('VAD', 'STT skipped: utterance too short bytes=' + (pcm16 ? pcm16.length * 2 : 0));
          reportVoice('VOICE', 'STT skipped: utterance too short bytes='
            + (pcm16 ? pcm16.length * 2 : 0));
          return;
        }
        audioPayload = await NativeAudio.encodeAudioForStt(pcm16, NativeAudio.NATIVE_MIC_SAMPLE_RATE);
        nativeLog('VAD', 'STT native encoded format=' + audioPayload.filename + ' bytes=' + audioPayload.blob.size);
        reportVoice('VOICE', 'STT upload start format=' + audioPayload.filename
          + ' bytes=' + audioPayload.blob.size);
      } else if (vadAudio && vadAudio.length) {
        audioPayload = await NativeAudio.encodeAudioForStt(vadAudio, NativeAudio.NATIVE_MIC_SAMPLE_RATE);
        nativeLog('VAD', 'STT desktop encoded format=' + audioPayload.filename + ' bytes=' + audioPayload.blob.size);
        reportVoice('VOICE', 'STT upload start format=' + audioPayload.filename
          + ' bytes=' + audioPayload.blob.size);
      } else {
        reportVoice('VOICE-ERROR', 'STT skipped: no speech captured');
        return;
      }
      const sttOut = await postVoiceSttXhr('/stt', function () {
        const retryForm = new FormData();
        retryForm.append('audio', audioPayload.blob, audioPayload.filename);
        return {
          method: 'POST',
          headers: withCsrf({}),
          body: retryForm,
          bodyBytes: audioPayload.blob.size,
          signal: sttSignal
        };
      });
      const sttNet = sttOut.net || { bytes: audioPayload.blob.size, upMs: 0 };
      reportVoice('VOICE', 'STT net: bytes=' + sttNet.bytes
        + ' upMs=' + sttNet.upMs
        + ' upKbps=' + (sttNet.upMs > 0 ? ((sttNet.bytes * 8) / sttNet.upMs).toFixed(1) : 'n/a'));
      if (!window.voiceModeActive || sessionGeneration !== voiceModeSessionGeneration) {
        reportVoice('VOICE', 'STT response discarded: session ended mid-upload');
        return;
      }
      const data = JSON.parse(sttOut.responseText);
      const text = (data.text || '').trim();

      if (text && window.voiceModeActive
          && sessionGeneration === voiceModeSessionGeneration) {
        reportVoice('VOICE', 'STT ok textLen=' + text.length);
        submitVoiceUtterance(text, {
          lastSpeechEndedAt: prevSpeechEndedAt,
          utteranceStartedAt: utteranceStartedAt
        });
      } else if (!text) {
        reportVoice('VOICE', 'STT empty result (heard nothing / unintelligible)');
      }
    } catch (err) {
      const sttErr = (err && err.message ? err.message : String(err));
      nativeLog('VAD', 'STT failed: ' + sttErr);
      reportVoice('VOICE-ERROR', 'STT failed: ' + sttErr);
      // A user-initiated stop aborts the upload; that is not a failure.
      // Anything else (truncated upload, timeout, 4xx/5xx) must be visible:
      // a silent green button is the failure mode being eliminated.
      if (!(sttSignal && sttSignal.aborted)) {
        appendMessage('Voice input failed (' + sttErr + '). Try again.', 'error-message');
      }
    } finally {
      if (sessionGeneration === voiceModeSessionGeneration) {
        vadSttInProgress = false;
      }
      if (window.voiceModeActive && sessionGeneration === voiceModeSessionGeneration) {
        await reinitializeVAD();
      }
      if (window.voiceModeActive
          && sessionGeneration === voiceModeSessionGeneration
          && nativeMicBridge && nativeMicBridge.hasCompletedSpeechCapture()) {
        setTimeout(function () { handleSpeechEnd(); }, 0);
      }
    }
  }

  // Pause/resume VAD when page is hidden
  document.addEventListener('visibilitychange', function () {
    if (window.voiceModeActive && !document.hidden) {
      acquireVoiceScreenWakeLock();
    }
    // With native mic bridge, we don't pause - native mic continues
    if (nativeMicBridge) return;
    if (!voiceModeVAD) return;
    if (document.hidden) {
      voiceModeVAD.pause();
    } else if (window.voiceModeActive) {
      try {
        voiceModeVAD.start();
      } catch (e) {
        console.error('VAD resume failed after visibility change:', e);
        stopVoiceMode();
      }
    }
  });

  // Initialize prompt/memory for guests
  if (!window.APP_DATA.loggedIn) {
    $('#user-system-prompt').val(window.DEFAULT_SYSTEM_PROMPT);
    $('#user-memory').val('');
  }

  $('#user-input').focus();

  $(window).trigger('resize');
});

// Toggle thinking content visibility (used by inline handler in generated HTML)
window.toggleThinking = function toggleThinking(button) {
  const $button = $(button);
  const $message = $button.closest('.message');
  const isFinished = !$message.find('.regenerate-button').prop('disabled');

  const $contentDiv = $button.next();
  const text = $contentDiv.text();
  const isSearch = text.includes('Searching') || text.includes('web search') || text.includes('Found source');
  const isRateLimited = text.toLowerCase().includes('rate limited');

  if ($contentDiv.css('display') === 'none') {
    $contentDiv.css('display', 'block');
    const label = isSearch ? 'Hide Search Details' : 'Hide Thinking';
    $button.html(`<i class="bi bi-caret-down-fill"></i> ${label}`);
  } else {
    $contentDiv.css('display', 'none');
    let label;
    if (isSearch) {
        label = isFinished ? 'Search completed.' : 'Searching the web...';
    } else if (isRateLimited && !isFinished) {
        label = 'Rate limited — retrying...';
    } else {
        label = 'Show Thinking';
    }
    $button.html(`<i class="bi bi-caret-right-fill"></i> ${label}`);
  }
};
// Initialize config from inline template if globals are not set
; (function initConfig() {
  if (!window.APP_DATA || !window.DEFAULT_SYSTEM_PROMPT) {
    const tpl = document.getElementById('app-data');
    if (tpl) {
      try {
        const cfg = JSON.parse(tpl.textContent || '{}');
        window.APP_DATA = window.APP_DATA || {
          userTier: cfg.userTier || 'free',
          availableModels: cfg.availableModels || [],
          loggedIn: !!cfg.loggedIn,
          saveThoughts: cfg.saveThoughts !== undefined ? cfg.saveThoughts : true,
          sendThoughts: cfg.sendThoughts !== undefined ? cfg.sendThoughts : false,
          renderMarkdown: cfg.renderMarkdown !== undefined ? cfg.renderMarkdown : true,
        };
        window.DEFAULT_SYSTEM_PROMPT = window.DEFAULT_SYSTEM_PROMPT || cfg.defaultSystemPrompt || '';
      } catch (e) {
        console.debug('APP_DATA parse error', e);
      }
    }
  }
})();
