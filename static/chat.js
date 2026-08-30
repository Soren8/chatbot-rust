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
      window.APP_DATA = { userTier: 'free', availableModels: [], loggedIn: false, saveThoughts: true, sendThoughts: false, renderMarkdown: true, autoplayTTS: false };
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

const SESSION_EXPIRED_SEND_MSG =
  'Session expired or unauthorized. Your message was not sent — it is still in the input box.';

const originalFetch = window.fetch;
window.fetch = function(input, init) {
  return originalFetch.apply(this, arguments).then(response => {
    if (response.status === 401) {
      let url = input;
      if (input instanceof Request) {
        url = input.url;
      }
      if (typeof url === 'string' && (
        url.includes('/chat') ||
        url.includes('/regenerate') ||
        url.includes('/get_sets') ||
        url.includes('/load_set') ||
        url.includes('/create_set') ||
        url.includes('/delete_set') ||
        url.includes('/rename_set') ||
        url.includes('/update_memory') ||
        url.includes('/update_system_prompt') ||
        url.includes('/delete_message') ||
        url.includes('/reset_chat') ||
        url.includes('/history_pair') ||
        url.includes('/history_image')
      )) {
        return response;
      }
      window.location.href = '/login';
      throw new Error('Session expired');
    }
    return response;
  });
};

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

function syncHistoryImageEncCookie(encKey) {
  if (!encKey) return;
  var secure = (window.location.protocol === 'https:') ? '; Secure' : '';
  document.cookie = 'hist_enc_key=' + encodeURIComponent(encKey)
    + '; Path=/history_image; SameSite=Strict' + secure;
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

function sleepMs(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function isRetryableVoiceStatus(status) {
  return status === 408 || status === 429 || status === 502 || status === 503 || status === 504
    || status >= 500;
}

function fetchVoiceRetry(url, buildOptions, attempts) {
  attempts = attempts || 3;
  function attempt(n) {
    var options = typeof buildOptions === 'function' ? buildOptions() : (buildOptions || {});
    var userSignal = options.signal;
    var controller = new AbortController();
    var timeoutId = setTimeout(function () { controller.abort(); }, 60000);
    var userAborted = false;
    var onUserAbort = function () {
      userAborted = true;
      controller.abort();
    };
    if (userSignal) {
      if (userSignal.aborted) {
        clearTimeout(timeoutId);
        var aborted = new Error('aborted');
        aborted.name = 'AbortError';
        return Promise.reject(aborted);
      }
      userSignal.addEventListener('abort', onUserAbort);
    }
    var opts = Object.assign({}, options, { signal: controller.signal });
    return fetch(url, opts).then(function (res) {
      if (res.ok) return res;
      if (res.status === 401) {
        window.location.href = '/login';
        throw new Error('Session expired');
      }
      if (n > 1 && isRetryableVoiceStatus(res.status)) {
        return sleepMs(400 * Math.pow(2, attempts - n)).then(function () { return attempt(n - 1); });
      }
      throw new Error('request failed (' + res.status + ')');
    }).catch(function (err) {
      if (err && err.message === 'Session expired') throw err;
      if (err && err.name === 'AbortError' && userAborted) throw err;
      if (n <= 1) throw err;
      return sleepMs(400 * Math.pow(2, attempts - n)).then(function () { return attempt(n - 1); });
    }).finally(function () {
      clearTimeout(timeoutId);
      if (userSignal) userSignal.removeEventListener('abort', onUserAbort);
    });
  }
  return attempt(attempts);
}

function withCsrf(headers) {
  var result = headers ? Object.assign({}, headers) : {};
  if (window.CSRF_TOKEN) {
    result['X-CSRF-Token'] = window.CSRF_TOKEN;
  }
  if (window.APP_DATA && window.APP_DATA.loggedIn && window.EncKey) {
    var encKey = window.EncKey.getKeyForRequestSync();
    if (encKey) {
      result['X-Enc-Key'] = encKey;
      syncHistoryImageEncCookie(encKey);
    }
  }
  return result;
}

async function withCsrfAsync(headers) {
  var result = headers ? Object.assign({}, headers) : {};
  if (window.CSRF_TOKEN) {
    result['X-CSRF-Token'] = window.CSRF_TOKEN;
  }
  if (window.APP_DATA && window.APP_DATA.loggedIn && window.EncKey) {
    var encKey = await window.EncKey.getKeyForRequest();
    if (encKey) {
      result['X-Enc-Key'] = encKey;
      syncHistoryImageEncCookie(encKey);
    }
  }
  return result;
}


function syncSelectedOptionVersion(version) {
  var $opt = $('#set-selector option:selected');
  if ($opt.length) $opt.attr('data-version', String(version));
}

/** Apply a set version from a response or 409 body.
 *  List refreshes (`get_sets`) must not rewind: an in-flight list after delete
 *  can be stale. Mutation / 409 bodies are authoritative (`allowRewind`). */
function applySetVersion(version, setId, options) {
  if (!window.APP_DATA) window.APP_DATA = {};
  var allowRewind = !!(options && options.allowRewind);
  if (setId) {
    if (window.APP_DATA.lastSetId && setId !== window.APP_DATA.lastSetId) {
      window.APP_DATA.lastSetId = setId;
      if (version != null && version !== '') {
        var switched = Number(version);
        if (!Number.isNaN(switched)) {
          window.APP_DATA.setVersion = switched;
          syncSelectedOptionVersion(switched);
        }
      }
      return;
    }
    window.APP_DATA.lastSetId = setId;
  }
  if (version == null || version === '') return;
  var next = Number(version);
  if (Number.isNaN(next)) return;
  var current = Number(window.APP_DATA.setVersion);
  if (!allowRewind && !Number.isNaN(current) && next < current) return;
  window.APP_DATA.setVersion = next;
  syncSelectedOptionVersion(next);
}

function activeSetPayload(extra) {
  var $o = $('#set-selector option:selected');
  var payload = Object.assign({}, extra || {});
  payload.set_name = $o.attr('data-name') || $o.text() || 'default';
  var setId = window.APP_DATA.lastSetId || $o.val();
  if (setId) payload.set_id = setId;
  if (window.APP_DATA.setVersion != null && window.APP_DATA.setVersion !== '') {
    payload.expected_version = Number(window.APP_DATA.setVersion);
  }
  return payload;
}

function noteSetVersionFromResponse(data) {
  if (!data) return;
  var version = data.version != null ? data.version : data.current_version;
  applySetVersion(version, data.set_id, { allowRewind: true });
}

/** Sync version from an authoritative READ response (load_set / history_pair).
 *  Advance-only: a concurrent write may make the read snapshot stale-low, and
 *  we must never rewind below a version the client already observed. */
function noteSetVersionFromRead(data) {
  if (!data) return;
  var version = data.version != null ? data.version : data.current_version;
  applySetVersion(version, data.set_id);
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
  if (window.APP_DATA.setVersion == null || window.APP_DATA.setVersion === '') return;
  var next = Number(window.APP_DATA.setVersion) + 1;
  if (Number.isNaN(next)) return;
  applySetVersion(next, window.APP_DATA.lastSetId);
}

var HISTORY_PAGE_SIZE = 40;
var HISTORY_OFFSET = 0;
var HISTORY_TOTAL = 0;
var HISTORY_HAS_MORE = false;
var HISTORY_LOADING_OLDER = false;
var HISTORY_SET_GEN = 0;

function resetHistoryWindow() {
  HISTORY_OFFSET = 0;
  HISTORY_TOTAL = 0;
  HISTORY_HAS_MORE = false;
  HISTORY_LOADING_OLDER = false;
}

function liveUserPairIndex(userMessageElement) {
  var el = userMessageElement && userMessageElement.jquery ? userMessageElement[0] : userMessageElement;
  if (!el) return -1;
  var nodes = document.querySelectorAll('#chat-content .message.user-message');
  var i = Array.prototype.indexOf.call(nodes, el);
  if (i < 0) return -1;
  return HISTORY_OFFSET + i;
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
  return $ai;
}

function reindexUserPairIndices() {
  var nodes = document.querySelectorAll('#chat-content .message.user-message');
  for (var i = 0; i < nodes.length; i++) {
    nodes[i].setAttribute('data-pair-index', String(HISTORY_OFFSET + i));
    var img = nodes[i].querySelector('img.chat-image');
    if (img) img.setAttribute('data-pair-index', String(HISTORY_OFFSET + i));
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
        if (!isRetry) return submitResetChat(true);
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

function preloadEncryptionKey() {
  if (!window.APP_DATA || !window.APP_DATA.loggedIn || !window.EncKey) {
    return Promise.resolve(null);
  }
  return window.EncKey.getKeyForRequest().catch(function(err) {
    console.debug('encryption key preload failed', err);
    return null;
  });
}

function showEncKeyGateLoading(message) {
  var $encGate = $('#enc-key-gate');
  if (!$encGate.length) {
    return;
  }
  $encGate.removeClass('d-none');
  $('#enc-key-gate-spinner').show();
  $('#enc-key-gate-actions').addClass('d-none');
  $encGate.find('.enc-key-gate-message').text(message || 'Loading encryption key…');
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

function beginEncKeyUnlockFlow() {
  if (window.EncKey && window.EncKey.isNativeSecureStorage && window.EncKey.isNativeSecureStorage()) {
    showEncKeyGateLoading('Confirm with fingerprint or device PIN…');
  } else {
    showEncKeyGateLoading('Loading encryption key…');
  }
  return waitForEncryptionKey()
    .then(function() {
      if (typeof window.loadChatSets !== 'function') {
        throw new Error('Chat is still starting. Try again.');
      }
      showEncKeyGateLoading('Loading your sets…');
      return window.loadChatSets();
    })
    .then(function() {
      hideEncKeyGate();
    })
    .catch(function(err) {
      console.error('encryption key unavailable on chat load', err);
      showEncKeyGateError(err);
      throw err;
    });
}

async function response401Kind(response) {
  if (response.status !== 401) {
    return null;
  }
  var body = {};
  try {
    body = await response.clone().json();
  } catch (_) {
    return 'session';
  }
  var msg = (body.error || body.message || '').toString();
  if (/encryption key|unlock|invalid encryption key/i.test(msg)) {
    return 'enc_key';
  }
  return 'session';
}

async function handle401OrRetry(response, retryFn) {
  var kind = await response401Kind(response);
  if (kind === 'enc_key') {
    var unlocked = await ensureEncryptionKeyUnlocked();
    if (unlocked && retryFn) {
      return retryFn();
    }
    throw new Error('Encryption key required. Please unlock.');
  }
  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Session expired');
  }
  return response;
}

async function ensureEncryptionKeyUnlocked() {
  if (!window.APP_DATA || !window.APP_DATA.loggedIn || !window.EncKey) {
    return null;
  }
  var existing = window.EncKey.getKeyForRequestSync();
  if (existing) {
    return existing;
  }
  return window.EncKey.getKeyForRequest();
}

async function waitForEncryptionKey() {
  if (!window.EncKey) {
    throw new Error('Encryption key unavailable. Sign out and log in again.');
  }
  if (window.EncKey.lock) {
    window.EncKey.lock();
  }
  var key = await window.EncKey.getKeyForRequest();
  if (key) {
    return key;
  }
  throw new Error('Encryption key unavailable. Sign out and log in again.');
}

async function fetchWithEncKey(input, init, retryOnUnlock) {
  var options = init ? Object.assign({}, init) : {};
  options.headers = await withCsrfAsync(options.headers || {});
  var response = await originalFetch(input, options);
  if (
    retryOnUnlock !== false &&
    response.status === 401 &&
    window.APP_DATA &&
    window.APP_DATA.loggedIn &&
    window.EncKey
  ) {
    var kind = await response401Kind(response);
    if (kind === 'enc_key') {
      var unlocked = await ensureEncryptionKeyUnlocked();
      if (unlocked) {
        options.headers = await withCsrfAsync(options.headers || {});
        return originalFetch(input, options);
      }
    }
  }
  return response;
}

// Settings panel behavior (collapse on small screens)
$(function() {
  if (window.APP_DATA && window.APP_DATA.loggedIn && window.EncKey) {
    var $deviceLock = $('#enable-device-lock');
    var $hint = $('#enc-key-storage-hint');
    if (window.EncKey.isNativeSecureStorage && window.EncKey.isNativeSecureStorage()) {
      if ($hint.length) {
        $hint.text('Your chat key is protected by this device OS. Saved at login; fingerprint or PIN required to unlock.');
      }
    } else if (window.EncKey.supportsWebAuthnPrf) {
      window.EncKey.supportsWebAuthnPrf().then(function(supported) {
        if (supported) {
          $deviceLock.show();
        }
      });
    }
    $deviceLock.on('click', function() {
      var name = window.APP_DATA.username || 'chatbot-user';
      window.EncKey.registerWebAuthnDeviceLock(name)
        .then(function() {
          $deviceLock.hide();
        })
        .catch(function(err) {
          alert('Could not enhance encryption key cache security: ' + (err && err.message ? err.message : err));
        });
    });
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
function escapeHTML(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Inverse of the common entities produced by escapeHTML.
// Used only to undo pre-escaping before highlight.js (which escapes again).
function decodeHTMLEntities(str) {
  return String(str == null ? '' : str)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&amp;/g, '&');
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
// Reconstructs from character-class-filtered parts so DOM-sourced strings never
// flow into HTML attribute sinks (CodeQL js/xss-through-dom).
// Returns null when the value is missing or not a safe data-image URL.
function sanitizeDataImageSrc(src) {
  if (src == null) return null;
  const raw = String(src);
  const m = /^data:image\/([A-Za-z0-9+.-]+);base64,([A-Za-z0-9+/=\s]+)$/.exec(raw);
  if (!m) return null;
  // .replace with inverted classes strips any HTML/JS meta-characters CodeQL
  // would otherwise track from DOM text into the src attribute.
  const subtype = m[1].replace(/[^A-Za-z0-9+.-]/g, '');
  const b64 = m[2].replace(/[^A-Za-z0-9+/=]/g, '');
  if (!subtype || !b64 || subtype !== m[1] || b64 !== m[2].replace(/[\s]/g, '')) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
  return 'data:image/' + subtype + ';base64,' + b64;
}

// Build the user-message display node without interpreting message text as HTML
// (CodeQL js/xss-through-dom). Text goes through createTextNode only; images use
// a reconstructed data:image URL from sanitizeDataImageSrc.
function buildUserMessageSpan(text, imageSrc, opts) {
  const span = document.createElement('span');
  span.className = 'user-message-text';

  const label = document.createElement('strong');
  label.textContent = 'You:';
  span.appendChild(label);
  span.appendChild(document.createTextNode(' '));

  const body = document.createElement('span');
  body.className = 'user-message-body';
  const lines = String(text == null ? '' : text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (i > 0) body.appendChild(document.createElement('br'));
    body.appendChild(document.createTextNode(lines[i]));
  }
  span.appendChild(body);

  const safeSrc = sanitizeDataImageSrc(imageSrc) || sanitizeLightboxSrc(imageSrc);
  if (safeSrc) {
    span.appendChild(document.createElement('br'));
    const img = document.createElement('img');
    img.className = 'chat-image';
    img.setAttribute('alt', 'Attached image');
    img.setAttribute('title', 'Click to expand');
    img.setAttribute('decoding', 'async');
    if (opts && opts.pairIndex != null) {
      img.setAttribute('data-pair-index', String(opts.pairIndex));
    }
    if (opts && opts.thumbnail) {
      img.setAttribute('data-thumb', '1');
    }
    if (opts && opts.deferSrc) {
      img.setAttribute('data-pending-src', safeSrc);
    } else {
      img.setAttribute('src', safeSrc);
    }
    span.appendChild(img);
  }

  return span;
}

// Append plain text (with optional newlines → <br>) without HTML interpretation.
function appendPlainTextWithBreaks(parent, text) {
  const lines = String(text == null ? '' : text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (i > 0) parent.appendChild(document.createElement('br'));
    parent.appendChild(document.createTextNode(lines[i]));
  }
}

// System/error chrome: fixed label + plain text only (createTextNode).
// Accepts only a scalar string — never options objects (CodeQL js/xss-through-exception
// is field-insensitive and would join error text with sibling fields like href).
function buildStatusMessageContent(className, text) {
  const frag = document.createDocumentFragment();
  const isError = className && className.indexOf('error-message') !== -1;
  const label = document.createElement('strong');
  label.textContent = isError ? 'Error:' : 'System:';
  frag.appendChild(label);
  frag.appendChild(document.createTextNode(' '));
  appendPlainTextWithBreaks(frag, text == null ? '' : String(text));
  return frag;
}

// Dedicated sets-load failure UI. Exception text is textContent only; the logout
// href is a string literal so it cannot be joined with error.message by analysis.
function buildSetsLoadErrorContent(errorText) {
  const frag = document.createDocumentFragment();
  const label = document.createElement('strong');
  label.textContent = 'Error:';
  frag.appendChild(label);
  frag.appendChild(document.createTextNode(' '));
  appendPlainTextWithBreaks(
    frag,
    'Could not load saved sets: ' + String(errorText == null ? '' : errorText) + ' '
  );
  const a = document.createElement('a');
  a.setAttribute('href', '/logout');
  a.textContent = 'Sign out';
  frag.appendChild(a);
  frag.appendChild(document.createTextNode(' and log in again if this persists.'));
  return frag;
}

// AI chrome builders — kept as separate functions so exception strings never
// share a parameter/object with an innerHTML sink (CodeQL js/xss-through-exception).

function buildAiLabelFragment() {
  const frag = document.createDocumentFragment();
  const strong = document.createElement('strong');
  strong.textContent = 'AI:';
  frag.appendChild(strong);
  return frag;
}

// History load only. `safeHtml` must already be produced by formatAiMessage /
// renderMarkdown (escapeHTML). Do not pass err.message here.
function buildAiHistoryChildren(safeHtml) {
  const frag = buildAiLabelFragment();
  frag.appendChild(document.createTextNode('\u00A0'));
  const textSpan = document.createElement('span');
  textSpan.className = 'ai-message-text';
  if (typeof safeHtml === 'string' && safeHtml) {
    textSpan.innerHTML = safeHtml;
  }
  frag.appendChild(textSpan);
  frag.appendChild(buildAiRegenerateContainer(true));
  return frag;
}

// Failed regenerate/chat: exception text via textContent only (never innerHTML).
function buildAiErrorChildren(errorText) {
  const frag = buildAiLabelFragment();
  frag.appendChild(document.createTextNode(' '));
  const errSpan = document.createElement('span');
  errSpan.className = 'error-message';
  errSpan.textContent = 'Error: ' + String(errorText == null ? '' : errorText);
  frag.appendChild(errSpan);
  frag.appendChild(buildAiRegenerateContainer(true));
  return frag;
}

// Streaming / regenerate placeholder shell (static chrome only).
function buildAiStreamChildren() {
  const frag = buildAiLabelFragment();

  const thinking = document.createElement('div');
  thinking.className = 'thinking-container';
  thinking.style.display = 'none';

  const toggle = document.createElement('button');
  toggle.className = 'toggle-thinking';
  toggle.style.display = 'none';
  toggle.type = 'button';
  const caret = document.createElement('i');
  caret.className = 'bi bi-caret-right-fill';
  toggle.appendChild(caret);
  toggle.appendChild(document.createTextNode(' Show Thinking'));
  thinking.appendChild(toggle);

  const thinkingContent = document.createElement('div');
  thinkingContent.className = 'thinking-content';
  thinkingContent.style.display = 'none';
  thinking.appendChild(thinkingContent);
  frag.appendChild(thinking);

  const textSpan = document.createElement('span');
  textSpan.className = 'ai-message-text';
  textSpan.textContent = 'Thinking...';
  frag.appendChild(textSpan);
  frag.appendChild(buildAiRegenerateContainer(false));
  return frag;
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
  const container = document.createElement('div');
  container.className = 'regenerate-container';

  const regen = document.createElement('button');
  regen.className = 'regenerate-button';
  regen.type = 'button';
  if (!enabled) regen.disabled = true;
  const regenIcon = document.createElement('i');
  regenIcon.className = 'bi bi-arrow-repeat';
  regen.appendChild(regenIcon);
  container.appendChild(regen);

  const play = document.createElement('button');
  play.className = 'play-button';
  play.type = 'button';
  const playIcon = document.createElement('i');
  playIcon.className = 'bi bi-play-fill';
  play.appendChild(playIcon);
  container.appendChild(play);

  return container;
}

// Configure marked with highlight.js
if (typeof marked !== 'undefined') {
  console.debug('Initializing marked with highlight.js');
  const renderer = new marked.Renderer();
  
  // Custom code block rendering with header and copy button
  renderer.code = function(args) {
    // Handle both object (new marked) and positional (old marked) arguments
    let text, lang;
    if (typeof args === 'object' && !Array.isArray(args)) {
      text = args.text;
      lang = args.lang;
    } else {
      text = arguments[0];
      lang = arguments[1];
    }

    // Fence language may appear in HTML attributes/text; keep it conservative.
    const language = String(lang || 'plaintext').replace(/[^a-zA-Z0-9_+#.-]/g, '') || 'plaintext';
    // renderMarkdown pre-escapes the whole document; undo that for the fence body
    // so hljs receives raw source and applies its own single escape pass.
    const rawCode = decodeHTMLEntities(text);
    let highlighted;
    
    console.debug('Rendering code block:', { language, textLength: rawCode.length });

    if (typeof hljs !== 'undefined') {
      try {
        const langObj = hljs.getLanguage(language);
        if (langObj) {
          highlighted = hljs.highlight(rawCode, { language }).value;
          console.debug('Highlight.js success for:', language);
        } else {
          highlighted = hljs.highlightAuto(rawCode).value;
          console.debug('Highlight.js auto-highlighting used');
        }
      } catch (e) {
        console.error('Highlight.js error:', e);
        highlighted = escapeHTML(rawCode);
      }
    } else {
      console.warn('Highlight.js (hljs) is not defined');
      highlighted = escapeHTML(rawCode);
    }

    return `<div class="code-block-container"><div class="code-block-header"><span>${escapeHTML(language)}</span><button class="copy-code-button" type="button" title="Copy to clipboard"><i class="bi bi-clipboard"></i></button></div><pre><code class="hljs language-${escapeHTML(language)}">${highlighted}</code></pre></div>`;
  };

  marked.use({ 
    renderer,
    gfm: true,
    breaks: true
  });
  console.debug('Marked configured with custom renderer');
} else {
  console.warn('Marked library not found');
}

function renderMarkdown(text) {
  if (text == null) text = '';
  else text = String(text);
  // Escape HTML meta-characters before markdown so values read from the DOM
  // (e.g. #user-input) cannot be reinterpreted as markup when assigned via .html()
  // (CodeQL js/xss-through-dom). Markdown syntax is unaffected; raw tags show as text.
  const safe = escapeHTML(text);
  if (window.APP_DATA && window.APP_DATA.renderMarkdown === false) {
    return safe.replace(/\n/g, '<br>');
  }
  if (typeof marked !== 'undefined') {
    try {
      return marked.parse(safe);
    } catch (e) {
      console.error('Markdown parsing error:', e);
      return safe.replace(/\n/g, '<br>');
    }
  }
  return safe.replace(/\n/g, '<br>');
}

// Top-level on purpose: appendHistoryPair / applyHistoryPage run outside the
// logged-in document.ready closure (a nested helper is ReferenceError there).
function formatAiMessage(text) {
  if (!text) return '';

  const openTag = '<think>';
  const closeTags = ['</think>', '[BEGIN FINAL RESPONSE]'];

  let thinkingParts = [];
  let visibleParts = [];
  let buffer = text;
  let state = 'visible';

  while (buffer.length > 0) {
    if (state === 'visible') {
      const idx = buffer.indexOf(openTag);
      if (idx !== -1) {
        visibleParts.push(buffer.substring(0, idx));
        buffer = buffer.substring(idx + openTag.length);
        state = 'thinking';
      } else {
        visibleParts.push(buffer);
        buffer = '';
      }
    } else {
      let firstCloseIdx = -1;
      let usedTagLen = 0;
      for (const tag of closeTags) {
        const idx = buffer.indexOf(tag);
        if (idx !== -1 && (firstCloseIdx === -1 || idx < firstCloseIdx)) {
          firstCloseIdx = idx;
          usedTagLen = tag.length;
        }
      }
      if (firstCloseIdx !== -1) {
        thinkingParts.push(buffer.substring(0, firstCloseIdx));
        buffer = buffer.substring(firstCloseIdx + usedTagLen);
        state = 'visible';
      } else {
        thinkingParts.push(buffer);
        buffer = '';
      }
    }
  }

  let html = '';
  const fullThinking = thinkingParts.join('').trim();
  if (fullThinking) {
    html += `<div class="thinking-container" style="display:block;"><button class="toggle-thinking" style="display:inline-block;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;">${escapeHTML(fullThinking).replace(/\n/g, '<br>')}</div></div>`;
  }

  html += renderMarkdown(visibleParts.join(''));
  return html;
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

let CURRENT_AUDIO = null;
let CURRENT_AUDIO_BUTTON = null;
/**
 * Desktop TTS controller (play-button + click-a-sentence).
 * session bumps on every stop so in-flight async work cannot affect the next play.
 * Uses one HTMLAudioElement — fully reset on stop so 2nd/3rd plays work after reload-only bugs.
 */
let desktopTtsSession = 0;
let desktopTtsAudio = null;
let desktopTtsAbort = null;
/** True while voice-mode TTS session is active (queued sentences). */
let voiceModeTtsSessionActive = false;
/** True while TTS audio is actively playing. */
let voiceModeTtsPlaying = false;
/** Do not start utterances until this timestamp (ms) — lets AEC settle after TTS. */
let voiceModeListenCooldownUntil = 0;
const TTS_LISTEN_COOLDOWN_MS = 400;
/** Bounded requeue attempts for a native TTS sentence on a spotty link. */
const MAX_TTS_SENTENCE_RETRIES = 3;
/** Total attempts to fetch one clip from /tts_stream (within the server's replay budget). */
const MAX_TTS_CLIP_ATTEMPTS = 2;
/** Backoff between clip GET retries; grows with the attempt number. */
const TTS_CLIP_RETRY_BACKOFF_MS = 400;

function armTtsListenCooldown() {
  voiceModeListenCooldownUntil = Date.now() + TTS_LISTEN_COOLDOWN_MS;
}

function resetPlayButtonUi(button) {
  if (!button) return;
  $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
}

function getDesktopTtsAudio() {
  if (!desktopTtsAudio) {
    desktopTtsAudio = new Audio();
  }
  return desktopTtsAudio;
}

/**
 * Reset the shared <audio> between utterances/sessions.
 * Important: do NOT call audio.load() after every stop — that re-arms autoplay
 * blocking so the 1st play works and the 2nd (after async /tts) silently fails.
 */
function resetDesktopTtsAudioElement() {
  const audio = desktopTtsAudio;
  if (!audio) return;
  audio.onended = null;
  audio.onerror = null;
  audio.onloadeddata = null;
  try { audio.pause(); } catch (e) { /* ignore */ }
  try {
    // Clear the resource without load() so the element keeps its user-activation media slot.
    audio.removeAttribute('src');
    audio.src = '';
  } catch (e) { /* ignore */ }
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
 * Always bumps desktopTtsSession so any prior async chain becomes a no-op.
 */
function stopCurrentDesktopTts() {
  desktopTtsSession += 1;
  if (desktopTtsAbort) {
    try { desktopTtsAbort.abort(); } catch (e) { /* ignore */ }
    desktopTtsAbort = null;
  }
  resetDesktopTtsAudioElement();
  const prevBtn = CURRENT_AUDIO_BUTTON;
  CURRENT_AUDIO = null;
  CURRENT_AUDIO_BUTTON = null;
  voiceModeTtsSessionActive = false;
  voiceModeTtsPlaying = false;
  resetPlayButtonUi(prevBtn);
  clearMessageTtsPlayingUi();
  if (typeof syncSendButtonState === 'function') {
    syncSendButtonState();
  }
}

function completeDesktopTtsPlayback(button) {
  CURRENT_AUDIO = null;
  CURRENT_AUDIO_BUTTON = null;
  resetPlayButtonUi(button);
  clearMessageTtsPlayingUi();
  resetDesktopTtsAudioElement();
  voiceModeTtsSessionActive = false;
  voiceModeTtsPlaying = false;
  if (window.voiceModeActive) {
    armTtsListenCooldown();
  }
  if (typeof syncSendButtonState === 'function') {
    syncSendButtonState();
  }
}

function desktopTtsIsLive(sessionId) {
  return sessionId === desktopTtsSession && CURRENT_AUDIO && CURRENT_AUDIO.sessionId === sessionId;
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
  const prev = String(previous == null ? '' : previous).trim();
  const added = String(next == null ? '' : next).trim();
  if (!prev) return added;
  if (!added) return prev;
  if (added === prev || prev.endsWith(added)) return prev;
  if (added.startsWith(prev)) return added;
  return prev + ' ' + added;
}

/** False end-of-speech / quick add-on window. After this, start a new turn. */
const VOICE_AMEND_WINDOW_MS = 2000;
let lastVoiceSpeechEndedAt = 0;
let lastVoiceUtteranceStartedAt = 0;

/** True when a new STT result is a continuation of the in-flight voice turn. */
function shouldAmendLastVoiceTurn(state) {
  state = state || {};
  if (!state.lastUserExists || !(state.generating || state.ttsActive)) return false;
  const endedAt = Number(state.lastSpeechEndedAt) || 0;
  const startedAt = Number(state.utteranceStartedAt) || 0;
  if (!endedAt || !startedAt) return false;
  return (startedAt - endedAt) <= VOICE_AMEND_WINDOW_MS;
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
      window.location.href = '/login';
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
  if (HISTORY_HAS_MORE && HISTORY_OFFSET > 0) {
    bar.hidden = false;
    if (btn) {
      btn.disabled = !!HISTORY_LOADING_OLDER;
      btn.textContent = HISTORY_LOADING_OLDER
        ? 'Loading…'
        : (HISTORY_OFFSET === 1
          ? 'Load older message'
          : 'Load older messages (' + HISTORY_OFFSET + ' earlier)');
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
}

function applyHistoryPage(data, mode) {
  var pairs = (data && data.history) ? data.history : [];
  var start = data && data.history_start != null ? Number(data.history_start) : 0;
  if (Number.isNaN(start)) start = 0;
  HISTORY_TOTAL = data && data.history_total != null ? Number(data.history_total) : pairs.length;
  HISTORY_HAS_MORE = !!(data && data.has_more);
  HISTORY_OFFSET = start;

  if (mode === 'prepend') {
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
  if (!HISTORY_HAS_MORE || HISTORY_LOADING_OLDER || HISTORY_OFFSET <= 0) return;
  if (!window.APP_DATA || !window.APP_DATA.loggedIn) return;
  HISTORY_LOADING_OLDER = true;
  updateLoadOlderBar();
  var before = HISTORY_OFFSET;
  var gen = HISTORY_SET_GEN;
  var setId = window.APP_DATA.lastSetId;
  var setName = window.APP_DATA.lastSet;
  withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
    return fetch('/load_set', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({
        set_id: setId,
        set_name: setName,
        limit: HISTORY_PAGE_SIZE,
        before: before,
        thumbnails: true
      })
    });
  }).then(function(r) {
    if (r.status === 401) return handle401OrRetry(r, function() { return Promise.reject(new Error('unauthorized')); });
    if (!r.ok) throw new Error('Failed to load older messages');
    return r.json();
  }).then(function(data) {
    if (gen !== HISTORY_SET_GEN) return;
    noteSetVersionFromRead(data);
    applyHistoryPage(data, 'prepend');
  }).catch(function(err) {
    console.error('Failed to load older messages:', err);
  }).then(function() {
    HISTORY_LOADING_OLDER = false;
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
  const dataSrc = sanitizeDataImageSrc(src);
  if (dataSrc) return dataSrc;
  if (src == null) return null;
  try {
    const u = new URL(String(src), window.location.href);
    if (u.origin !== window.location.origin) return null;
    const m = /^\/history_image\/([A-Za-z0-9._~-]+)\/([0-9]+)\/([0-9]+)\/([0-9]+)$/.exec(u.pathname);
    if (!m) return null;
    // Reconstruct from character-class-filtered captures so DOM-sourced
    // pathname/search never flow into HTML attribute sinks (CodeQL js/xss-through-dom).
    const setId = m[1].replace(/[^A-Za-z0-9._~-]/g, '');
    const version = m[2].replace(/[^0-9]/g, '');
    const pairIndex = m[3].replace(/[^0-9]/g, '');
    const imgIdx = m[4].replace(/[^0-9]/g, '');
    if (!setId || setId !== m[1] || version !== m[2] || pairIndex !== m[3] || imgIdx !== m[4]) {
      return null;
    }
    const path = '/history_image/' + setId + '/' + version + '/' + pairIndex + '/' + imgIdx;
    if (!u.search) return path;
    if (u.search === '?size=thumb') return path + '?size=thumb';
    return null;
  } catch (e) {
    return null;
  }
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

      deleteContainer.appendChild(editBtn);
      deleteContainer.appendChild(deleteBtn);
      host.appendChild(deleteContainer);
    } catch (e) { console.debug('Failed to add buttons:', e); }
  }

  mountChatMessage(host, mountOpts);
  return $messageElement;
}

let currentAbortController = null;
let chatRequestSeq = 0;

function beginChatRequest() {
  chatRequestSeq += 1;
  if (currentAbortController) {
    try { currentAbortController.abort(); } catch (e) { /* ignore */ }
  }
  currentAbortController = new AbortController();
  setGeneratingState(true);
  return chatRequestSeq;
}

function isLiveChatRequest(seq) {
  return seq === chatRequestSeq;
}

function finishChatRequest(seq) {
  if (!isLiveChatRequest(seq)) return false;
  currentAbortController = null;
  syncSendButtonState();
  return true;
}

function isVoiceTtsActive() {
  return !!(CURRENT_AUDIO || voiceModeTtsSessionActive || voiceModeTtsPlaying);
}

function syncSendButtonState() {
  const generating = !!currentAbortController;
  const voiceTts = !!window.voiceModeActive && isVoiceTtsActive();
  setGeneratingState(generating || voiceTts);
}

function abortChatRequestQuietly() {
  chatRequestSeq += 1;
  if (currentAbortController) {
    try { currentAbortController.abort(); } catch (e) { /* ignore */ }
    currentAbortController = null;
  }
}

function sleepMs(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function fetchWithGenerateRetry(url, init, attempt) {
  attempt = attempt || 0;
  return fetch(url, init).then(function (res) {
    if ((res.status === 429 || (res.status === 400 && attempt < 8)) && attempt < 12) {
      return sleepMs(200 + attempt * 150).then(function () {
        if (init && init.signal && init.signal.aborted) {
          const err = new Error('Aborted');
          err.name = 'AbortError';
          throw err;
        }
        return fetchWithGenerateRetry(url, init, attempt + 1);
      });
    }
    return res;
  });
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
  if (currentAbortController) {
    currentAbortController.abort();
    currentAbortController = null;
  }
  syncSendButtonState();
}

// Sanitize raw markdown text for TTS: strip URLs, citations, and formatting
function sanitizeForTTS(text) {
  return String(text || '')
    // Strip URLs (must come before citation removal)
    .replace(/https?:\/\/[^\s)]+|www\.[^\s)]+/g, '')
    // Strip markdown citation links: [[1]](url) or [[1]]() -> empty
    .replace(/\[\[(\d+)\]\]\([^)]*\)/g, '')
    // Strip remaining markdown links: [text](url) -> text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    // Strip bold/italic: ***text***, **text**, *text*
    .replace(/\*{1,3}([^*]+)\*{1,3}/g, '$1')
    // Strip underline bold/italic: ___text___, __text__, _text_
    .replace(/_{1,3}([^_]+)_{1,3}/g, '$1')
    // Strip strikethrough: ~~text~~
    .replace(/~~([^~]+)~~/g, '$1')
    // Strip inline code: `text`
    .replace(/`([^`]*)`/g, '$1')
    // Strip heading markers: ### heading
    .replace(/^#{1,6}\s+/gm, '')
    // Collapse multiple spaces into one
    .replace(/  +/g, ' ')
    .trim();
}

/** Full TTS source text for an AI message (data-original preferred, then visible DOM). */
function getMessageTtsText($messageElement) {
  let fullText = $messageElement.attr('data-original') || '';
  if (fullText) {
    fullText = fullText.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  }
  if (!fullText) {
    const $textClone = $messageElement.find('.ai-message-text').clone();
    $textClone.find('.thinking-container').remove();
    $textClone.find('.regenerate-container').remove();
    fullText = $textClone.text().trim();
  }
  fullText = sanitizeForTTS(fullText);
  if (fullText === 'Thinking...') return '';
  if (/^\[Error\]/.test(fullText) || /^Error:/.test(fullText)) return '';
  return fullText;
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
 * Whether a sentence string already ends with a terminator (incl. ellipsis).
 * Used when streaming: do not enqueue an unfinished trailing fragment.
 */
function sentenceEndsWithTerminator(sentenceText) {
  const s = String(sentenceText || '');
  // Terminator is . ! ? … or a run of periods (...), then optional closers.
  return /(?:\.{1,}|[!?…])["'”’)\]]*$/.test(s);
}

/** True if `ch` is an ASCII digit (0-9). */
function isAsciiDigit(ch) {
  return ch >= '0' && ch <= '9';
}

/**
 * Split plain text into sentences. Single algorithm used for:
 * - hover highlight bounds
 * - click-to-play sentence selection
 * - voice-mode discover
 * Do NOT sanitize before splitting (sanitize changes boundaries / can drop the first sentence).
 *
 * Ellipsis "..." / ".." / "…." is ONE terminator — never three empty "." sentences.
 *
 * Decimal/version dots like "4.6", "3.14", "1.2.3" are NOT sentence terminators
 * (a period between two digits is a number separator, not end-of-sentence).
 *
 * @returns {{start:number, end:number, text:string}[]}
 */
function splitSentences(text) {
  const out = [];
  if (!text) return out;
  let i = 0;
  const n = text.length;
  while (i < n) {
    // Skip whitespace between sentences (not part of either sentence).
    while (i < n && /\s/.test(text.charAt(i))) i++;
    if (i >= n) break;
    const start = i;
    let end = i;
    while (end < n) {
      const c = text.charAt(end);
      if (c === '.' || c === '!' || c === '?' || c === '\u2026' /* … */) {
        if (c === '.') {
          // Decimal/version dot: digit on BOTH sides → not a terminator.
          // "4.6", "3.14", "1.2.3" stay inside one sentence so TTS does not pause.
          const prev = end > 0 ? text.charAt(end - 1) : '';
          const next = end + 1 < n ? text.charAt(end + 1) : '';
          if (isAsciiDigit(prev) && isAsciiDigit(next)) {
            end++;
            continue;
          }
          // Consume the whole run: "..." is one terminator, not three sentences.
          while (end < n && text.charAt(end) === '.') end++;
        } else if (c === '\u2026') {
          end++;
        } else {
          // ! or ? — keep "?!?!" as a single trailing burst on this sentence.
          while (end < n && (text.charAt(end) === '!' || text.charAt(end) === '?')) end++;
        }
        // Include trailing closers: ..."  )'
        while (end < n && /["'”’)\]]/.test(text.charAt(end))) end++;
        break;
      }
      end++;
    }
    if (end > start) {
      out.push({ start: start, end: end, text: text.slice(start, end) });
    }
    i = end;
  }
  return out;
}

/** Index of the sentence containing caret offset, or -1. */
function sentenceIndexAtOffset(sentences, offset) {
  if (!sentences || !sentences.length) return -1;
  const o = Math.max(0, offset);
  for (let i = 0; i < sentences.length; i++) {
    const s = sentences[i];
    // Whitespace before the first sentence → first sentence.
    if (o < s.start) return i;
    // Inside [start, end) or on the final character of the sentence.
    if (o < s.end) return i;
    // Exactly at end boundary: if there is a next sentence, caret sits between them → next.
    if (o === s.end && i + 1 < sentences.length) continue;
    if (o === s.end) return i;
  }
  return sentences.length - 1;
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
    badge.innerHTML = isPlaying
      ? '<i class="bi bi-stop-fill"></i>'
      : '<i class="bi bi-play-fill"></i>';
    const badgeSize = 22;
    badge.style.left = Math.max(0, firstRect.left - badgeSize - 4) + 'px';
    badge.style.top = (firstRect.top + (firstRect.height - badgeSize) / 2) + 'px';
    document.body.appendChild(badge);
  }
  return sentence;
}

/**
 * Fetch one TTS token and play it on the shared HTMLAudioElement.
 * Resolves true when that clip finished while the session is still live.
 */
function playOneTtsUtterance(sessionId, text) {
  if (!desktopTtsIsLive(sessionId)) return Promise.resolve(false);
  const cleaned = (sanitizeForTTS(text) || String(text || '')).trim();
  if (!cleaned) return Promise.resolve(true);

  const signal = desktopTtsAbort ? desktopTtsAbort.signal : undefined;
  return fetchVoiceRetry('/tts', {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ text: cleaned }),
    signal: signal
  })
  .then(function (r) {
    if (!desktopTtsIsLive(sessionId)) return null;
    return r.json();
  })
  .then(function (data) {
    if (!desktopTtsIsLive(sessionId) || !data || !data.token) return false;
    const audio = getDesktopTtsAudio();
    return new Promise(function (resolve) {
      if (!desktopTtsIsLive(sessionId)) {
        resolve(false);
        return;
      }
      let settled = false;
      let clipAttempt = 0;
      const clipUrl = '/tts_stream/' + encodeURIComponent(data.token);
      const finish = function (ok) {
        if (settled) return;
        settled = true;
        audio.onended = null;
        audio.onerror = null;
        if (window.voiceModeActive) {
          voiceModeTtsPlaying = false;
          if (typeof window.notifyVoiceModeTtsEnded === 'function') {
            window.notifyVoiceModeTtsEnded();
          }
        }
        resolve(!!ok && desktopTtsIsLive(sessionId));
      };
      // A dropped clip GET fires the media element's error event (browsers do
      // not retry media requests). The server retains a generated WAV for
      // bounded replays and re-arms a failed generation, so retry the same
      // token with backoff before failing the sentence. An autoplay-blocked
      // play() (NotAllowedError) is not transient and stays fatal.
      const startClip = function () {
        if (settled) return;
        clipAttempt += 1;
        const myAttempt = clipAttempt;
        let attemptFailed = false;
        const failAttempt = function (err) {
          if (settled || attemptFailed || myAttempt !== clipAttempt) return;
          attemptFailed = true;
          if (err && err.name === 'NotAllowedError') {
            console.error('TTS audio.play() failed:', err);
            finish(false);
            return;
          }
          if (clipAttempt >= MAX_TTS_CLIP_ATTEMPTS || !desktopTtsIsLive(sessionId)) {
            finish(false);
            return;
          }
          setTimeout(function () {
            if (settled || !desktopTtsIsLive(sessionId)) return;
            startClip();
          }, TTS_CLIP_RETRY_BACKOFF_MS * clipAttempt);
        };
        audio.onended = function () { finish(true); };
        audio.onerror = function () { failAttempt(null); };
        // Always assign a fresh absolute URL; prior load() cleared the element.
        audio.src = clipUrl;
        if (window.voiceModeActive) {
          voiceModeTtsPlaying = true;
          if (typeof window.notifyVoiceModeTtsStarted === 'function') {
            window.notifyVoiceModeTtsStarted();
          }
        }
        const playPromise = audio.play();
        if (playPromise && typeof playPromise.then === 'function') {
          playPromise.catch(function (err) {
            failAttempt(err);
          });
        }
      };
      startClip();
    });
  })
  .catch(function (err) {
    if (err && (err.name === 'AbortError' || (err.message && err.message.indexOf('aborted') !== -1))) {
      return false;
    }
    console.error('TTS error:', err);
    return false;
  });
}

/**
 * Play a fixed list of sentences (click-a-sentence path).
 * Sentences are already split from DOM text; we only sanitize per item for the API.
 */
function playFixedSentenceList(sessionId, button, sentences) {
  let chain = Promise.resolve(true);
  sentences.forEach(function (sentenceText) {
    chain = chain.then(function (still) {
      if (!still || !desktopTtsIsLive(sessionId)) return false;
      return playOneTtsUtterance(sessionId, sentenceText);
    });
  });
  chain.then(function () {
    if (!desktopTtsIsLive(sessionId)) return;
    completeDesktopTtsPlayback(button);
  });
}

/**
 * Play from message body (play button). Supports streaming generation.
 */
function playMessageBodyTts(sessionId, button, $messageElement) {
  // Absolute character offset into getMessageTtsText(); only sentences with end > consumed
  // are enqueued. sanitizeForTTS can shrink already-consumed text later (a markdown
  // emphasis/inline-code pair closing after the boundary sentence), so starts may
  // drift below the boundary; ends only ever move left when sanitize shrinks
  // completed text, so the end guard alone prevents replaying a sentence.
  let consumedLen = 0;
  let queue = [];
  let running = false;
  let observer = null;
  let pollTimer = null;
  let sentenceRetries = 0;
  let retryScheduled = false;

  function isStillGenerating() {
    const currentRawText = $messageElement.find('.ai-message-text').text().trim();
    return currentRawText === 'Thinking...' || (currentAbortController !== null);
  }

  function discoverAbsolute() {
    if (!desktopTtsIsLive(sessionId)) return;
    const full = getMessageTtsText($messageElement);
    if (!full || full.length <= consumedLen) return;
    const sentences = splitSentences(full);
    for (let i = 0; i < sentences.length; i++) {
      const s = sentences[i];
      if (s.end <= consumedLen) continue;
      if (!sentenceEndsWithTerminator(s.text) && isStillGenerating()) break;
      queue.push(s.text);
      consumedLen = s.end;
    }
  }

  // React to streaming text updates immediately. Polling still runs as a
  // safety net in case MutationObserver is unavailable or misses an update
  // (e.g. the LLM was idle and emitted a long buffer in one chunk).
  function onTextChanged() {
    if (!desktopTtsIsLive(sessionId)) {
      teardownObserver();
      return;
    }
    discoverAbsolute();
    if (!running && queue.length) pump();
  }

  function teardownObserver() {
    if (observer) {
      try { observer.disconnect(); } catch (e) { /* ignore */ }
      observer = null;
    }
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function finishIfIdle() {
    if (!desktopTtsIsLive(sessionId)) {
      teardownObserver();
      return;
    }
    if (running || queue.length) return;
    if (isStillGenerating()) {
      pollTimer = setTimeout(function () {
        pollTimer = null;
        if (!desktopTtsIsLive(sessionId)) return;
        discoverAbsolute();
        pump();
      }, 60);
      return;
    }
    discoverAbsolute();
    if (queue.length) {
      pump();
      return;
    }
    teardownObserver();
    completeDesktopTtsPlayback(button);
  }

  function pump() {
    if (!desktopTtsIsLive(sessionId) || running || retryScheduled) return;
    discoverAbsolute();
    if (!queue.length) {
      finishIfIdle();
      return;
    }
    running = true;
    const next = queue.shift();
    playOneTtsUtterance(sessionId, next).then(function (ok) {
      running = false;
      if (!desktopTtsIsLive(sessionId)) {
        teardownObserver();
        return;
      }
      if (!ok) {
        // Transient failure (token fetch, clip GET, playback): requeue with
        // backoff like the native sentence pump so a spotty link delays the
        // sentence instead of ending speech after the last good one. Bounded
        // so a dead sentence cannot churn forever; after that, skip it.
        if (sentenceRetries < MAX_TTS_SENTENCE_RETRIES) {
          sentenceRetries += 1;
          queue.unshift(next);
          retryScheduled = true;
          setTimeout(function () {
            retryScheduled = false;
            pump();
          }, 400 * sentenceRetries);
          return;
        }
        sentenceRetries = 0;
        console.error('Desktop TTS sentence failed; skipping after retries');
        pump();
        return;
      }
      sentenceRetries = 0;
      pump();
    });
  }

  // Hook into the visible text node so we can start TTS on the first sentence
  // the moment it lands, without waiting for the 60 ms poll cycle. This is
  // the main latency win since the web-search/tool-calling flow added the
  // extra search + second LLM hop.
  const textEl = $messageElement.find('.ai-message-text')[0];
  if (textEl && typeof MutationObserver === 'function') {
    observer = new MutationObserver(onTextChanged);
    observer.observe(textEl, { childList: true, subtree: true, characterData: true });
  }

  pump();
}

/**
 * Play TTS for an AI message.
 * options.sentences — string[] already split from the clicked DOM sentence onward.
 *   When provided, those exact strings are spoken in order (highlight === audio).
 * Without options: speak full message from data-original / DOM (play button).
 */
window.playTTS = function playTTS(button, options) {
  options = options || {};

  // Toggle stop when this control is already the active speaker.
  if (CURRENT_AUDIO && CURRENT_AUDIO_BUTTON === button) {
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
  const sessionId = desktopTtsSession;
  desktopTtsAbort = new AbortController();

  CURRENT_AUDIO = {
    sessionId: sessionId,
    stop: function () { stopCurrentDesktopTts(); }
  };
  CURRENT_AUDIO_BUTTON = button;
  if (window.voiceModeActive) {
    voiceModeTtsSessionActive = true;
    if (typeof syncSendButtonState === 'function') {
      syncSendButtonState();
    }
  }

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
  if (window.voiceModeActive && window.nativeVoiceTtsAvailable
      && typeof window.playNativeVoiceModeTts === 'function') {
    window.playNativeVoiceModeTts(button, options);
    return;
  }
  window.playTTS(button, options);
};

/** Voice mode uses the same playTTS / HTML Audio path as the play button. */
function playMessageTts(button, options) {
  if (window.voiceModeActive && typeof window.playTTSVoiceMode === 'function') {
    window.playTTSVoiceMode(button, options);
    return;
  }
  window.playTTS(button, options);
}
window.playMessageTts = playMessageTts;

window.regenerateMessage = function regenerateMessage(button) {
  const $aiMessageElement = $(button).closest('.message');
  const $previousUserMessage = $aiMessageElement.prev('.message.user-message');
  if ($previousUserMessage.length === 0) return;
  let userText = ($previousUserMessage.attr('data-original') || ($previousUserMessage.find('.user-message-text').text() || $previousUserMessage.text() || '').replace(/^\s*You:\s*/, '')).trim();
  if ($previousUserMessage.attr('data-local-only') === '1') {
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

  fetchWithGenerateRetry('/regenerate', {
    method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }),
    signal: currentAbortController.signal,
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
    if (response.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
    if (!response.ok) {
      return response.text().then(t => {
        let errData = null;
        try { errData = t ? JSON.parse(t) : null; } catch (e) { errData = null; }
        if (errData && errData.error === 'version_conflict' && isLiveChatRequest(seq)) {
          // Adopt the authoritative version and replay the regeneration once.
          noteSetVersionFromResponse(errData);
          if (!opts.versionRetried) {
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
    let buffer = '';
    let state = 'visible';
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
      $target.attr('data-original', fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : ''));
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
      $target.attr('data-original', fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : ''));
    }
    function processBuffer() {
      const openTag = '<think>';
      const closeTags = ['</think>', '[BEGIN FINAL RESPONSE]'];

      while (buffer.length > 0) {
        if (state === 'visible') {
          const tagStart = buffer.indexOf(openTag);
          if (tagStart !== -1) {
            const visiblePart = buffer.substring(0, tagStart);
            appendVisible(visiblePart);
            buffer = buffer.substring(tagStart + openTag.length);
            state = 'thinking';
            continue;
          } else {
            let flushableEnd = buffer.length;
            for (let i = 1; i <= buffer.length && i <= openTag.length; i++) {
              const suffix = buffer.substring(buffer.length - i);
              if (openTag.startsWith(suffix)) { flushableEnd = buffer.length - i; break; }
            }
            const visiblePart = buffer.substring(0, flushableEnd);
            appendVisible(visiblePart);
            buffer = buffer.substring(flushableEnd);
            break;
          }
        } else {
          let firstCloseTagIndex = -1;
          let actualCloseTag = '';

          for (const tag of closeTags) {
            const idx = buffer.indexOf(tag);
            if (idx !== -1 && (firstCloseTagIndex === -1 || idx < firstCloseTagIndex)) {
              firstCloseTagIndex = idx;
              actualCloseTag = tag;
            }
          }

          if (firstCloseTagIndex !== -1) {
            const thinkingPart = buffer.substring(0, firstCloseTagIndex);
            appendThinking(thinkingPart);
            buffer = buffer.substring(firstCloseTagIndex + actualCloseTag.length);
            state = 'visible';
            continue;
          } else {
            let flushableEnd = buffer.length;
            const maxTagLen = Math.max(...closeTags.map(t => t.length));
            for (let i = 1; i <= buffer.length && i <= maxTagLen; i++) {
              const suffix = buffer.substring(buffer.length - i);
              if (closeTags.some(tag => tag.startsWith(suffix))) {
                flushableEnd = buffer.length - i;
                break;
              }
            }
            const thinkingPart = buffer.substring(0, flushableEnd);
            appendThinking(thinkingPart);
            buffer = buffer.substring(flushableEnd);
            break;
          }
        }
      }
    }
            function read() {
          reader.read().then(({done, value}) => {
            if (done) {
              const finalAiOriginal = fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : '');
              $target.attr('data-original', finalAiOriginal);
              
              try {
                $target.find('.regenerate-button').prop('disabled', false);
                const playBtn = $target.find('.play-button').prop('disabled', false);
                if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
              } catch (e) {}
              finishChatRequest(seq);
              var $regenUser = $target.prev('.message.user-message');
              clearLocalOnlyTurn($regenUser, $target);
              noteLocalVersionBumpAfterPersist();
              if (typeof loadSets === 'function') loadSets(false);
              return;
            }
            buffer += decoder.decode(value, {stream:true});
            const nearBottom = shouldStickChatToBottom();
            processBuffer();
            if (nearBottom) {
              scrollToBottom();
            }
            read();
          }).catch(err => {
            if (!isLiveChatRequest(seq)) return;
            try {
              $target.find('.regenerate-button').prop('disabled', false);
              const playBtn = $target.find('.play-button').prop('disabled', false);
              if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            finishChatRequest(seq);
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
          if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
        } catch (e) {}
        finishChatRequest(seq);
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
    if (r.status === 401) { window.location.href = '/login'; return null; }
    return r.json().then(data => ({ ok: r.ok, status: r.status, data }));
  })
  .then(result => {
    if (!result) return;
    if (result.data && result.data.error === 'version_conflict') {
      applySetVersion(result.data.current_version, result.data.set_id, { allowRewind: true });
      if (!isRetry) {
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
      if (HISTORY_TOTAL > 0) HISTORY_TOTAL -= 1;
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
          autoplay_tts: autoplayTTS
      };

      fetch('/update_preferences', {
          method: 'POST',
          headers: withCsrf({ 'Content-Type': 'application/json' }),
          body: JSON.stringify(preferences)
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
    const isPlaying = !!(CURRENT_AUDIO && $(el).closest('.message').find('.play-button')[0] === CURRENT_AUDIO_BUTTON);
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
    if (CURRENT_AUDIO && $(this).closest('.message').find('.play-button')[0] === CURRENT_AUDIO_BUTTON) {
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
    if (CURRENT_AUDIO && CURRENT_AUDIO_BUTTON === playBtn) {
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

  // Load sets for logged-in users (wait for encryption key from login storage first)
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
          if (!r.ok) {
            throw new Error('Failed to load sets');
          }
          return r;
        })
        .then(r => r.json())
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
      HISTORY_SET_GEN += 1;
      var loadGen = HISTORY_SET_GEN;
      savePreferences();
      function fetchSet() {
        return withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
          return fetch('/load_set', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
              set_id: setId,
              set_name: setName,
              limit: HISTORY_PAGE_SIZE,
              thumbnails: true
            })
          });
        });
      }
      fetchSet()
        .then(async r => {
          if (r.status === 401) {
            return handle401OrRetry(r, fetchSet);
          }
          if (!r.ok) {
            try { const err = await r.json(); throw new Error(err && (err.error || err.message) || 'Failed to load set'); }
            catch (_) { throw new Error('Failed to load set'); }
          }
          return r;
        })
        .then(r => r.json())
        .then(data => {
          if (loadGen !== HISTORY_SET_GEN) return;
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
      beginEncKeyUnlockFlow();
    });

    $('#new-set').on('click', function() {
      const setName = prompt('Enter name for new set:');
      if (setName) {
        fetch('/create_set', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ set_name: setName }) })
          .then(r => r.json())
          .then(data => {
            if (data.status === 'success') {
              const newId = data.set_id;
              window.APP_DATA.lastSetId = newId;
              window.APP_DATA.lastSet = data.name || setName;
              loadSets(false).then(() => {
                if (newId) $('#set-selector').val(newId);
                $('#set-selector').trigger('change');
              });
              appendMessage('Created new set: ' + setName, 'system-message');
            } else {
              appendMessage(data.error || 'Failed to create set', 'error-message');
            }
          });
      }
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
          if (!isRetry) return submitRenameSet(setId, oldName, newName, true);
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
            if (!isRetry) return submitDeleteSet(setId, setName, true);
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
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          noteSetVersionFromResponse(data);
          appendMessage('System prompt saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          // Sync the authoritative version and retry once — e.g. a chat turn
          // finalized (or a prompt updated from another tab) since page load.
          noteSetVersionFromResponse(data);
          if (!isRetry) return saveSystemPromptNow(sysPromptText, true);
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
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          noteSetVersionFromResponse(data);
          appendMessage('Memory saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          noteSetVersionFromResponse(data);
          if (!isRetry) return saveMemoryNow(memText, true);
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
      if ($ghost.attr('data-local-only') === '1') {
        removeLocalOnlyTurn($ghost);
      }
      pairIndex = HISTORY_OFFSET + document.querySelectorAll('#chat-content .message.user-message').length;
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
      signal: currentAbortController.signal,
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
              if (!opts.versionRetried) {
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

        if (window.APP_DATA.autoplayTTS || window.voiceModeActive) {
          const playBtn = $targetElement.find('.play-button')[0];
          if (playBtn) setTimeout(() => playMessageTts(playBtn), 50);
        }

        // Initial scroll to bottom when AI starts responding
        scrollToBottom();
        const $messageTextElement = $targetElement.find('.ai-message-text');
        const $thinkingContainerWrapper = $targetElement.find('.thinking-container');
        const $thinkingContentElement = $targetElement.find('.thinking-content');
        let buffer = '';
        let state = 'visible';
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
          $targetElement.attr('data-original', fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : ''));
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
          $targetElement.attr('data-original', fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : ''));
        }
        function processChunk(chunk) {
          buffer += chunk;
          const openTag = '<think>';
          const closeTags = ['</think>', '[BEGIN FINAL RESPONSE]'];

          while (buffer.length > 0) {
            if (state === 'visible') {
              const tagStart = buffer.indexOf(openTag);
              if (tagStart !== -1) {
                const visiblePart = buffer.substring(0, tagStart);
                appendVisible(visiblePart);
                buffer = buffer.substring(tagStart + openTag.length);
                state = 'thinking';
                continue;
              } else {
                let flushableEnd = buffer.length;
                for (let i = 1; i <= buffer.length && i <= openTag.length; i++) {
                  const suffix = buffer.substring(buffer.length - i);
                  if (openTag.startsWith(suffix)) { flushableEnd = buffer.length - i; break; }
                }
                const visiblePart = buffer.substring(0, flushableEnd);
                appendVisible(visiblePart);
                buffer = buffer.substring(flushableEnd);
                break;
              }
            } else if (state === 'thinking') {
              let firstCloseTagIndex = -1;
              let actualCloseTag = '';

              for (const tag of closeTags) {
                const idx = buffer.indexOf(tag);
                if (idx !== -1 && (firstCloseTagIndex === -1 || idx < firstCloseTagIndex)) {
                  firstCloseTagIndex = idx;
                  actualCloseTag = tag;
                }
              }

              if (firstCloseTagIndex !== -1) {
                const thinkingPart = buffer.substring(0, firstCloseTagIndex);
                appendThinking(thinkingPart);
                buffer = buffer.substring(firstCloseTagIndex + actualCloseTag.length);
                state = 'visible';
                continue;
              } else {
                let flushableEnd = buffer.length;
                const maxTagLen = Math.max(...closeTags.map(t => t.length));
                for (let i = 1; i <= buffer.length && i <= maxTagLen; i++) {
                  const suffix = buffer.substring(buffer.length - i);
                  if (closeTags.some(tag => tag.startsWith(suffix))) {
                    flushableEnd = buffer.length - i;
                    break;
                  }
                }
                const thinkingPart = buffer.substring(0, flushableEnd);
                appendThinking(thinkingPart);
                buffer = buffer.substring(flushableEnd);
                break;
              }
            }
          }
        }
        function readStream() {
          return reader.read().then(({ done, value }) => {
            if (done) {
              if (buffer) {
                if (state === 'thinking') appendThinking(buffer); else appendVisible(buffer);
                buffer = '';
              }
              
              const finalAiOriginal = fullVisibleText + (fullThinkingText ? '<think>' + fullThinkingText + '</think>' : '');
              $targetElement.attr('data-original', finalAiOriginal);

              try {
                $targetElement.find('.regenerate-button').prop('disabled', false);
                const playBtn = $targetElement.find('.play-button').prop('disabled', false);
                if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
              } catch (e) {}
              finishChatRequest(seq);
              HISTORY_TOTAL = Math.max(HISTORY_TOTAL, pairIndex + 1);
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
              if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            const errText = err && err.message ? err.message : String(err);
            if (buffer) {
              if (state === 'thinking') appendThinking(buffer); else appendVisible(buffer);
              buffer = '';
            }
            appendVisible('\n[Error] Stream interrupted: ' + errText);
            finishChatRequest(seq);
          });
        }
        readStream();
      })
      .catch(error => {
        if (!isLiveChatRequest(seq)) return;
        if (error.name === 'AbortError') {
          const $lastAI = $('.ai-message:last-child');
          $lastAI.find('.ai-message-text').append(' [Stopped]');
          try {
            $lastAI.find('.regenerate-button').prop('disabled', false);
            const playBtn = $lastAI.find('.play-button').prop('disabled', false);
            if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
          } catch (e) {}
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
      } else {
          $(this).removeClass('btn-outline-secondary').addClass('btn-primary');
          $(this).attr('title', 'Web Search: ON');
      }
  });

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

        window.NativeMic.stop().then(function () {
          if (_nativeMicPcmChunks.length === 0) return;
          const pcm16 = NativeAudio.mergePcm16Chunks(_nativeMicPcmChunks);
          const wavBlob = NativeAudio.pcm16ToWavBlob(pcm16);

          _nativeMicPcmChunks = [];

          fetchVoiceRetry('/stt', function () {
            const retryForm = new FormData();
            retryForm.append('audio', wavBlob, 'recording.wav');
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
  let voiceSttAbortController = null;
  // High-confidence Silero frames (~32 ms each) before desktop barge-in.
  let bargeInFrames = 0;
  const BARGE_IN_FRAMES_DESKTOP = 4;
  const BARGE_IN_SPEECH_PROB = 0.85;
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

  function NativeMicUtteranceVAD(onError) {
    this.onError = onError;
    this.preRollBuffer = new NativeAudio.Pcm16RingBuffer(NativeAudio.SPEECH_PREROLL_SAMPLES);
    this.utteranceChunks = [];
    this.startGateChunks = [];
    this.inSpeech = false;
    this.speechAboveCount = 0;
    this.nonSpeechLikeCount = 0;
    this.bargeInFired = false;
    this.silenceMs = 0;
    this.speechActiveMs = 0;
    this.speechLikeMs = 0;
    this.voicedMs = 0;
    this.voicedWindow = [];
    this.nativeListener = null;
    this.isRecording = false;
    this.chunkCount = 0;
  }

  NativeMicUtteranceVAD.prototype._resetSpeechCounters = function () {
    this.speechAboveCount = 0;
    this.nonSpeechLikeCount = 0;
    this.startGateChunks = [];
    this.bargeInFired = false;
    this.silenceMs = 0;
    this.speechActiveMs = 0;
    this.speechLikeMs = 0;
    this.voicedMs = 0;
    this.voicedWindow = [];
  };

  /** Phase 1: start capture on speech-like energy. Does not stop TTS. */
  NativeMicUtteranceVAD.prototype._maybeStartUtterance = function _maybeStartUtterance(pcm16, rms, skipPreRoll) {
    if (this.inSpeech) return false;
    if (NativeAudio.pcm16IsSpeechLike(pcm16, rms)) {
      this.startGateChunks.push(pcm16.slice());
      this.speechAboveCount++;
      this.nonSpeechLikeCount = 0;
      if (this.speechAboveCount >= NativeAudio.SPEECH_START_FRAMES) {
        nativeLog('VAD', (skipPreRoll ? 'tts ' : '') + 'utterance start rms=' + Math.round(rms));
        this._beginUtterance(skipPreRoll);
        return true;
      }
    } else if (rms > NativeAudio.SPEECH_RMS_THRESHOLD) {
      this.nonSpeechLikeCount++;
      if (this.nonSpeechLikeCount >= NativeAudio.SPEECH_START_MISS_FRAMES) {
        this.speechAboveCount = 0;
        this.startGateChunks = [];
      }
    } else {
      this.speechAboveCount = 0;
      this.nonSpeechLikeCount = 0;
      this.startGateChunks = [];
    }
    return false;
  };

  /** Phase 2: stop TTS now if real speech is confirmed. Not called from _endUtterance. */
  NativeMicUtteranceVAD.prototype._maybeBargeIn = function _maybeBargeIn() {
    if (this.bargeInFired) return;
    if (!(voiceModeTtsSessionActive || voiceModeTtsPlaying)) return;
    if (!NativeAudio.pcm16RealSpeechDetected(this.speechLikeMs, this.voicedMs)) return;
    this.bargeInFired = true;
    nativeLog('VAD', 'barge-in on real speech likeMs=' + this.speechLikeMs
      + ' voicedMs=' + this.voicedMs);
    handleBargeIn();
  };

  NativeMicUtteranceVAD.prototype._noteVoicedFrame = function _noteVoicedFrame(copy, frameMs) {
    this.voicedWindow.push(copy);
    const w = NativeAudio.SPEECH_VOICED_WINDOW_FRAMES;
    if (this.voicedWindow.length > w) this.voicedWindow.shift();
    if (this.voicedWindow.length >= w) {
      const win = NativeAudio.mergePcm16Chunks(this.voicedWindow);
      if (NativeAudio.pcm16IsVoicedSpeech(win)) this.voicedMs += frameMs;
    }
  };

  NativeMicUtteranceVAD.prototype._accumulateUtterance = function _accumulateUtterance(copy, rms, frameMs) {
    this.utteranceChunks.push(copy);
    if (NativeAudio.pcm16IsSpeechLike(copy, rms)) {
      this.silenceMs = 0;
      this.speechActiveMs += frameMs;
      this.speechLikeMs += frameMs;
      this._noteVoicedFrame(copy, frameMs);
    } else {
      this.silenceMs += frameMs;
      this.voicedWindow = [];
      if (this.silenceMs >= NativeAudio.SPEECH_END_SILENCE_MS) {
        this._endUtterance();
        return;
      }
    }
    this._maybeBargeIn();
  };

  NativeMicUtteranceVAD.prototype._onNativePcm = function _onNativePcm(pcm16) {
    if (!this.isRecording || !window.voiceModeActive) return;
    const copy = pcm16.slice();
    const rms = NativeAudio.pcm16Rms(copy);
    const frameMs = 20;
    const now = Date.now();

    this.preRollBuffer.push(copy);
    this.chunkCount++;

    // During TTS: record from speech-like start (Silero onSpeechStart). Barge-in
    // only after real speech (REAL_SPEECH_MS + voicing), not on cough/"hey".
    if (voiceModeTtsSessionActive || voiceModeTtsPlaying) {
      const started = this._maybeStartUtterance(copy, rms, true);
      if (this.inSpeech && !started) {
        this._accumulateUtterance(copy, rms, frameMs);
      }
      if (this.chunkCount % 50 === 0) {
        nativeLog('VAD', 'pcm#' + this.chunkCount + ' ttsSess=1 ttsPlay=' + voiceModeTtsPlaying
          + ' inSpeech=' + this.inSpeech + ' speechMs=' + this.speechActiveMs
          + ' rms=' + Math.round(rms));
      }
      return;
    }

    if (now < voiceModeListenCooldownUntil) {
      return;
    }

    const started = this._maybeStartUtterance(copy, rms, false);
    if (this.inSpeech && !started) {
      this._accumulateUtterance(copy, rms, frameMs);
    }

    if (this.chunkCount % 50 === 0) {
      nativeLog('VAD', 'pcm#' + this.chunkCount + ' inSpeech=' + this.inSpeech
        + ' ttsPlay=' + voiceModeTtsPlaying + ' rms=' + Math.round(rms));
    }
  };

  /** Start recording. Barge-in is _maybeBargeIn, not here. */
  NativeMicUtteranceVAD.prototype._beginUtterance = function _beginUtterance(skipPreRoll) {
    if (this.inSpeech) return;
    this.inSpeech = true;
    const startChunks = this.startGateChunks;
    this.startGateChunks = [];
    this._resetSpeechCounters();
    this.utteranceStartedAt = Date.now();
    lastVoiceUtteranceStartedAt = this.utteranceStartedAt;
    this.speechActiveMs = startChunks.length * 20;
    this.speechLikeMs = startChunks.length * 20;
    this.voicedMs = NativeAudio.pcm16VoicedMsFromChunks(startChunks, 20);
    this.voicedWindow = startChunks.slice(-NativeAudio.SPEECH_VOICED_WINDOW_FRAMES);
    if (skipPreRoll) {
      // Keep the speech-like start-gate frames; drop earlier pre-roll (TTS leak).
      this.utteranceChunks = startChunks;
      nativeLog('VAD', 'utterance begin (during TTS, start-gate frames=' + startChunks.length + ')');
    } else {
      this.utteranceChunks = this.preRollBuffer.snapshotChunks();
      nativeLog('VAD', 'utterance begin preRollChunks=' + this.utteranceChunks.length);
    }
    this._maybeBargeIn();
  };

  NativeMicUtteranceVAD.prototype._endUtterance = function _endUtterance() {
    if (!this.inSpeech) return;
    this.inSpeech = false;
    this.speechAboveCount = 0;
    this.nonSpeechLikeCount = 0;
    this.silenceMs = 0;
    this.bargeInFired = false;
    this.speechLikeMs = 0;
    this.voicedMs = 0;
    this.voicedWindow = [];
    if (this.speechActiveMs < NativeAudio.SPEECH_MIN_ACTIVE_MS) {
      nativeLog('VAD', 'utterance rejected: speechActiveMs=' + this.speechActiveMs
        + ' min=' + NativeAudio.SPEECH_MIN_ACTIVE_MS);
      this.utteranceChunks = [];
      this.speechActiveMs = 0;
      return;
    }
    nativeLog('VAD', 'utterance end chunks=' + this.utteranceChunks.length
      + ' speechMs=' + this.speechActiveMs);
    handleSpeechEnd();
  };

  NativeMicUtteranceVAD.prototype.takeSpeechWavBlob = function () {
    const pcm16 = NativeAudio.mergePcm16Chunks(this.utteranceChunks);
    this.utteranceChunks = [];
    return NativeAudio.pcm16ToWavBlob(pcm16);
  };

  NativeMicUtteranceVAD.prototype.hasSpeechCapture = function () {
    return this.utteranceChunks.length > 0;
  };

  NativeMicUtteranceVAD.prototype.hasCompletedSpeechCapture = function () {
    return !this.inSpeech && this.utteranceChunks.length > 0;
  };

  NativeMicUtteranceVAD.prototype.start = async function () {
    const self = this;
    if (typeof NativeAudio === 'undefined') {
      throw new Error('native-audio.js not loaded');
    }
    try {
      nativeLog('VAD', 'NativeMicUtteranceVAD start (RMS v' + NativeAudio.VOICE_MODE_NATIVE_VAD_VERSION + ')');
      this.preRollBuffer.clear();
      this.utteranceChunks = [];
      this.startGateChunks = [];
      this.inSpeech = false;
      this._resetSpeechCounters();
      this.chunkCount = 0;

      if (nativeMicBridge !== this) {
        throw new Error('native VAD start superseded');
      }
      if (nativeMicStopPromise) {
        await nativeMicStopPromise;
      }
      if (nativeMicBridge !== this) {
        throw new Error('native VAD start superseded');
      }
      await ensureNativeMicPermission();
      if (nativeMicBridge !== this) {
        throw new Error('native VAD start superseded');
      }
      try {
        await window.NativeMic.start();
      } catch (first) {
        const firstMsg = first && first.message ? first.message : String(first);
        if (/permission/i.test(firstMsg)) throw first;
        nativeLog('VAD', 'NativeMic.start retry after: ' + firstMsg);
        if (nativeMicBridge !== this) {
          throw new Error('native VAD start superseded');
        }
        const retryStopPromise = Promise.resolve().then(function () {
          return window.NativeMic.stop();
        });
        nativeMicStopPromise = retryStopPromise;
        try {
          await retryStopPromise;
        } finally {
          if (nativeMicStopPromise === retryStopPromise) {
            nativeMicStopPromise = null;
          }
        }
        if (nativeMicBridge !== this) {
          throw new Error('native VAD start superseded');
        }
        await window.NativeMic.start();
      }

      if (nativeMicBridge !== this) {
        throw new Error('native VAD start superseded');
      }
      this.nativeListener = window.NativeMic.addListener('nativeMicData', function (data) {
        if (!self.isRecording || !window.voiceModeActive) return;
        if (!data || !data.data) return;
        try {
          self._onNativePcm(NativeAudio.decodeNativePcmBase64(data.data));
        } catch (err) {
          nativeLog('VAD', 'PCM decode error: ' + err.message);
        }
      });
      this.isRecording = true;
    } catch (err) {
      nativeLog('VAD', 'NativeMicUtteranceVAD start failed: ' + (err && err.message ? err.message : err));
      throw err;
    }
  };

  NativeMicUtteranceVAD.prototype.stop = async function () {
    try {
      this.isRecording = false;
      this.inSpeech = false;

      if (this.nativeListener) {
        this.nativeListener.remove();
        this.nativeListener = null;
      }

      this.preRollBuffer.clear();
      this.utteranceChunks = [];
      this.startGateChunks = [];
      if (nativeMicBridge === this) {
        const stopPromise = Promise.resolve().then(function () {
          return window.NativeMic.stop();
        });
        nativeMicStopPromise = stopPromise;
        try {
          await stopPromise;
        } finally {
          if (nativeMicStopPromise === stopPromise) {
            nativeMicStopPromise = null;
          }
        }
      }
    } catch (err) {
      console.error('Error stopping Voice Mode native VAD:', err);
    }
  };

  NativeMicUtteranceVAD.prototype.reinitialize = async function () {
    nativeLog('VAD', 'reinitialize: native RMS VAD always running');
  };

  NativeMicUtteranceVAD.prototype.onTtsPlaybackStarted = function () {
    this.preRollBuffer.clear();
    this.inSpeech = false;
    this.utteranceChunks = [];
    this.startGateChunks = [];
    this._resetSpeechCounters();
  };

  function onVoiceModeTtsStarted() {
    voiceModeTtsPlaying = true;
    if (nativeMicBridge && nativeMicBridge.onTtsPlaybackStarted) {
      nativeMicBridge.onTtsPlaybackStarted();
    }
    nativeLog('VAD', 'TTS playback started');
  }

  function onVoiceModeTtsEnded() {
    voiceModeTtsPlaying = false;
    nativeLog('VAD', 'TTS playback ended');
  }

  window.notifyVoiceModeTtsStarted = onVoiceModeTtsStarted;
  window.notifyVoiceModeTtsEnded = onVoiceModeTtsEnded;

  let nativeVoiceTtsSessionListener = null;
  let nativeVoiceTtsSessionPromise = null;
  let nativeVoiceTtsGeneration = 0;

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
    nativeVoiceTtsGeneration += 1;
    if (nativeVoiceTtsSessionListener) {
      try { nativeVoiceTtsSessionListener.remove(); } catch (e) { /* ignore */ }
      nativeVoiceTtsSessionListener = null;
    }
    nativeVoiceTtsSessionPromise = null;
  }

  function finishNativeVoiceTts(generation, button) {
    if (generation !== nativeVoiceTtsGeneration) return;
    onVoiceModeTtsEnded();
    voiceModeTtsSessionActive = false;
    voiceModeTtsPlaying = false;
    if (CURRENT_AUDIO && CURRENT_AUDIO.nativeGeneration === generation) {
      CURRENT_AUDIO = null;
      CURRENT_AUDIO_BUTTON = null;
      resetPlayButtonUi(button);
      clearMessageTtsPlayingUi();
    }
    if (nativeVoiceTtsSessionListener) {
      try { nativeVoiceTtsSessionListener.remove(); } catch (e) { /* ignore */ }
      nativeVoiceTtsSessionListener = null;
    }
    nativeVoiceTtsSessionPromise = null;
    armTtsListenCooldown();
    syncSendButtonState();
  }

  function playNativeVoiceModeTts(button, options) {
    options = options || {};
    if (!window.NativeVoiceTts || !window.nativeVoiceTtsAvailable) {
      window.playTTS(button, options);
      return;
    }
    if (CURRENT_AUDIO && CURRENT_AUDIO_BUTTON === button) {
      stopAllTtsPlayback();
      return;
    }
    if (CURRENT_AUDIO) stopAllTtsPlayback();

    invalidateNativeVoiceTts();
    const nativeVoiceTtsStopPromise = window.NativeVoiceTts.stop().catch(function () {});
    stopCurrentDesktopTts();

    const generation = nativeVoiceTtsGeneration;
    const voiceTtsAbortController = new AbortController();
    const ttsSignal = voiceTtsAbortController.signal;
    const $messageElement = $(button).closest('.message');
    const pendingNativeTtsTokens = new Set();
    let stopped = false;
    let processedText = '';
    let sentenceQueue = [];
    let endRequested = false;
    let sentenceRetries = 0;
    let retryScheduled = false;

    voiceModeTtsSessionActive = true;
    voiceModeTtsPlaying = false;
    CURRENT_AUDIO_BUTTON = button;
    CURRENT_AUDIO = {
      nativeGeneration: generation,
      stop: function () {
        stopped = true;
        pendingNativeTtsTokens.forEach(function (token) {
          cancelNativeTtsToken(token);
        });
        pendingNativeTtsTokens.clear();
        try { voiceTtsAbortController.abort(); } catch (e) { /* ignore */ }
        invalidateNativeVoiceTts();
        voiceModeTtsSessionActive = false;
        voiceModeTtsPlaying = false;
        window.NativeVoiceTts.stop().catch(function () {});
      }
    };
    $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
    $messageElement.addClass('tts-is-playing');
    $messageElement.find('.ai-message-text').addClass('tts-is-playing');
    syncSendButtonState();

    function live() {
      return !stopped && generation === nativeVoiceTtsGeneration && window.voiceModeActive;
    }

    function isStillGenerating() {
      const raw = $messageElement.find('.ai-message-text').text().trim();
      return raw === 'Thinking...' || currentAbortController !== null;
    }

    function discoverSentences() {
      if (!live()) return;
      const fullText = getMessageTtsText($messageElement);
      if (!fullText || fullText.length <= processedText.length) return;
      const pending = fullText.substring(processedText.length);
      const parts = splitSentences(pending);
      let advancedTo = 0;
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (!sentenceEndsWithTerminator(part.text) && isStillGenerating()) break;
        sentenceQueue.push(part.text);
        advancedTo = part.end;
      }
      if (advancedTo > 0) processedText += pending.substring(0, advancedTo);
    }

    function ensureSession() {
      if (nativeVoiceTtsSessionPromise) return nativeVoiceTtsSessionPromise;
      nativeVoiceTtsSessionPromise = nativeVoiceTtsStopPromise.then(function () {
        if (!live()) return null;
        return window.NativeVoiceTts.beginSession();
      }).then(function () {
        if (!live()) return;
        nativeVoiceTtsSessionListener = window.NativeVoiceTts.addListener('playbackState', function (data) {
          if (!data || generation !== nativeVoiceTtsGeneration) return;
          if (data.type === 'started') {
            onVoiceModeTtsStarted();
          } else if (data.type === 'ended') {
            finishNativeVoiceTts(generation, button);
          } else if (data.type === 'error') {
            console.error('Native voice TTS error:', data.message);
          }
        });
      });
      return nativeVoiceTtsSessionPromise;
    }

    function markEndOfQueue() {
      if (!live() || endRequested) return;
      endRequested = true;
      ensureSession().then(function () {
        if (live()) return window.NativeVoiceTts.markEndOfQueue();
      }).catch(function (err) {
        if (live()) {
          console.error('Native voice TTS session failed:', err);
          finishNativeVoiceTts(generation, button);
        }
      });
    }

    // Wake the pump on streaming text updates so we don't wait out the 80 ms
    // poll cycle between an LLM finishing a sentence and TTS starting.
    function onTextChanged() {
      if (!live()) {
        teardownObserver();
        return;
      }
      discoverSentences();
      if (sentenceQueue.length > 0 && !pumpInFlight) {
        pump();
      }
    }

    function teardownObserver() {
      if (observer) {
        try { observer.disconnect(); } catch (e) { /* ignore */ }
        observer = null;
      }
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
    }

    let observer = null;
    let pollTimer = null;
    let pumpInFlight = false;

    function pump() {
      if (!live()) return;
      if (pumpInFlight) return;
      discoverSentences();
      if (sentenceQueue.length > 0) {
        const text = String(sentenceQueue.shift() || '').trim();
        if (!text) { pump(); return; }
        pumpInFlight = true;
        ensureSession().then(function () {
          if (!live()) return null;
          return fetchVoiceRetry('/tts', {
            method: 'POST',
            headers: withCsrf({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ text: text }),
            signal: ttsSignal
          });
        }).then(function (response) {
          if (!response) return null;
          const responseToken = response.headers && response.headers.get('X-TTS-Token');
          if (responseToken) {
            const token = String(responseToken);
            pendingNativeTtsTokens.add(token);
            if (!live()) {
              pendingNativeTtsTokens.delete(token);
              cancelNativeTtsToken(token);
              return null;
            }
          }
          return response.json().catch(function (err) {
            if (responseToken) return { token: String(responseToken) };
            throw err;
          });
        }).then(function (data) {
          if (!data || !data.token) return null;
          sentenceRetries = 0;
          const token = String(data.token);
          pendingNativeTtsTokens.add(token);
          if (!live()) {
            pendingNativeTtsTokens.delete(token);
            cancelNativeTtsToken(token);
            return null;
          }
          return window.NativeVoiceTts.enqueue(nativeVoiceTtsStreamUrl(token)).catch(function (err) {
            pendingNativeTtsTokens.delete(token);
            cancelNativeTtsToken(token);
            // Drop the cached session so the retry begins a fresh native
            // session instead of failing every subsequent enqueue too.
            nativeVoiceTtsSessionPromise = null;
            throw err;
          });
        }).catch(function (err) {
          if (!live() || !err) return;
          if (err.message === 'Session expired') return;
          const statusMatch = /request failed \((\d+)\)/.exec(err.message || '');
          const status = statusMatch ? Number(statusMatch[1]) : 0;
          // On a spotty link a dropped sentence is a silent gap: requeue any
          // transient failure (network error, stall timeout, 429/5xx), not
          // only 429. Bounded so a dead link cannot churn forever.
          if ((status === 0 || isRetryableVoiceStatus(status)) && sentenceRetries < MAX_TTS_SENTENCE_RETRIES) {
            sentenceRetries += 1;
            sentenceQueue.unshift(text);
            retryScheduled = true;
            setTimeout(function () {
              retryScheduled = false;
              pump();
            }, 400 * sentenceRetries);
          } else {
            sentenceRetries = 0;
            console.error('Native voice TTS sentence failed; skipping after retries:', err);
          }
        }).then(function () {
          pumpInFlight = false;
          if (live() && !retryScheduled) pump();
        });
        return;
      }
      if (isStillGenerating()) {
        pollTimer = setTimeout(function () {
          pollTimer = null;
          pump();
        }, 80);
        return;
      }
      const remaining = getMessageTtsText($messageElement).substring(processedText.length).trim();
      if (remaining) {
        sentenceQueue.push(remaining);
        processedText += getMessageTtsText($messageElement).substring(processedText.length);
        pump();
        return;
      }
      teardownObserver();
      markEndOfQueue();
    }

    if (options.sentences && options.sentences.length) {
      options.sentences.forEach(function (sentence) {
        if (sentence && String(sentence).trim()) sentenceQueue.push(String(sentence));
      });
      processedText = getMessageTtsText($messageElement) || '';
    }

    // React immediately to streaming text updates so TTS starts on the first
    // complete sentence without waiting out the 80 ms poll cycle. Important
    // for the web-search/tool-calling path: the final answer only begins
    // streaming after the search + second LLM hop completes.
    const textEl = $messageElement.find('.ai-message-text')[0];
    if (textEl && typeof MutationObserver === 'function') {
      observer = new MutationObserver(onTextChanged);
      observer.observe(textEl, { childList: true, subtree: true, characterData: true });
    }

    pump();
  }
  window.playNativeVoiceModeTts = playNativeVoiceModeTts;

  const VOICE_MODE_WANTED_KEY = 'chatbotVoiceModeWanted';
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
    try {
      if (on) sessionStorage.setItem(VOICE_MODE_WANTED_KEY, '1');
      else sessionStorage.removeItem(VOICE_MODE_WANTED_KEY);
    } catch (e) { /* ignore */ }
  }

  function voiceModeWanted() {
    try { return sessionStorage.getItem(VOICE_MODE_WANTED_KEY) === '1'; } catch (e) { return false; }
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
          await window.NativeMic.enterVoiceRoute();
        }
        startingNativeBridge = new NativeMicUtteranceVAD(function (err) {
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
      $voiceModeBtn.addClass('active');
      $micBtn.prop('disabled', true);
      acquireVoiceScreenWakeLock();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      nativeLog('VAD', 'startVoiceMode failed attempt=' + attempt + ' ' + msg);
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

  function createVAD(stream, hooks) {
    hooks = hooks || {};
    nativeLog('VAD', 'createVAD called with stream id: ' + stream.id);
    return vad.MicVAD.new({
      stream: stream,
      model: 'v5',
      baseAssetPath: '/static/deps/vad/',
      onnxWASMBasePath: '/static/deps/vad/ort/',
      positiveSpeechThreshold: 0.7,
      negativeSpeechThreshold: 0.4,
      redemptionMs: 1500,
      minSpeechMs: 400,
      getStream: async () => stream,
      onSpeechStart: hooks.onSpeechStart || function () {
        nativeLog('VAD', 'onSpeechStart');
        lastVoiceUtteranceStartedAt = Date.now();
      },
      onSpeechRealStart: hooks.onSpeechRealStart || function () {
        nativeLog('VAD', 'onSpeechRealStart');
        if (CURRENT_AUDIO || voiceModeTtsSessionActive || voiceModeTtsPlaying) {
          handleBargeIn();
        }
      },
      onFrameProcessed: hooks.onFrameProcessed || function (probs) {
        const ttsActive = CURRENT_AUDIO || voiceModeTtsSessionActive || voiceModeTtsPlaying;
        if (ttsActive && probs.isSpeech > BARGE_IN_SPEECH_PROB) {
          bargeInFrames++;
          if (bargeInFrames >= BARGE_IN_FRAMES_DESKTOP) {
            bargeInFrames = 0;
            handleBargeIn();
          }
        } else {
          bargeInFrames = 0;
        }
      },
      onSpeechEnd: hooks.onSpeechEnd || function (audio) {
        nativeLog('VAD', 'onSpeechEnd');
        handleSpeechEnd(audio);
      },
    });
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
    opts = opts || {};
    if (stopAllTtsPlayback._busy) return;
    stopAllTtsPlayback._busy = true;
    try {
      voiceModeTtsPlaying = false;
      voiceModeTtsSessionActive = false;
      if (opts.preserveListen) {
        voiceModeListenCooldownUntil = 0;
      } else {
        armTtsListenCooldown();
      }
      const audio = CURRENT_AUDIO;
      if (audio && audio.stop) {
        try { audio.stop(); } catch (e) { /* ignore */ }
      }
      if (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) {
        window.NativeVoiceTts.stop().catch(function () {});
      }
      stopCurrentDesktopTts();
      syncSendButtonState();
    } finally {
      stopAllTtsPlayback._busy = false;
    }
  }
  window.stopAllTtsPlayback = stopAllTtsPlayback;

  function stopVoicePlaybackOnly() {
    stopAllTtsPlayback({ preserveListen: true });
  }

  function stopVoiceMode() {
    voiceModeSessionGeneration += 1;
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
    bargeInFrames = 0;
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
    if (currentAbortController) {
      currentAbortController.abort();
      currentAbortController = null;
      chatRequestSeq += 1;
      const $lastAI = $('#chat-content .message.ai-message').last();
      if ($lastAI.length) {
        const $text = $lastAI.find('.ai-message-text');
        const raw = ($text.text() || '');
        if (raw.indexOf('[Stopped]') === -1) {
          $text.append(' [Stopped]');
        }
        $lastAI.find('.regenerate-button').prop('disabled', false);
        $lastAI.find('.play-button').prop('disabled', false);
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
    const generating = !!currentAbortController || $('#send-button').hasClass('is-generating');
    const ttsActive = !!(voiceModeTtsSessionActive || voiceModeTtsPlaying);
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
    if (vadSttInProgress) return;
    if (!window.voiceModeActive) return;
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
      let wavBlob;
      if (nativeMicBridge && nativeMicBridge.hasSpeechCapture()) {
        wavBlob = nativeMicBridge.takeSpeechWavBlob();
        nativeLog('VAD', 'STT native PCM wavBytes=' + wavBlob.size);
        if (wavBlob.size < 44 + NativeAudio.SPEECH_MIN_PCM_BYTES) {
          nativeLog('VAD', 'STT skipped: utterance too short bytes=' + wavBlob.size);
          return;
        }
      } else if (vadAudio && vadAudio.length) {
        wavBlob = NativeAudio.float32ToWavBlob(vadAudio, NativeAudio.NATIVE_MIC_SAMPLE_RATE);
      } else {
        return;
      }
      const res = await fetchVoiceRetry('/stt', function () {
        const retryForm = new FormData();
        retryForm.append('audio', wavBlob, 'recording.wav');
        return {
          method: 'POST',
          headers: withCsrf({}),
          body: retryForm,
          signal: sttSignal
        };
      });
      if (!window.voiceModeActive || sessionGeneration !== voiceModeSessionGeneration) return;
      const data = await res.json();
      const text = (data.text || '').trim();

      if (text && window.voiceModeActive
          && sessionGeneration === voiceModeSessionGeneration) {
        submitVoiceUtterance(text, {
          lastSpeechEndedAt: prevSpeechEndedAt,
          utteranceStartedAt: utteranceStartedAt
        });
      }
    } catch (err) {
      nativeLog('VAD', 'STT failed: ' + (err && err.message ? err.message : err));
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
