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
      addListener: function(eventName, callback) {
        return window.Capacitor.addListener('NativeMic', eventName, callback);
      }
    };
    window.nativeMicAvailable = true;

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
        url.includes('/reset_chat')
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

function withCsrf(headers) {
  var result = headers ? Object.assign({}, headers) : {};
  if (window.CSRF_TOKEN) {
    result['X-CSRF-Token'] = window.CSRF_TOKEN;
  }
  if (window.APP_DATA && window.APP_DATA.loggedIn && window.EncKey) {
    var encKey = window.EncKey.getKeyForRequestSync();
    if (encKey) {
      result['X-Enc-Key'] = encKey;
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
    }
  }
  return result;
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
  if (data.set_id) window.APP_DATA.lastSetId = data.set_id;
  if (data.version != null) window.APP_DATA.setVersion = data.version;
}

/** After chat/regenerate persist, CAS version advances by one. Update immediately
 *  so delete/reset don't race the async loadSets() refresh. */
function noteLocalVersionBumpAfterPersist() {
  if (window.APP_DATA.setVersion == null || window.APP_DATA.setVersion === '') return;
  var next = Number(window.APP_DATA.setVersion) + 1;
  if (Number.isNaN(next)) return;
  window.APP_DATA.setVersion = next;
  var $opt = $('#set-selector option:selected');
  if ($opt.length) $opt.attr('data-version', String(next));
}

function handleVersionConflict(response, data) {
  var msg = (data && data.message) || 'Chat was modified in another tab. Reloading…';
  if (typeof appendMessage === 'function') {
    appendMessage('<strong>System:</strong> ' + escapeHTML(msg), 'system-message');
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
function escapeHTML(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
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

    const language = lang || 'plaintext';
    let highlighted;
    
    console.debug('Rendering code block:', { language, textLength: text.length });

    if (typeof hljs !== 'undefined') {
      try {
        const langObj = hljs.getLanguage(language);
        if (langObj) {
          highlighted = hljs.highlight(text, { language }).value;
          console.debug('Highlight.js success for:', language);
        } else {
          highlighted = hljs.highlightAuto(text).value;
          console.debug('Highlight.js auto-highlighting used');
        }
      } catch (e) {
        console.error('Highlight.js error:', e);
        highlighted = escapeHTML(text);
      }
    } else {
      console.warn('Highlight.js (hljs) is not defined');
      highlighted = escapeHTML(text);
    }

    return `<div class="code-block-container"><div class="code-block-header"><span>${language}</span><button class="copy-code-button" type="button" title="Copy to clipboard"><i class="bi bi-clipboard"></i></button></div><pre><code class="hljs language-${language}">${highlighted}</code></pre></div>`;
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
  if (window.APP_DATA && window.APP_DATA.renderMarkdown === false) {
    return escapeHTML(text).replace(/\n/g, '<br>');
  }
  if (typeof marked !== 'undefined') {
    try {
      return marked.parse(text);
    } catch (e) {
      console.error('Markdown parsing error:', e);
      return escapeHTML(text).replace(/\n/g, '<br>');
    }
  }
  return escapeHTML(text).replace(/\n/g, '<br>');
}

// Scroll helpers for the chat content container
function isAtBottom() {
  const container = document.getElementById('chat-content');
  if (!container) return false;
  const threshold = 30; // pixels from bottom to be considered "at bottom"
  return (container.scrollTop + container.clientHeight) >= (container.scrollHeight - threshold);
}

function scrollToBottom() {
  const container = document.getElementById('chat-content');
  if (!container) return;
  // Use scrollTo for more reliable behavior in some browsers
  container.scrollTo({
    top: container.scrollHeight,
    behavior: 'instant'
  });
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
  resetPlayButtonUi(prevBtn);
  clearMessageTtsPlayingUi();
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

function parseUserMessageContent(originalText) {
  var raw = originalText == null ? '' : String(originalText);
  var imageMatch = raw.match(USER_IMAGE_TAG_RE);
  var imageSrc = imageMatch ? imageMatch[1] : null;
  var text = raw.replace(/\[IMAGE:[^\]]+\]/g, '').trim();
  return { text: text, imageSrc: imageSrc };
}

function composeUserMessageContent(text, imageSrc) {
  var body = (text == null ? '' : String(text)).trim();
  if (imageSrc) {
    return body + (body ? '\n' : '') + '[IMAGE:' + imageSrc + ']';
  }
  return body;
}

// Thumbnail HTML for chat image attachments (click opens full-size lightbox).
function chatImageHtml(src) {
  return (
    '<br><img class="chat-image" src="' +
    escapeHTML(src) +
    '" alt="Attached image" title="Click to expand" loading="lazy">'
  );
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

function openImageLightbox(src) {
  if (!src) return;
  const $overlay = ensureImageLightbox();
  $overlay.find('.image-lightbox-img').attr('src', src);
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

// Append a message to the chat content
function appendMessage(message, className, pairIndex) {
  const $chatContent = $('#chat-content');
  const $messageElement = $('<div>').addClass('message ' + className);

  if (className && className.indexOf('user-message') !== -1) {
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

    // Handle image attachments [IMAGE:data:image/png;base64,...]
    const parsed = parseUserMessageContent(originalText);
    const imageHtml = parsed.imageSrc ? chatImageHtml(parsed.imageSrc) : '';

    $messageElement.html(`<span class="user-message-text"><strong>You:</strong> ${renderMarkdown(parsed.text)}${imageHtml}</span>`);
    $messageElement.attr('data-original', composeUserMessageContent(parsed.text, parsed.imageSrc));
  } else {
    $messageElement.html(message);
  }

  if (typeof pairIndex !== 'undefined' && pairIndex !== null) {
    $messageElement.attr('data-pair-index', pairIndex);
  }

  if (className && className.indexOf('user-message') !== -1) {
    try {
      const $deleteContainer = $('<div>').addClass('regenerate-container');
      const $editBtn = $('<button>')
        .attr('type', 'button')
        .addClass('edit-button')
        .attr('title', 'Edit message')
        .html('<i class="bi bi-pencil-fill"></i>');
      const $deleteBtn = $('<button>')
        .attr('type', 'button')
        .addClass('delete-button')
        .attr('title', 'Delete message')
        .html('<span class="delete-icon"><i class="bi bi-trash-fill"></i></span>');
      $deleteContainer.append($editBtn).append($deleteBtn);
      $messageElement.append($deleteContainer);
    } catch (e) { console.debug('Failed to add buttons:', e); }
  }

  $chatContent.append($messageElement);
  if (typeof __autoScroll !== 'undefined' ? __autoScroll : isAtBottom()) {
    scrollToBottom();
  }
  return $messageElement;
}

let currentAbortController = null;

function setGeneratingState(isGenerating) {
  const $btn = $('#send-button');
  if (isGenerating) {
    $btn.removeClass('btn-outline-primary').addClass('btn-danger').text('Stop').addClass('is-generating');
  } else {
    $btn.removeClass('btn-danger').addClass('btn-outline-primary').text('Send').removeClass('is-generating');
  }
}

function handleStopClick() {
  if (currentAbortController) {
    currentAbortController.abort();
    currentAbortController = null;
    setGeneratingState(false);
  }
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

/**
 * Split plain text into sentences. Single algorithm used for:
 * - hover highlight bounds
 * - click-to-play sentence selection
 * - voice-mode discover
 * Do NOT sanitize before splitting (sanitize changes boundaries / can drop the first sentence).
 *
 * Ellipsis "..." / ".." / "…." is ONE terminator — never three empty "." sentences.
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
  return fetch('/tts', {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ text: cleaned }),
    signal: signal
  })
  .then(function (r) {
    if (!desktopTtsIsLive(sessionId)) return null;
    if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
    if (!r.ok) throw new Error('TTS request failed');
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
      const finish = function (ok) {
        if (settled) return;
        settled = true;
        audio.onended = null;
        audio.onerror = null;
        resolve(!!ok && desktopTtsIsLive(sessionId));
      };
      audio.onended = function () { finish(true); };
      audio.onerror = function () { finish(false); };
      // Always assign a fresh absolute URL; prior load() cleared the element.
      audio.src = '/tts_stream/' + encodeURIComponent(data.token);
      const playPromise = audio.play();
      if (playPromise && typeof playPromise.then === 'function') {
        playPromise.catch(function (err) {
          console.error('TTS audio.play() failed:', err);
          finish(false);
        });
      }
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
    // Natural end: clear UI without bumping session early mid-flight.
    CURRENT_AUDIO = null;
    CURRENT_AUDIO_BUTTON = null;
    resetPlayButtonUi(button);
    clearMessageTtsPlayingUi();
    resetDesktopTtsAudioElement();
  });
}

/**
 * Play from message body (play button). Supports streaming generation.
 */
function playMessageBodyTts(sessionId, button, $messageElement) {
  // Absolute character offset into getMessageTtsText(); only sentences with end > consumed
  // and start >= consumed are enqueued.
  let consumedLen = 0;
  let queue = [];
  let running = false;

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
      if (s.start < consumedLen) continue;
      if (!sentenceEndsWithTerminator(s.text) && isStillGenerating()) break;
      queue.push(s.text);
      consumedLen = s.end;
    }
  }

  function finishIfIdle() {
    if (!desktopTtsIsLive(sessionId)) return;
    if (running || queue.length) return;
    if (isStillGenerating()) {
      setTimeout(function () {
        if (!desktopTtsIsLive(sessionId)) return;
        discoverAbsolute();
        pump();
      }, 120);
      return;
    }
    discoverAbsolute();
    if (queue.length) {
      pump();
      return;
    }
    CURRENT_AUDIO = null;
    CURRENT_AUDIO_BUTTON = null;
    resetPlayButtonUi(button);
    clearMessageTtsPlayingUi();
    resetDesktopTtsAudioElement();
  }

  function pump() {
    if (!desktopTtsIsLive(sessionId) || running) return;
    discoverAbsolute();
    if (!queue.length) {
      finishIfIdle();
      return;
    }
    running = true;
    const next = queue.shift();
    playOneTtsUtterance(sessionId, next).then(function (ok) {
      running = false;
      if (!desktopTtsIsLive(sessionId)) return;
      if (!ok) {
        stopCurrentDesktopTts();
        return;
      }
      pump();
    });
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
    stopCurrentDesktopTts();
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

  $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
  $messageElement.addClass('tts-is-playing');
  $messageElement.find('.ai-message-text').addClass('tts-is-playing');

  if (options.sentences && options.sentences.length) {
    playFixedSentenceList(sessionId, button, options.sentences);
    return;
  }
  playMessageBodyTts(sessionId, button, $messageElement);
}
window.regenerateMessage = function regenerateMessage(button) {
  const $aiMessageElement = $(button).closest('.message');
  const $previousUserMessage = $aiMessageElement.prev('.message.user-message');
  if ($previousUserMessage.length === 0) return;
  const userText = ($previousUserMessage.attr('data-original') || ($previousUserMessage.find('.user-message-text').text() || $previousUserMessage.text() || '').replace(/^\s*You:\s*/, '')).trim();
  const userMsgNodes = Array.from(document.querySelectorAll('.message.user-message'));
  let pairIndex = userMsgNodes.indexOf($previousUserMessage[0]);
  if (pairIndex === -1) {
    const prevText = ($previousUserMessage.find('.user-message-text').text() || '').trim();
    pairIndex = userMsgNodes.findIndex(n => (n.querySelector('.user-message-text') || {}).textContent?.trim() === prevText);
  }
  window.performRegeneration($aiMessageElement[0], userText, pairIndex);
};

window.performRegeneration = function performRegeneration(aiMessageElement, userText, pairIndex) {
  const $target = $(aiMessageElement);
  $target.removeAttr('data-original');
  $target.html(`<strong>AI:</strong><div class="thinking-container" style="display:none;"><button class="toggle-thinking" style="display:none;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;"></div></div><span class="ai-message-text">Thinking...</span><div class="regenerate-container"><button class="regenerate-button" disabled><i class="bi bi-arrow-repeat"></i></button><button class="play-button"><i class="bi bi-play-fill"></i></button></div>`);
  
if (window.APP_DATA.autoplayTTS || window.voiceModeActive) {
    const playBtn = $target.find('.play-button')[0];
    if (playBtn) setTimeout(() => (window.voiceModeActive ? window.playTTSVoiceMode(playBtn) : window.playTTS(playBtn)), 50);
  }

  if (currentAbortController) currentAbortController.abort();
  currentAbortController = new AbortController();
  setGeneratingState(true);

  fetch('/regenerate', {
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
    if (!response.ok) throw new Error('Network response was not ok');
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
              setGeneratingState(false);
              currentAbortController = null;
              noteLocalVersionBumpAfterPersist();
              if (typeof loadSets === 'function') loadSets(false);
              return;
            }
            buffer += decoder.decode(value, {stream:true});
            const nearBottom = isAtBottom();
            processBuffer();
            if (nearBottom) {
              scrollToBottom();
            }
            read();
          }).catch(err => {
            try {
              $target.find('.regenerate-button').prop('disabled', false);
              const playBtn = $target.find('.play-button').prop('disabled', false);
              if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            setGeneratingState(false);
            currentAbortController = null;
          });
        }
        read();
      })
      .catch(err => {
        if (err.name === 'AbortError') {
          $target.find('.ai-message-text').append(' [Stopped]');
        } else {
          $target.html(`<strong>AI:</strong> <span class="error-message">Error: ${err.message}</span>`);
        }
        try {
          $target.find('.regenerate-button').prop('disabled', false);
          const playBtn = $target.find('.play-button').prop('disabled', false);
          if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
        } catch (e) {}
        setGeneratingState(false);
        currentAbortController = null;
      });
};

function handleDeleteMessage(buttonElement) {
  const deleteBtn = $(buttonElement);
  const userMessageElement = deleteBtn.closest('.message.user-message');
  if (userMessageElement.length === 0) return;

  const aiMessageElement = userMessageElement.next('.ai-message');
  if (aiMessageElement.length === 0) {
    console.error('Cannot delete: missing AI message pair');
    return;
  }

  const userText = (userMessageElement.attr('data-original') || userMessageElement.find('.user-message-text').text() || userMessageElement.text() || '').replace(/^\s*You:\s*/, '').trim();
  if (!userText) {
    console.error('Cannot delete: missing message text');
    return;
  }

  const storedPairIndex = userMessageElement.attr('data-pair-index');
  let pairIndex = storedPairIndex !== undefined && storedPairIndex !== '' ? parseInt(storedPairIndex, 10) : NaN;
  if (Number.isNaN(pairIndex)) {
    const userMsgNodes = Array.from(document.querySelectorAll('.message.user-message'));
    pairIndex = userMsgNodes.indexOf(userMessageElement[0]);
  }
  if (pairIndex < 0) {
    console.error('Cannot delete: could not resolve pair index');
    return;
  }

  console.debug('Deleting message pair:', { pairIndex, userTextLen: userText.length });

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
    if (result.status === 409 || (result.data && result.data.error === 'version_conflict')) {
      return handleVersionConflict(null, result.data);
    }
    if (result.ok && result.data && result.data.status === 'success') {
      noteSetVersionFromResponse(result.data);
      aiMessageElement.remove();
      userMessageElement.remove();
      return;
    }
    const errMsg = (result.data && result.data.error) || `delete failed (${result.status})`;
    if (result.status === 404 || (errMsg && /out of range/i.test(errMsg))) {
      // Pair was never saved server-side (failed/stopped AI response) and only
      // existed client-side in the DOM. Remove it locally without error.
      aiMessageElement.remove();
      userMessageElement.remove();
      console.debug('Removed client-side-only message pair (server reported out of range)');
      return;
    }
    console.error('Server failed to delete message:', errMsg);
    appendMessage('<strong>Error:</strong> Failed to delete message: ' + escapeHTML(errMsg), 'error-message');
  })
  .catch(err => {
    console.error('Error deleting message:', err);
    appendMessage('<strong>Error:</strong> Failed to delete message: ' + escapeHTML(err.message), 'error-message');
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
      appendMessage('<strong>Error:</strong> Please select an image file.', 'error-message');
      return;
    }

    const reader = new FileReader();
    reader.onload = function(event) {
      const imgData = event.target.result;
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
    if (isAtBottom()) {
      $scrollToBottomBtn.fadeOut(200);
    } else if ($scrollToBottomBtn.is(':hidden')) {
      $scrollToBottomBtn.css('display', 'flex').hide().fadeIn(200);
    }
  });

  $scrollToBottomBtn.on('click', function() {
    scrollToBottom();
  });

  // Expand chat image attachments to full size
  $(document).on('click', 'img.chat-image', function(e) {
    e.preventDefault();
    e.stopPropagation();
    openImageLightbox(this.getAttribute('src'));
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
      stopCurrentDesktopTts();
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
    window.playTTS(playBtn, { sentences: toPlay });
  });

  // Delegation for play, delete, and edit
  $(document).on('click', function(event) {
    const target = event.target;
    const playBtn = target.closest && target.closest('.play-button');
    if (playBtn) {
      window.playTTS(playBtn);
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
      $messageElement.data('editImageSrc', parsed.imageSrc);

      const $editContainer = $('<div>').addClass('edit-message-container');
      if (parsed.imageSrc) {
        const $imgPreview = $('<div>').addClass('edit-image-preview');
        const $img = $('<img>')
          .addClass('edit-image-thumb')
          .attr('src', parsed.imageSrc)
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
      const imageSrc = $messageElement.data('editImageSrc') || null;
      const newText = composeUserMessageContent(textOnly, imageSrc);
      if (!newText) return;

      const userMsgNodes = Array.from(document.querySelectorAll('.message.user-message'));
      const pairIndex = userMsgNodes.indexOf($messageElement[0]);

      const saved = parseUserMessageContent(newText);
      const imageHtml = saved.imageSrc ? chatImageHtml(saved.imageSrc) : '';

      $messageElement.attr('data-original', newText);
      $messageElement.find('.user-message-text').html(`<strong>You:</strong> ${renderMarkdown(saved.text)}${imageHtml}`).show();
      $messageElement.find('.edit-message-container').remove();
      $messageElement.removeData('editImageSrc');
      $messageElement.find('.regenerate-container').show();

      const $aiMessageElement = $messageElement.next('.message.ai-message');
      if ($aiMessageElement.length > 0) {
        window.performRegeneration($aiMessageElement[0], newText, pairIndex);
      }
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

    navigator.clipboard.writeText(code).then(() => {
      const originalHtml = $btn.html();
      $btn.addClass('copied').html('<i class="bi bi-check2"></i>');
      setTimeout(() => {
        $btn.removeClass('copied').html(originalHtml);
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy code:', err);
      alert('Failed to copy code to clipboard');
    });
  });

  // Load sets for logged-in users (wait for encryption key from login storage first)
  if (window.APP_DATA.loggedIn) {
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

          // Always sync setVersion from the selected option so stale values
          // don't cause CAS conflicts on the next mutation.
          const $selectedOpt = $selector.find('option:selected');
          if ($selectedOpt.length) {
            window.APP_DATA.setVersion = $selectedOpt.attr('data-version') || null;
          }

          if (shouldTriggerChange) {
            $selector.trigger('change');
          }
        })
        .catch(function(error) {
          console.error('Failed to load sets:', error);
          appendMessage(
            '<strong>Error:</strong> Could not load saved sets: ' + escapeHTML(error.message || String(error)) +
            ' <a href="/logout">Sign out</a> and log in again if this persists.',
            'error-message'
          );
          throw error;
        });
    }

    window.loadChatSets = loadSets;

    $('#set-selector').on('change', function() {
      const $opt = $(this).find('option:selected');
      const setId = $(this).val();
      const setName = $opt.attr('data-name') || setId;
      window.APP_DATA.lastSetId = setId;
      window.APP_DATA.lastSet = setName;
      window.APP_DATA.setVersion = $opt.attr('data-version') || null;
      savePreferences();
      function fetchSet() {
        return withCsrfAsync({ 'Content-Type': 'application/json' }).then(function(headers) {
          return fetch('/load_set', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ set_id: setId, set_name: setName })
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
          if (data.set_id) window.APP_DATA.lastSetId = data.set_id;
          if (data.name) window.APP_DATA.lastSet = data.name;
          if (data.version != null) window.APP_DATA.setVersion = data.version;
          $opt.attr('data-version', data.version != null ? data.version : '');
          if (data.name) $opt.attr('data-name', data.name).text(data.name);
          $('#user-system-prompt').val(data.system_prompt || '');
          $('#user-memory').val(data.memory || '');
          $('#chat-content').empty();
          if (data.history && data.history.length > 0) {
            data.history.forEach(([userMsg, aiMsg], pairIndex) => {
              appendMessage(userMsg, 'user-message', pairIndex);
              const formattedAi = formatAiMessage(aiMsg);
              const $aiMsg = appendMessage(`<strong>AI:</strong>&nbsp;<span class=\"ai-message-text\">${formattedAi}</span><div class=\"regenerate-container\"><button class=\"regenerate-button\"><i class=\"bi bi-arrow-repeat\"></i></button><button class=\"play-button\"><i class=\"bi bi-play-fill\"></i></button></div>`, 'ai-message');
              $aiMsg.attr('data-original', aiMsg);
            });
            setTimeout(function() { scrollToBottom(); }, 0);
          }
          appendMessage('<strong>System:</strong> Loaded set: ' + escapeHTML(setName), 'system-message');
        })
        .catch(error => { appendMessage('<strong>Error:</strong> Failed to load set: ' + escapeHTML(error.message), 'error-message'); });
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
              appendMessage('<strong>System:</strong> Created new set: ' + escapeHTML(setName), 'system-message');
            } else {
              appendMessage('<strong>Error:</strong> ' + data.error, 'error-message');
            }
          });
      }
    });

    $('#rename-set').on('click', function() {
      const $opt = $('#set-selector option:selected');
      const setId = $('#set-selector').val();
      const oldName = $opt.attr('data-name') || setId;
      if (oldName === 'default' || $opt.attr('data-name') === 'default') {
        appendMessage('<strong>Error:</strong> Cannot rename default set', 'error-message');
        return;
      }
      const newName = prompt('Enter new name for set:', oldName);
      if (newName && newName !== oldName) {
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
            if (data.version != null) window.APP_DATA.setVersion = data.version;
            loadSets(false).then(() => {
              $('#set-selector').val(window.APP_DATA.lastSetId);
              appendMessage('<strong>System:</strong> Renamed set to: ' + escapeHTML(newName), 'system-message');
            });
          } else {
            appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to rename set'), 'error-message');
          }
        })
        .catch(err => {
          appendMessage('<strong>Error:</strong> ' + escapeHTML(err.message), 'error-message');
        });
      }
    });

    $('#delete-set').on('click', function() {
      const $opt = $('#set-selector option:selected');
      const setId = $('#set-selector').val();
      const setName = $opt.attr('data-name') || setId;
      if (setName === 'default') { appendMessage('<strong>Error:</strong> Cannot delete default set', 'error-message'); return; }
      if (confirm('Are you sure you want to delete set: ' + setName + '?')) {
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
            if (data.status === 'success') { loadSets(); appendMessage('<strong>System:</strong> Deleted set: ' + escapeHTML(setName), 'system-message'); }
            else { appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to delete set'), 'error-message'); }
          });
      }
    });
  }

  function activeSetName() {
    const $opt = $('#set-selector option:selected');
    return $opt.attr('data-name') || $opt.text() || 'default';
  }

  // Save buttons
  $('#save-system-prompt').on('click', function() {
    const sysPromptText = $('#user-system-prompt').val();
    const setName = activeSetName();
    fetch('/update_system_prompt', {
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
          appendMessage('<strong>System:</strong> System prompt saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          return handleVersionConflict(null, data);
        }
        else appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to save system prompt.'), 'error-message');
      })
      .catch(error => { appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message'); });
  });

  $('#save-memory').on('click', function() {
    const memText = $('#user-memory').val();
    const setName = activeSetName();
    fetch('/update_memory', {
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
          appendMessage('<strong>System:</strong> Memory saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        } else if (data.error === 'version_conflict') {
          return handleVersionConflict(null, data);
        }
        else appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to save memory.'), 'error-message');
      })
      .catch(error => { appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message'); });
  });

  function sendMessage() {
    const $systemPromptElement = $('#user-system-prompt');
    const $userInputElement = $('#user-input');
    if ($systemPromptElement.length === 0 || $userInputElement.length === 0) {
      appendMessage('<strong>Error:</strong> Chat system not properly initialized. Please refresh the page.', 'error-message');
      return;
    }
    const message = $userInputElement.val().trim();
    if (!message && !pendingImageData) return;
    const systemPrompt = $systemPromptElement.val() || window.DEFAULT_SYSTEM_PROMPT;
    const activeSet = (typeof activeSetName === 'function' ? activeSetName() : ($('#set-selector option:selected').attr('data-name') || 'default'));

    // Same wire format as durable history: plain text + optional [IMAGE:data:...] tag.
    // appendMessage parses that tag into a preview <img> (same path as load_set).
    // Do not pre-build HTML with <img> here — textContent extraction would strip it and
    // leave no [IMAGE:...] tag to reconstruct, so the image only appeared after reload.
    let fullMessage = message;
    if (pendingImageData) {
      fullMessage = message + '\n[IMAGE:' + pendingImageData + ']';
    }

    appendMessage(fullMessage, 'user-message');
    const $pendingUserMessage = $('#chat-content .message.user-message').last();

    const requestData = activeSetPayload({
      message: fullMessage,
      system_prompt: systemPrompt,
      model_name: $('#modelSelect').val(),
      web_search: $('#web-search-toggle').hasClass('btn-primary'),
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    });

    if (currentAbortController) currentAbortController.abort();
    currentAbortController = new AbortController();
    setGeneratingState(true);

    fetch('/chat', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      signal: currentAbortController.signal,
      body: JSON.stringify(requestData)
    })
      .then(response => {
        if (response.status === 401) throw new Error(SESSION_EXPIRED_SEND_MSG);
        if (!response.ok) return response.text().then(t => { throw new Error(t || 'Network response was not ok'); });
        $userInputElement.val('');
        if (pendingImagePreview) {
          pendingImagePreview.remove();
          pendingImagePreview = null;
        }
        pendingImageData = null;
        $('#image-input').val('');
        return response;
      })
      .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        appendMessage(`<strong>AI:</strong><div class="thinking-container" style="display:none;"><button class="toggle-thinking" style="display:none;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;"></div></div><span class="ai-message-text">Thinking...</span><div class="regenerate-container"><button class="regenerate-button" disabled><i class="bi bi-arrow-repeat"></i></button><button class="play-button"><i class="bi bi-play-fill"></i></button></div>`, 'ai-message');
        
        const $targetElement = $('.ai-message:last-child');

        if (window.APP_DATA.autoplayTTS || window.voiceModeActive) {
          const playBtn = $targetElement.find('.play-button')[0];
          if (playBtn) setTimeout(() => (window.voiceModeActive ? window.playTTSVoiceMode(playBtn) : window.playTTS(playBtn)), 50);
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
              setGeneratingState(false);
              currentAbortController = null;
              noteLocalVersionBumpAfterPersist();
              if (typeof loadSets === 'function') loadSets(false);
              return;
            }
            const chunk = decoder.decode(value, { stream: true });
            const nearBottom = isAtBottom();
            processChunk(chunk);
            if (nearBottom) {
              scrollToBottom();
            }
            return readStream();
          }).catch(err => {
            try {
              $targetElement.find('.regenerate-button').prop('disabled', false);
              const playBtn = $targetElement.find('.play-button').prop('disabled', false);
              if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
            } catch (e) {}
            setGeneratingState(false);
            currentAbortController = null;
          });
        }
        readStream();
      })
      .catch(error => {
        if (error.name === 'AbortError') {
          const $lastAI = $('.ai-message:last-child');
          $lastAI.find('.ai-message-text').append(' [Stopped]');
          try {
            $lastAI.find('.regenerate-button').prop('disabled', false);
            const playBtn = $lastAI.find('.play-button').prop('disabled', false);
            if (!playBtn.is(CURRENT_AUDIO_BUTTON)) playBtn.html('<i class="bi bi-play-fill"></i>');
          } catch (e) {}
        } else {
          if ($pendingUserMessage.length) $pendingUserMessage.remove();
          appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message');
        }
        setGeneratingState(false);
        currentAbortController = null;
      });
  }

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
      fetch('/reset_chat', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify(activeSetPayload({})) })
        .then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })))
        .then(result => {
          if (result.status === 409 || (result.data && result.data.error === 'version_conflict')) {
            return handleVersionConflict(null, result.data);
          }
          if (result.ok && result.data && result.data.status === 'success') {
            noteSetVersionFromResponse(result.data);
            $('#chat-content').empty();
            appendMessage('<strong>System:</strong> Chat history has been reset for set ' + escapeHTML(result.data.set_name) + '.', 'system-message');
            return;
          }
          const errMsg = (result.data && (result.data.message || result.data.error)) || 'Failed to reset chat';
          appendMessage(`<strong>Error:</strong> ${escapeHTML(errMsg)}`, 'error-message');
        })
        .catch(error => { appendMessage(`<strong>Error:</strong> ${escapeHTML(error.message)}`, 'error-message'); });
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
          const formData = new FormData();
          formData.append('audio', wavBlob, 'recording.wav');

          _nativeMicPcmChunks = [];

          fetch('/stt', {
            method: 'POST',
            headers: withCsrf({}),
            body: formData,
          })
            .then(function (res) {
              if (!res.ok) throw new Error('STT request failed (' + res.status + ')');
              return res.json();
            })
            .then(function (data) {
              const current = $('#user-input').val();
              const separator = current.trim() ? ' ' : '';
              $('#user-input').val(current + separator + (data.text || '')).focus();
            })
            .catch(function (err) {
              appendMessage('<strong>Error:</strong> ' + escapeHTML(err.message), 'error-message');
            });
        }).catch(function (err) {
          appendMessage('<strong>Error:</strong> ' + escapeHTML(err.message), 'error-message');
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
        appendMessage('<strong>Error:</strong> Microphone access denied: ' + escapeHTML(err.message), 'error-message');
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
          const formData = new FormData();
          formData.append('audio', blob, 'recording.webm');

          fetch('/stt', {
            method: 'POST',
            headers: withCsrf({}),
            body: formData,
          })
            .then(function (res) {
              if (!res.ok) throw new Error('STT request failed (' + res.status + ')');
              return res.json();
            })
            .then(function (data) {
              const current = $('#user-input').val();
              const separator = current.trim() ? ' ' : '';
              $('#user-input').val(current + separator + (data.text || '')).focus();
            })
            .catch(function (err) {
              appendMessage('<strong>Error:</strong> ' + escapeHTML(err.message), 'error-message');
            });
        };

        _mediaRecorder.start();
        $micBtn.addClass('recording').html('&#x23F9;').attr('title', 'Stop Recording');
      }).catch(function (err) {
        appendMessage('<strong>Error:</strong> Microphone access denied: ' + escapeHTML(err.message), 'error-message');
      });
    });
  }

  // ── Voice Mode ─────────────────────────────────────────────────────────────
  const $voiceModeBtn = $('#voice-mode-btn');
  window.voiceModeActive = false;
  let voiceModeVAD = null;
  let voiceModeStream = null;
  let vadSttInProgress = false;
  // Sustained-speech barge-in confirmation state
  let bargeInFrames = 0;
  const BARGE_IN_FRAMES_DESKTOP = 3;  // ~300ms at 100ms/frame
  const BARGE_IN_FRAMES_MOBILE = 3;   // ~300ms - same as desktop for fast response
  const isMobile = /Mobi|Android/i.test(navigator.userAgent);
  const BARGE_IN_THRESHOLD = BARGE_IN_FRAMES_DESKTOP;
  // Native mic bridge for Voice Mode on Android
  let nativeMicBridge = null;

  const hasNativeMicVoice = window.nativeMicAvailable && isMobile && typeof vad !== 'undefined';
  if ((navigator.mediaDevices && navigator.mediaDevices.getUserMedia && typeof vad !== 'undefined') || hasNativeMicVoice) {
    $voiceModeBtn.show();
  }

  $voiceModeBtn.on('click', function () {
    if (window.voiceModeActive) {
      stopVoiceMode();
    } else {
      startVoiceMode();
    }
  });

  // Capacitor voice mode: native PCM + RMS VAD only (matches Android Auto VoiceScreen).
  // No Silero / WebView AudioContext — that path breaks during HTML TTS playback.
  function NativeMicUtteranceVAD(onError) {
    this.onError = onError;
    this.preRollBuffer = new NativeAudio.Pcm16RingBuffer(NativeAudio.SPEECH_PREROLL_SAMPLES);
    this.utteranceChunks = [];
    this.inSpeech = false;
    this.speechAboveCount = 0;
    this.bargeAboveCount = 0;
    this.silenceMs = 0;
    this.speechActiveMs = 0;
    this.nativeListener = null;
    this.isRecording = false;
    this.chunkCount = 0;
  }

  /** Ms after TTS ends before RMS utterance detection resumes. */
  const TTS_LISTEN_COOLDOWN_MS = 400;

  NativeMicUtteranceVAD.prototype._onNativePcm = function (pcm16) {
    const copy = pcm16.slice();
    const rms = NativeAudio.pcm16Rms(copy);
    const frameMs = 20;
    const now = Date.now();

    this.preRollBuffer.push(copy);
    this.chunkCount++;

    // During TTS session: skip classification while fetching; barge-in only while audio plays.
    if (voiceModeTtsSessionActive) {
      if (voiceModeTtsPlaying) {
        if (rms > NativeAudio.BARGE_IN_RMS_THRESHOLD) {
          this.bargeAboveCount++;
          if (this.bargeAboveCount >= NativeAudio.BARGE_IN_RMS_FRAMES) {
            this.bargeAboveCount = 0;
            nativeLog('VAD', 'barge-in TTS rms=' + Math.round(rms));
            handleBargeIn();
            if (!this.inSpeech && !vadSttInProgress) {
              this._beginUtterance(true);
            }
          }
        } else {
          this.bargeAboveCount = 0;
        }
      } else {
        this.bargeAboveCount = 0;
      }
      if (this.inSpeech) {
        this.utteranceChunks.push(copy);
        if (rms > NativeAudio.SPEECH_RMS_THRESHOLD) {
          this.silenceMs = 0;
          this.speechActiveMs += frameMs;
        } else {
          this.silenceMs += frameMs;
          if (this.silenceMs >= NativeAudio.SPEECH_END_SILENCE_MS) {
            this._endUtterance();
          }
        }
      }
      if (this.chunkCount % 50 === 0) {
        nativeLog('VAD', 'pcm#' + this.chunkCount + ' ttsSess=1 ttsPlay=' + voiceModeTtsPlaying
          + ' rms=' + Math.round(rms));
      }
      return;
    }

    if (now < voiceModeListenCooldownUntil) {
      return;
    }

    if (!this.inSpeech && !vadSttInProgress) {
      if (rms > NativeAudio.SPEECH_RMS_THRESHOLD) {
        this.speechAboveCount++;
        if (this.speechAboveCount >= NativeAudio.SPEECH_START_FRAMES) {
          nativeLog('VAD', 'utterance start rms=' + Math.round(rms));
          this._beginUtterance();
        }
      } else {
        this.speechAboveCount = 0;
      }
    }

    if (this.inSpeech) {
      this.utteranceChunks.push(copy);
      if (rms > NativeAudio.SPEECH_RMS_THRESHOLD) {
        this.silenceMs = 0;
        this.speechActiveMs += frameMs;
      } else {
        this.silenceMs += frameMs;
        if (this.silenceMs >= NativeAudio.SPEECH_END_SILENCE_MS) {
          nativeLog('VAD', 'utterance end rms=' + Math.round(rms) + ' chunks=' + this.utteranceChunks.length
            + ' speechMs=' + this.speechActiveMs);
          this._endUtterance();
        }
      }
    }

    if (this.chunkCount % 50 === 0) {
      nativeLog('VAD', 'pcm#' + this.chunkCount + ' inSpeech=' + this.inSpeech
        + ' ttsPlay=' + voiceModeTtsPlaying + ' rms=' + Math.round(rms));
    }
  };

  NativeMicUtteranceVAD.prototype._beginUtterance = function (skipPreRoll) {
    if (this.inSpeech || vadSttInProgress) return;
    this.inSpeech = true;
    this.speechAboveCount = 0;
    this.silenceMs = 0;
    this.speechActiveMs = 0;
    if (skipPreRoll) {
      this.utteranceChunks = [];
      nativeLog('VAD', 'utterance begin (post-barge-in, no pre-roll)');
    } else {
      this.utteranceChunks = this.preRollBuffer.snapshotChunks();
      nativeLog('VAD', 'utterance begin preRollChunks=' + this.utteranceChunks.length);
    }
  };

  NativeMicUtteranceVAD.prototype._endUtterance = function () {
    if (!this.inSpeech) return;
    this.inSpeech = false;
    this.speechAboveCount = 0;
    this.silenceMs = 0;
    if (this.speechActiveMs < NativeAudio.SPEECH_MIN_ACTIVE_MS) {
      nativeLog('VAD', 'utterance rejected: speechActiveMs=' + this.speechActiveMs
        + ' min=' + NativeAudio.SPEECH_MIN_ACTIVE_MS);
      this.utteranceChunks = [];
      this.speechActiveMs = 0;
      return;
    }
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

  NativeMicUtteranceVAD.prototype.start = async function () {
    const self = this;
    if (typeof NativeAudio === 'undefined') {
      throw new Error('native-audio.js not loaded');
    }
    try {
      nativeLog('VAD', 'NativeMicUtteranceVAD start (RMS v' + NativeAudio.VOICE_MODE_NATIVE_VAD_VERSION + ')');
      this.preRollBuffer.clear();
      this.utteranceChunks = [];
      this.inSpeech = false;
      this.speechAboveCount = 0;
      this.bargeAboveCount = 0;
      this.silenceMs = 0;
      this.speechActiveMs = 0;
      this.chunkCount = 0;

      await window.NativeMic.start();

      this.nativeListener = window.NativeMic.addListener('nativeMicData', function (data) {
        if (!data || !data.data) return;
        try {
          self._onNativePcm(NativeAudio.decodeNativePcmBase64(data.data));
        } catch (err) {
          nativeLog('VAD', 'PCM decode error: ' + err.message);
        }
      });
      this.isRecording = true;
    } catch (err) {
      this.onError('Failed to start Voice Mode: ' + err.message);
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
      await window.NativeMic.stop();
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
    this.speechAboveCount = 0;
    this.bargeAboveCount = 0;
    this.silenceMs = 0;
    this.speechActiveMs = 0;
  };

  function useNativeVoiceTtsPlayback() {
    return !!(window.nativeVoiceTtsAvailable && window.voiceModeActive && window.NativeVoiceTts);
  }

  function finishVoiceModeTtsSession() {
    voiceModeTtsSessionActive = false;
    voiceModeTtsPlaying = false;
    voiceModeListenCooldownUntil = Date.now() + TTS_LISTEN_COOLDOWN_MS;
  }

  function onVoiceModeTtsStarted() {
    voiceModeTtsPlaying = true;
    if (nativeMicBridge && nativeMicBridge.onTtsPlaybackStarted) {
      nativeMicBridge.onTtsPlaybackStarted();
    }
    nativeLog('VAD', 'TTS playback started native=' + useNativeVoiceTtsPlayback());
  }

  function onVoiceModeTtsEnded() {
    voiceModeTtsPlaying = false;
    // Cooldown only when the full TTS session finishes, not between sentences.
    nativeLog('VAD', 'TTS playback ended');
  }

  let nativeVoiceTtsSessionListener = null;
  let nativeVoiceTtsSessionPromise = null;
  let nativeVoiceTtsOnSessionEnded = null;
  let nativeTtsFetchChain = Promise.resolve();

  function nativeVoiceTtsStreamUrl(token) {
    return window.location.origin + '/tts_stream/' + encodeURIComponent(token);
  }

  function ensureNativeVoiceTtsSession() {
    if (nativeVoiceTtsSessionPromise) {
      return nativeVoiceTtsSessionPromise;
    }
    nativeVoiceTtsSessionPromise = window.NativeVoiceTts.beginSession().then(function () {
      if (nativeVoiceTtsSessionListener) {
        nativeVoiceTtsSessionListener.remove();
      }
      nativeVoiceTtsSessionListener = window.NativeVoiceTts.addListener('playbackState', function (data) {
        if (data.type === 'started') {
          onVoiceModeTtsStarted();
        } else if (data.type === 'ended') {
          onVoiceModeTtsEnded();
          tearDownNativeVoiceTtsSession();
          if (nativeVoiceTtsOnSessionEnded) {
            var endedCb = nativeVoiceTtsOnSessionEnded;
            nativeVoiceTtsOnSessionEnded = null;
            endedCb();
          }
        } else if (data.type === 'error') {
          onVoiceModeTtsEnded();
          console.error('Native voice TTS error:', data.message);
        }
      });
    });
    return nativeVoiceTtsSessionPromise;
  }

  function enqueueNativeVoiceTts(token) {
    return ensureNativeVoiceTtsSession().then(function () {
      return window.NativeVoiceTts.enqueue(nativeVoiceTtsStreamUrl(token));
    });
  }

  function closeNativeVoiceTtsSession() {
    return nativeTtsFetchChain.then(function () {
      if (!nativeVoiceTtsSessionPromise) {
        return Promise.resolve();
      }
      return nativeVoiceTtsSessionPromise.then(function () {
        return window.NativeVoiceTts.markEndOfQueue();
      });
    });
  }

  function tearDownNativeVoiceTtsSession() {
    if (nativeVoiceTtsSessionListener) {
      nativeVoiceTtsSessionListener.remove();
      nativeVoiceTtsSessionListener = null;
    }
    nativeVoiceTtsSessionPromise = null;
  }

  async function startVoiceMode() {
    try {
      const useNativeMicVAD = window.nativeMicAvailable && isMobile;

      if (useNativeMicVAD) {
        nativeMicBridge = new NativeMicUtteranceVAD(function (err) {
          appendMessage('<strong>Error:</strong> ' + err, 'error-message');
        });
        await nativeMicBridge.start();
      } else {
        // Use browser getUserMedia on desktop
        voiceModeStream = await navigator.mediaDevices.getUserMedia({
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true,
            channelCount: 1
          }
        });

        voiceModeVAD = await createVAD(voiceModeStream);
        await voiceModeVAD.start();
      }

      window.voiceModeActive = true;
      $voiceModeBtn.addClass('active');
      $micBtn.prop('disabled', true);
    } catch (err) {
      appendMessage('<strong>Error:</strong> Voice mode failed to start: ' + escapeHTML(err.message), 'error-message');
    }
  }

  function createVAD(stream, hooks) {
    hooks = hooks || {};
    nativeLog('VAD', 'createVAD called with stream id: ' + stream.id);
    return vad.MicVAD.new({
      stream: stream,
      model: 'v5',
      baseAssetPath: '/static/deps/vad/',
      onnxWASMBasePath: '/static/deps/vad/ort/',
      positiveSpeechThreshold: 0.5,
      redemptionFrames: 5,
      minSpeechFrames: 1,
      getStream: async () => stream,
      onSpeechStart: hooks.onSpeechStart || function () {
        nativeLog('VAD', 'onSpeechStart');
        if (CURRENT_AUDIO) handleBargeIn();
      },
      onFrameProcessed: hooks.onFrameProcessed || function (probs) {
        if (CURRENT_AUDIO && probs.isSpeech > 0.8) {
          bargeInFrames++;
          if (bargeInFrames >= BARGE_IN_THRESHOLD) {
            bargeInFrames = 0;
            handleBargeIn();
          }
        } else if (!CURRENT_AUDIO) {
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
      appendMessage('<strong>Error:</strong> Voice detection failed to recover. Please toggle voice mode off and on.', 'error-message');
      stopVoiceMode();
    }
  }

  function stopVoiceMode() {
    if (nativeMicBridge) {
      nativeMicBridge.stop();
      nativeMicBridge = null;
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
    window.voiceModeActive = false;
    voiceModeTtsPlaying = false;
    voiceModeTtsSessionActive = false;
    voiceModeListenCooldownUntil = 0;
    if (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) {
      window.NativeVoiceTts.stop().catch(function () {});
    }
    tearDownNativeVoiceTtsSession();
    nativeVoiceTtsOnSessionEnded = null;
    bargeInFrames = 0;
    $voiceModeBtn.removeClass('active');
    $micBtn.prop('disabled', false);
  }

  function handleBargeIn() {
    voiceModeTtsPlaying = false;
    voiceModeTtsSessionActive = false;
    voiceModeListenCooldownUntil = 0;
    if (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) {
      window.NativeVoiceTts.stop().catch(function () {});
    }
    tearDownNativeVoiceTtsSession();
    nativeVoiceTtsOnSessionEnded = null;
    if (CURRENT_AUDIO) {
      if (CURRENT_AUDIO.stop) CURRENT_AUDIO.stop();
      if (CURRENT_AUDIO_BUTTON) {
        $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
      }
      CURRENT_AUDIO = null;
      CURRENT_AUDIO_BUTTON = null;
    }
    if (currentAbortController) {
      currentAbortController.abort();
      currentAbortController = null;
      setGeneratingState(false);
    }
  }

  async function handleSpeechEnd(vadAudio) {
    console.log('[VAD] handleSpeechEnd called, vadSttInProgress=', vadSttInProgress);
    if (vadSttInProgress) return;
    vadSttInProgress = true;
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
      const formData = new FormData();
      formData.append('audio', wavBlob, 'recording.wav');

      const res = await fetch('/stt', {
        method: 'POST',
        headers: withCsrf({}),
        body: formData
      });
      if (!res.ok) throw new Error('STT request failed (' + res.status + ')');
      const data = await res.json();
      const text = (data.text || '').trim();

      if (text) {
        $('#user-input').val(text);
        sendMessage();
      }
    } catch (err) {
      appendMessage('<strong>Error:</strong> Voice STT failed: ' + escapeHTML(err.message), 'error-message');
    } finally {
      vadSttInProgress = false;
      if (window.voiceModeActive) {
        await reinitializeVAD();
      }
    }
  }

  // Pause/resume VAD when page is hidden
  document.addEventListener('visibilitychange', function () {
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

  // Voice mode TTS: native AudioTrack on Capacitor (AEC-safe), HTML audio on desktop
  window.playTTSVoiceMode = function playTTSVoiceMode(button) {
    if (CURRENT_AUDIO && CURRENT_AUDIO_BUTTON === button) {
      if (CURRENT_AUDIO.stop) CURRENT_AUDIO.stop();
      if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
      CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null; return;
    }
    if (CURRENT_AUDIO) {
      if (CURRENT_AUDIO.stop) CURRENT_AUDIO.stop();
      if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
      CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null;
    }

    const $messageElement = $(button).closest('.message');
    let isStopped = false;
    let processedText = '';
    let sentenceQueue = [];
    let isFetching = false;
    let audioEl = null;
    let nativeTtsPendingFetches = 0;
    let nativeTtsCloseRequested = false;
    nativeTtsFetchChain = Promise.resolve();
    voiceModeTtsSessionActive = true;

    function getPendingText() {
      const fullText = getMessageTtsText($messageElement);
      if (!fullText) return '';
      if (fullText.startsWith(processedText)) return fullText.substring(processedText.length);
      const idx = fullText.indexOf(processedText);
      if (idx !== -1) return fullText.substring(idx + processedText.length);
      return '';
    }

    function discoverSentences() {
      if (isStopped) return;
      const pending = getPendingText();
      if (!pending) return;
      // Same splitter as desktop TTS (ellipsis "..." is one terminator).
      const parts = splitSentences(pending);
      if (!parts.length) return;
      const currentRawText = $messageElement.find('.ai-message-text').text().trim();
      const stillGenerating = currentRawText === 'Thinking...' || (currentAbortController !== null);
      let advancedTo = 0;
      for (let pi = 0; pi < parts.length; pi++) {
        const p = parts[pi];
        // While streaming, leave an unfinished trailing fragment for later.
        if (!sentenceEndsWithTerminator(p.text) && stillGenerating) break;
        sentenceQueue.push(p.text);
        advancedTo = p.end;
      }
      if (advancedTo > 0) {
        // Include whitespace between the previous cursor and this end.
        processedText += pending.substring(0, advancedTo);
      }
    }

    function maybeFinishNativeTtsSession() {
      if (!useNativeVoiceTtsPlayback() || isStopped || nativeTtsCloseRequested) return;
      if (nativeTtsPendingFetches > 0 || sentenceQueue.length > 0) return;
      const currentRawText = $messageElement.find('.ai-message-text').text().trim();
      const stillGenerating = currentRawText === 'Thinking...' || (currentAbortController !== null);
      if (stillGenerating) {
        setTimeout(playNext, 200);
        return;
      }
      const remaining = getPendingText();
      if (remaining.trim()) {
        sentenceQueue.push(remaining);
        processedText += remaining;
        playNext();
        return;
      }
      nativeTtsCloseRequested = true;
      if (!nativeVoiceTtsSessionPromise) {
        if (!isStopped && CURRENT_AUDIO_BUTTON === button) {
          $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
          CURRENT_AUDIO = null;
          CURRENT_AUDIO_BUTTON = null;
        }
        finishVoiceModeTtsSession();
        return;
      }
      nativeVoiceTtsOnSessionEnded = function () {
        if (!isStopped && CURRENT_AUDIO_BUTTON === button) {
          $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
          CURRENT_AUDIO = null;
          CURRENT_AUDIO_BUTTON = null;
        }
        finishVoiceModeTtsSession();
      };
      closeNativeVoiceTtsSession().catch(function () {
        if (nativeVoiceTtsOnSessionEnded) {
          var cb = nativeVoiceTtsOnSessionEnded;
          nativeVoiceTtsOnSessionEnded = null;
          cb();
        }
      });
    }

    function scheduleNativeTtsFetch(text) {
      nativeTtsPendingFetches++;
      nativeTtsFetchChain = nativeTtsFetchChain.then(function () {
        if (isStopped) return;
        const controller = new AbortController();
        const timeoutId = setTimeout(function () { controller.abort(); }, 30000);
        return fetch('/tts', {
          method: 'POST',
          headers: withCsrf({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ text: text }),
          signal: controller.signal
        })
        .then(function (r) {
          clearTimeout(timeoutId);
          if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
          if (!r.ok) throw new Error('TTS request failed');
          return r.json();
        })
        .then(function (data) {
          if (isStopped) return;
          return enqueueNativeVoiceTts(data.token);
        })
        .finally(function () {
          clearTimeout(timeoutId);
        });
      }).catch(function (err) {
        console.error('Native voice TTS error:', err);
      }).finally(function () {
        nativeTtsPendingFetches--;
        if (!isStopped) {
          maybeFinishNativeTtsSession();
        }
      });
    }

    function playNext() {
      if (isStopped) return;
      if (sentenceQueue.length === 0) discoverSentences();

      if (useNativeVoiceTtsPlayback()) {
        while (sentenceQueue.length > 0) {
          const text = sentenceQueue.shift().trim();
          if (text) scheduleNativeTtsFetch(text);
        }
        maybeFinishNativeTtsSession();
        if (sentenceQueue.length === 0) {
          const currentRawText = $messageElement.find('.ai-message-text').text().trim();
          const stillGenerating = currentRawText === 'Thinking...' || (currentAbortController !== null);
          if (stillGenerating) {
            setTimeout(playNext, 200);
          }
        }
        return;
      }

      if (sentenceQueue.length === 0) {
        const currentRawText = $messageElement.find('.ai-message-text').text().trim();
        const stillGenerating = currentRawText === 'Thinking...' || (currentAbortController !== null);
        if (!stillGenerating) {
          const remaining = getPendingText();
          if (remaining.trim()) {
            sentenceQueue.push(remaining);
            processedText += remaining;
          } else {
            // All done
            if (CURRENT_AUDIO_BUTTON === button) {
              $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
              CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null;
            }
            finishVoiceModeTtsSession();
            return;
          }
        } else {
          setTimeout(playNext, 200);
          return;
        }
      }

      if (sentenceQueue.length > 0) {
        const text = sentenceQueue.shift().trim();
        if (!text) { setTimeout(playNext, 10); return; }

        isFetching = true;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        fetch('/tts', {
          method: 'POST',
          headers: withCsrf({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ text: text }),
          signal: controller.signal
        })
        .then(r => {
          clearTimeout(timeoutId);
          if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
          if (!r.ok) throw new Error('TTS request failed');
          return r.json();
        })
        .then(function (data) {
          if (isStopped) return;
          audioEl = new Audio('/tts_stream/' + data.token);
          audioEl.onplay = function () {
            onVoiceModeTtsStarted();
          };
          audioEl.onended = function () {
            onVoiceModeTtsEnded();
            if (!isStopped) { isFetching = false; playNext(); }
          };
          audioEl.onerror = function () {
            onVoiceModeTtsEnded();
            console.error('Voice mode audio playback error');
            isFetching = false;
            if (!isStopped) setTimeout(playNext, 500);
          };
          audioEl.play().catch(function (e) {
            onVoiceModeTtsEnded();
            console.error('Audio play failed:', e);
            isFetching = false;
            if (!isStopped) setTimeout(playNext, 500);
          });
        })
        .catch(err => {
          console.error('Voice mode TTS error:', err);
          isFetching = false;
          if (!isStopped) setTimeout(playNext, 500);
        });
      }
    }

    CURRENT_AUDIO = {
      stop: function () {
        isStopped = true;
        nativeTtsCloseRequested = true;
        nativeTtsFetchChain = Promise.resolve();
        finishVoiceModeTtsSession();
        tearDownNativeVoiceTtsSession();
        nativeVoiceTtsOnSessionEnded = null;
        if (window.NativeVoiceTts && window.nativeVoiceTtsAvailable) {
          window.NativeVoiceTts.stop().catch(function () {});
        }
        if (audioEl) { audioEl.pause(); audioEl.src = ''; audioEl = null; }
      }
    };
    CURRENT_AUDIO_BUTTON = button;
    $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
    playNext();
  };

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
  
  if ($contentDiv.css('display') === 'none') {
    $contentDiv.css('display', 'block');
    const label = isSearch ? 'Hide Search Details' : 'Hide Thinking';
    $button.html(`<i class="bi bi-caret-down-fill"></i> ${label}`);
  } else {
    $contentDiv.css('display', 'none');
    let label;
    if (isSearch) {
        label = isFinished ? 'Search completed.' : 'Searching the web...';
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
