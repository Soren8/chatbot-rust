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
        saveThoughts: cfg && cfg.saveThoughts !== undefined ? cfg.saveThoughts : true,
        sendThoughts: cfg && cfg.sendThoughts !== undefined ? cfg.sendThoughts : false,
      };
      console.debug('Initialized APP_DATA:', { save: window.APP_DATA.saveThoughts, send: window.APP_DATA.sendThoughts });
      window.DEFAULT_SYSTEM_PROMPT = (cfg && cfg.defaultSystemPrompt) || window.DEFAULT_SYSTEM_PROMPT || '';
    } else {
      window.APP_DATA = { userTier: 'free', availableModels: [], loggedIn: false, saveThoughts: true, sendThoughts: false };
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

const originalFetch = window.fetch;
window.fetch = function() {
  return originalFetch.apply(this, arguments).then(response => {
    if (response.status === 401) {
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
  return result;
}

// Settings panel behavior (collapse on small screens)
$(function() {
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

// Mobile input helper to keep input visible when keyboard shows
$(function() {
  try {
    var $input = $('#user-input');
    var $chatBox = $('#chat-box');
    if (!$input.length || !$chatBox.length) return;

    function updateInputHeight() {
      try {
        var h = $input[0].getBoundingClientRect().height || 56;
        $(':root').css('--chat-input-height', h + 'px');
        $chatBox.css('padding-bottom', 'calc(' + h + 'px + env(safe-area-inset-bottom, 0))');
      } catch (e) {}
    }

    $input.on('focus', function() {
      updateInputHeight();
      setTimeout(function() { try { $input[0].scrollIntoView({block: 'center'}); } catch (e) {} }, 300);
    });

    $(window).on('resize', updateInputHeight);
    updateInputHeight();
  } catch (e) { console.debug('mobile input helper error', e); }
});

// Global helpers and state
function escapeHTML(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

let CURRENT_AUDIO = null;
let CURRENT_AUDIO_BUTTON = null;

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
}

// Append a message to the chat content
function appendMessage(message, className, pairIndex) {
  const $chatContent = $('#chat-content');
  const $messageElement = $('<div>').addClass('message ' + className);

  if (className && className.indexOf('user-message') !== -1) {
    let originalText = message;
    if (typeof message === 'string' && message.indexOf('<strong>You:') !== -1) {
      const tmp = document.createElement('div');
      tmp.innerHTML = message;
      originalText = (tmp.textContent || tmp.innerText || '').replace(/^\s*You:\s*/, '').trim();
    }
    $messageElement.html(`<span class="user-message-text"><strong>You:</strong> ${escapeHTML(originalText)}</span>`);
    $messageElement.attr('data-original', originalText);
  } else {
    $messageElement.html(message);
  }

  if (typeof pairIndex !== 'undefined' && pairIndex !== null) {
    $messageElement.attr('data-pair-index', pairIndex);
  }

  if (className && className.indexOf('user-message') !== -1) {
    try {
      const $deleteContainer = $('<div>').addClass('regenerate-container');
      const $deleteBtn = $('<button>')
        .attr('type', 'button')
        .addClass('delete-button')
        .attr('title', 'Delete message')
        .html('<span class="delete-icon"><i class="bi bi-trash-fill"></i></span>');
      $deleteContainer.append($deleteBtn);
      $messageElement.append($deleteContainer);
    } catch (e) { console.debug('Failed to add delete button:', e); }
  }

  $chatContent.append($messageElement);
  const $scrollTarget = $('#chat-content');
  if (typeof __autoScroll !== 'undefined' ? __autoScroll : ($scrollTarget.scrollTop() + $scrollTarget.innerHeight() >= $scrollTarget[0].scrollHeight - 50)) {
    $scrollTarget.scrollTop($scrollTarget[0].scrollHeight);
  }
  return $messageElement;
}

window.playTTS = function playTTS(button) {
  if (CURRENT_AUDIO && CURRENT_AUDIO_BUTTON === button) {
    try { CURRENT_AUDIO.pause(); CURRENT_AUDIO.currentTime = 0; } catch (e) {}
    if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
    CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null; return;
  }
  if (CURRENT_AUDIO) {
    try { CURRENT_AUDIO.pause(); CURRENT_AUDIO.currentTime = 0; } catch (e) {}
    if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
    CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null;
  }
  const $messageElement = $(button).closest('.message');
  const messageText = $messageElement.find('.ai-message-text').text() || '';
  if (!messageText) return;
  $(button).prop('disabled', true).text('...');
  fetch('/tts', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ text: messageText }) })
    .then(r => { 
      if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
      if (!r.ok) throw new Error('Network response was not ok'); 
      return r.blob(); 
    })
    .then(blob => {
      const audioUrl = URL.createObjectURL(blob);
      const audio = new Audio(audioUrl);
      CURRENT_AUDIO = audio; CURRENT_AUDIO_BUTTON = button;
      $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');
      audio.play().catch(()=>{});
      audio.addEventListener('ended', () => { if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class=\"bi bi-play-fill\"></i>'); try { URL.revokeObjectURL(audioUrl); } catch (e) {} CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null; });
      audio.addEventListener('pause', () => { if (CURRENT_AUDIO_BUTTON) $(CURRENT_AUDIO_BUTTON).removeClass('playing').prop('disabled', false).html('<i class=\"bi bi-play-fill\"></i>'); });
    })
    .catch(err => { $(button).prop('disabled', false).html('<i class="bi bi-play-fill"></i>').removeClass('playing'); alert('Error playing audio: ' + err.message); });
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
  const $targetAI = $('.ai-message').eq(pairIndex);
  const $target = $targetAI.length ? $targetAI : $aiMessageElement;
  $target.html(`<strong>AI:</strong><div class="thinking-container" style="display:none;"><button class="toggle-thinking" style="display:none;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;"></div></div><span class="ai-message-text">Thinking...</span><div class="regenerate-container"><button class="regenerate-button" disabled><i class="bi bi-arrow-repeat"></i></button><button class="play-button" disabled><i class="bi bi-play-fill"></i></button></div>`);
  // Initial scroll to bottom when regeneration starts
  const $scrollTarget = $('#chat-content');
  if ($scrollTarget.length) $scrollTarget.scrollTop($scrollTarget[0].scrollHeight);

  fetch('/regenerate', {
    method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      message: userText,
      system_prompt: $('#user-system-prompt').val(),
      set_name: $('#set-selector').val() || 'default',
      model_name: $('#modelSelect').val(),
      pair_index: pairIndex,
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    })
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

    function appendVisible(content) {
      if (!content) return;
      if (!hasWrittenToDOM) { $msgText.text(content); hasWrittenToDOM = true; }
      else { $msgText.text($msgText.text() + content); }
    }
    function appendThinking(content) {
      if (!content) return;
      if (!hasWrittenToDOM) { $msgText.text(''); hasWrittenToDOM = true; }
      $thinkingWrap.show();
      $thinkingWrap.find('.toggle-thinking').show();
      $thinkingContent.text($thinkingContent.text() + content);
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
          try { $target.find('.regenerate-button, .play-button').prop('disabled', false); $target.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
          return;
        }
        buffer += decoder.decode(value, {stream:true});
        const $scrollTarget = $('#chat-content');
        const nearBottom = $scrollTarget.length && ($scrollTarget.scrollTop() + $scrollTarget.innerHeight() >= $scrollTarget[0].scrollHeight - 50);
        processBuffer();
        if (nearBottom) {
          $scrollTarget.scrollTop($scrollTarget[0].scrollHeight);
        }
        read();
      }).catch(()=>{});
    }
    read();
  })
  .catch(err => { $aiMessageElement.html(`<strong>AI:</strong> <span class="error-message">Error: ${err.message}</span>`); });
}

// Main ready block
$(document).ready(function() {
  disablePremiumModels();

  // Initialize checkboxes
  if (window.APP_DATA) {
    $('#check-save-thoughts').prop('checked', window.APP_DATA.saveThoughts);
    $('#check-send-thoughts').prop('checked', window.APP_DATA.sendThoughts);
  }

  // Validate model tier on selection change (replacing inline onchange)
  $('#modelSelect').on('change', validateModelTier);

  // Delegation for play and delete
  $(document).on('click', function(event) {
    const target = event.target;
    const playBtn = target.closest && target.closest('.play-button');
    if (playBtn) { window.playTTS(playBtn); return; }
    const deleteBtn = target.closest && target.closest('.delete-button');
    if (deleteBtn) {
      const userMessageElement = deleteBtn.closest('.message.user-message');
      if (!userMessageElement) return;
      const aiMessageElement = userMessageElement.nextElementSibling && userMessageElement.nextElementSibling.classList.contains('ai-message') ? userMessageElement.nextElementSibling : null;
      const userText = (userMessageElement.querySelector('.user-message-text')?.textContent || '').replace('You:', '').trim();
      const aiText = aiMessageElement ? (aiMessageElement.querySelector('.ai-message-text')?.textContent || '').trim() : '';
      if (aiMessageElement) aiMessageElement.remove();
      userMessageElement.remove();
      fetch('/delete_message', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ user_message: userText, ai_message: aiText, set_name: $('#set-selector').val() || 'default' }) })
        .then(r => { if (r.status === 401) { window.location.href = '/login'; } })
        .catch(()=>{});
    }
  });

  // Delegated handlers replacing inline onclicks
  $(document).on('click', '.regenerate-button', function() { window.regenerateMessage(this); });
  $(document).on('click', '.toggle-thinking', function() { window.toggleThinking(this); });

  // Load sets for logged-in users
  if (window.APP_DATA.loggedIn) {
    function formatAiMessage(text) {
      if (!text) return '';
      let html = '';
      let buffer = text;
      let state = 'visible';
      const openTag = '<think>';
      const closeTags = ['</think>', '[BEGIN FINAL RESPONSE]'];

      while (buffer.length > 0) {
        if (state === 'visible') {
          const idx = buffer.indexOf(openTag);
          if (idx !== -1) {
            html += escapeHTML(buffer.substring(0, idx));
            buffer = buffer.substring(idx + openTag.length);
            state = 'thinking';
            html += '<div class="thinking-container" style="display:block;"><button class="toggle-thinking" style="display:inline-block;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;">';
          } else {
            html += escapeHTML(buffer);
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
            html += escapeHTML(buffer.substring(0, firstCloseIdx));
            buffer = buffer.substring(firstCloseIdx + usedTagLen);
            state = 'visible';
            html += '</div></div>';
          } else {
            html += escapeHTML(buffer);
            buffer = '';
            html += '</div></div>';
          }
        }
      }
      return html;
    }

    function loadSets(shouldTriggerChange = true) {
      return fetch('/get_sets', { headers: withCsrf() })
        .then(r => r.json())
        .then(data => {
          const $selector = $('#set-selector');
          $selector.empty();
          $.each(data, function(setName) {
            $('<option>').val(setName).text(setName).appendTo($selector);
          });
          if (shouldTriggerChange) {
            $selector.trigger('change');
          }
        });
    }

    $('#set-selector').on('change', function() {
      const setName = $(this).val();
      fetch('/load_set', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ set_name: setName }) })
        .then(async r => {
          if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
          if (!r.ok) {
            try { const err = await r.json(); throw new Error(err && (err.error || err.message) || 'Failed to load set'); }
            catch (_) { throw new Error('Failed to load set'); }
          }
          return r.json();
        })
        .then(data => {
          $('#user-system-prompt').val(data.system_prompt || '');
          $('#user-memory').val(data.memory || '');
          $('#chat-content').empty();
          if (data.history && data.history.length > 0) {
            data.history.forEach(([userMsg, aiMsg]) => {
              appendMessage(userMsg, 'user-message');
              const formattedAi = formatAiMessage(aiMsg);
              appendMessage(`<strong>AI:</strong>&nbsp;<span class=\"ai-message-text\">${formattedAi}</span><div class=\"regenerate-container\"><button class=\"regenerate-button\"><i class=\"bi bi-arrow-repeat\"></i></button><button class=\"play-button\"><i class=\"bi bi-play-fill\"></i></button></div>`, 'ai-message');
            });
            setTimeout(function() { try { $('#chat-content').scrollTop($('#chat-content')[0].scrollHeight); } catch (e) {} }, 0);
          }
          appendMessage('<strong>System:</strong> Loaded set: ' + escapeHTML(setName), 'system-message');
        })
        .catch(error => { appendMessage('<strong>Error:</strong> Failed to load set: ' + escapeHTML(error.message), 'error-message'); });
      });
    // Populate sets after binding change handler so initial trigger loads data
    loadSets();

    $('#new-set').on('click', function() {
      const setName = prompt('Enter name for new set:');
      if (setName) {
        fetch('/create_set', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ set_name: setName }) })
          .then(r => r.json())
          .then(data => {
            if (data.status === 'success') {
              loadSets(false).then(() => { 
                $('#set-selector').val(setName); 
                $('#set-selector').trigger('change'); 
              });
              appendMessage('<strong>System:</strong> Created new set: ' + escapeHTML(setName), 'system-message');
            } else {
              appendMessage('<strong>Error:</strong> ' + data.error, 'error-message');
            }
          });
      }
    });

    $('#delete-set').on('click', function() {
      const setName = $('#set-selector').val();
      if (setName === 'default') { appendMessage('<strong>Error:</strong> Cannot delete default set', 'error-message'); return; }
      if (confirm('Are you sure you want to delete set: ' + setName + '?')) {
        fetch('/delete_set', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ set_name: setName }) })
          .then(r => r.json())
          .then(data => {
            if (data.status === 'success') { loadSets(); appendMessage('<strong>System:</strong> Deleted set: ' + escapeHTML(setName), 'system-message'); }
            else { appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to delete set'), 'error-message'); }
          });
      }
    });
  }

  // Save buttons
  $('#save-system-prompt').on('click', function() {
    const sysPromptText = $('#user-system-prompt').val();
    const setName = $('#set-selector').val() || 'default';
    fetch('/update_system_prompt', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ system_prompt: sysPromptText, set_name: setName }) })
      .then(r => { if (!r.ok) throw new Error('Network response was not ok'); return r.json(); })
      .then(data => { if (data.status === 'success') appendMessage('<strong>System:</strong> System prompt saved successfully.', 'system-message'); else appendMessage('<strong>Error:</strong> Failed to save system prompt.', 'error-message'); })
      .catch(error => { appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message'); });
  });

  $('#save-memory').on('click', function() {
    const memText = $('#user-memory').val();
    const setName = $('#set-selector').val() || 'default';
    fetch('/update_memory', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ memory: memText, set_name: setName }) })
      .then(r => r.json())
      .then(data => { if (data.status === 'success') appendMessage('<strong>System:</strong> Memory saved successfully.', 'system-message'); else appendMessage('<strong>Error:</strong> Failed to save memory.', 'error-message'); })
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
    if (!message) return;
    const systemPrompt = $systemPromptElement.val() || window.DEFAULT_SYSTEM_PROMPT;
    const activeSet = ($('#set-selector').val() || 'default');
    $userInputElement.val('');
    appendMessage('<strong>You:</strong> ' + escapeHTML(message), 'user-message');
    const requestData = {
      message,
      system_prompt: systemPrompt,
      set_name: activeSet,
      model_name: $('#modelSelect').val(),
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    };
    fetch('/chat', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify(requestData) })
      .then(response => { 
        if (response.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
        if (!response.ok) return response.text().then(t => { throw new Error(t || 'Network response was not ok'); }); 
        return response; 
      })
      .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        appendMessage(`<strong>AI:</strong><div class="thinking-container" style="display:none;"><button class="toggle-thinking" style="display:none;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;"></div></div><span class="ai-message-text">Thinking...</span><div class="regenerate-container"><button class="regenerate-button" disabled><i class="bi bi-arrow-repeat"></i></button><button class="play-button" disabled><i class="bi bi-play-fill"></i></button></div>`, 'ai-message');
        // Initial scroll to bottom when AI starts responding
        const $scrollTarget = $('#chat-content');
        $scrollTarget.scrollTop($scrollTarget[0].scrollHeight);
        const $targetElement = $('.ai-message:last-child');
        const $messageTextElement = $targetElement.find('.ai-message-text');
        const $thinkingContainerWrapper = $targetElement.find('.thinking-container');
        const $thinkingContentElement = $targetElement.find('.thinking-content');
        let buffer = '';
        let state = 'visible';
        let hasWrittenToDOM = false;
        function appendVisible(content) {
          if (!content) return;
          if (!hasWrittenToDOM) { $messageTextElement.text(content); hasWrittenToDOM = true; }
          else { $messageTextElement.text($messageTextElement.text() + content); }
        }
        function appendThinking(content) {
          if (!content) return;
          if (!hasWrittenToDOM) { $messageTextElement.text(''); hasWrittenToDOM = true; }
          $thinkingContainerWrapper.show();
          $thinkingContainerWrapper.find('.toggle-thinking').show();
          $thinkingContentElement.text($thinkingContentElement.text() + content);
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
              try { $targetElement.find('.regenerate-button, .play-button').prop('disabled', false); $targetElement.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
              return;
            }
            const chunk = decoder.decode(value, { stream: true });
            const $scrollTarget = $('#chat-content');
            const nearBottom = $scrollTarget.length && ($scrollTarget.scrollTop() + $scrollTarget.innerHeight() >= $scrollTarget[0].scrollHeight - 50);
            processChunk(chunk);
            if (nearBottom) {
              $scrollTarget.scrollTop($scrollTarget[0].scrollHeight);
            }
            return readStream();
          }).catch(()=>{});
        }
        readStream();
      })
      .catch(error => { appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message'); });
  }

  $('#user-input').on('keypress', function(e) { if (e.key === 'Enter') { e.preventDefault(); sendMessage(); } });
  $('#send-button').on('click', function() { sendMessage(); });

  $('#reset-chat').on('click', function() {
    const setName = $('#set-selector').val() || 'default';
    if (confirm(`Are you sure you want to reset the chat history for set: ${setName}?`)) {
      fetch('/reset_chat', { method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }), body: JSON.stringify({ set_name: setName }) })
        .then(r => { if (!r.ok) return r.json().then(err => { throw new Error(err.message || 'Failed to reset chat'); }); return r.json(); })
        .then(response => {
          if (response.status === 'success') {
            $('#chat-content').empty();
            appendMessage('<strong>System:</strong> Chat history has been reset for set ' + escapeHTML(response.set_name) + '.', 'system-message');
          } else {
            appendMessage(`<strong>Error:</strong> ${escapeHTML(response.message)}`, 'error-message');
          }
        })
        .catch(error => { appendMessage(`<strong>Error:</strong> ${escapeHTML(error.message)}`, 'error-message'); });
    }
  });

  // Initialize prompt/memory for guests
  if (!window.APP_DATA.loggedIn) {
    $('#user-system-prompt').val(window.DEFAULT_SYSTEM_PROMPT);
    $('#user-memory').val('');
  }

  $(window).trigger('resize');
});

// Toggle thinking content visibility (used by inline handler in generated HTML)
window.toggleThinking = function toggleThinking(button) {
  const $button = $(button);
  const $contentDiv = $button.next();
  if ($contentDiv.css('display') === 'none') {
    $contentDiv.css('display', 'block');
    $button.html('<i class="bi bi-caret-down-fill"></i> Hide Thinking');
  } else {
    $contentDiv.css('display', 'none');
    $button.html('<i class="bi bi-caret-right-fill"></i> Show Thinking');
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
        };
        window.DEFAULT_SYSTEM_PROMPT = window.DEFAULT_SYSTEM_PROMPT || cfg.defaultSystemPrompt || '';
      } catch (e) {
        console.debug('APP_DATA parse error', e);
      }
    }
  }
})();
