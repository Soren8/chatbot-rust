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

const originalFetch = window.fetch;
window.fetch = function(input, init) {
  return originalFetch.apply(this, arguments).then(response => {
    if (response.status === 401) {
      let url = input;
      if (input instanceof Request) {
        url = input.url;
      }
      if (typeof url === 'string' && (url.includes('/update_memory') || url.includes('/update_system_prompt'))) {
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
    $messageElement.html(`<span class="user-message-text"><strong>You:</strong> ${renderMarkdown(originalText)}</span>`);
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

window.playTTS = function playTTS(button) {
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
  let nextStartTime = 0;
  let processedText = '';
  let sentenceQueue = [];
  let isFetching = false;
  
  // Use a single AudioContext for sample-accurate scheduling
  const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  if (audioCtx.state === 'suspended') {
    audioCtx.resume().catch(e => console.debug('AudioContext resume failed:', e));
  }

  CURRENT_AUDIO = {
    stop: () => {
      isStopped = true;
      if (audioCtx.state !== 'closed') audioCtx.close().catch(() => {});
    }
  };
  CURRENT_AUDIO_BUTTON = button;

  $(button).prop('disabled', false).addClass('playing').html('<i class="bi bi-stop-fill"></i>');

  function getPendingText() {
    // Prefer data-original if available, as it is the raw text (not markdown-mangled)
    let fullText = $messageElement.attr('data-original') || '';
    if (fullText) {
      // Strip thinking tags to get only the visible text
      fullText = fullText.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    }
    
    // Fallback to DOM text if data-original is missing or empty
    if (!fullText) {
      const $textClone = $messageElement.find('.ai-message-text').clone();
      $textClone.find('.thinking-container').remove();
      $textClone.find('.regenerate-container').remove();
      fullText = $textClone.text().trim();
    }

    if (fullText === 'Thinking...') return '';
    if (fullText.startsWith(processedText)) {
      return fullText.substring(processedText.length);
    }
    // Fallback if mismatch occurs (e.g. due to markdown re-rendering)
    console.debug('TTS text mismatch, attempting recovery', { 
      full: fullText.substring(0, 20) + '...', 
      processed: processedText.substring(0, 20) + '...' 
    });
    const idx = fullText.indexOf(processedText);
    if (idx !== -1) {
      return fullText.substring(idx + processedText.length);
    }
    return '';
  }

  function discoverSentences() {
    if (isStopped) return;
    const pending = getPendingText();
    if (!pending) return;

    // Look for sentence terminators
    const matches = pending.match(/[^.!?]+[.!?]+/g);
    if (matches) {
      matches.forEach(s => {
        sentenceQueue.push(s);
        processedText += s;
      });
    }
  }

  function processQueue() {
    if (isStopped || isFetching) return;
    
    if (sentenceQueue.length === 0) {
      discoverSentences();
    }

    if (sentenceQueue.length === 0) {
      // Check if generation is finished or still in 'Thinking...' phase
      const currentRawText = $messageElement.find('.ai-message-text').text().trim();
      const stillThinking = currentRawText === 'Thinking...';
      const stillGenerating = stillThinking || (window.currentAbortController !== null);
      
      if (!stillGenerating) {
        const remaining = getPendingText();
        if (remaining.trim()) {
          sentenceQueue.push(remaining);
          processedText += remaining;
        } else {
          // Truly finished
          const checkEnd = setInterval(() => {
            if (isStopped) { clearInterval(checkEnd); return; }
            
            // If context is suspended, try to resume it one last time
            if (audioCtx.state === 'suspended') {
              audioCtx.resume().catch(() => {});
            }

            if (audioCtx.currentTime >= nextStartTime) {
              clearInterval(checkEnd);
              if (CURRENT_AUDIO_BUTTON === button) {
                $(button).removeClass('playing').prop('disabled', false).html('<i class="bi bi-play-fill"></i>');
                CURRENT_AUDIO = null; CURRENT_AUDIO_BUTTON = null;
              }
            }
          }, 100);
          return;
        }
      } else {
        // Still generating or still thinking, poll again soon
        setTimeout(processQueue, 200);
        return;
      }
    }

    if (sentenceQueue.length > 0) {
      const text = sentenceQueue.shift().trim();
      if (!text) { setTimeout(processQueue, 10); return; }

      isFetching = true;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      // Step 1: Get Token
      fetch('/tts', {
        method: 'POST',
        headers: withCsrf({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ text: text }),
        signal: controller.signal
      })
      .then(r => {
        clearTimeout(timeoutId);
        if (r.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
        if (!r.ok) throw new Error('Network response was not ok');
        return r.json();
      })
      .then(data => {
        if (isStopped) return;
        // Step 2: Fetch full WAV
        return fetch(`/tts_stream/${data.token}`).then(r => {
            if (!r.ok) throw new Error('Stream fetch failed');
            return r.arrayBuffer();
        });
      })
      .then(arrayBuffer => {
        if (isStopped) { isFetching = false; return; }
        if (!arrayBuffer || arrayBuffer.byteLength === 0) { throw new Error('Empty audio buffer'); }
        // Step 3: Decode full WAV
        return audioCtx.decodeAudioData(arrayBuffer);
      })
      .then(audioBuffer => {
        if (isStopped) { isFetching = false; return; }
        if (!audioBuffer) { throw new Error('Failed to decode audio'); }
        
        const source = audioCtx.createBufferSource();
        source.buffer = audioBuffer;
        source.connect(audioCtx.destination);
        
        // Ensure AudioContext is running
        if (audioCtx.state === 'suspended') {
          audioCtx.resume().catch(() => {});
        }

        const now = audioCtx.currentTime;
        // If we are starting or have fallen behind, start immediately
        if (nextStartTime < now) nextStartTime = now;
        
        source.start(nextStartTime);
        nextStartTime += audioBuffer.duration;
        
        isFetching = false;
        processQueue();
      })
      .catch(err => {
        console.error('TTS error:', err);
        isFetching = false;
        // Wait a bit before retrying to avoid rapid failure loops
        setTimeout(processQueue, 500);
      });
    }
  }

  processQueue();
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
  
  if (window.APP_DATA.autoplayTTS) {
    const playBtn = $target.find('.play-button')[0];
    if (playBtn) setTimeout(() => window.playTTS(playBtn), 50);
  }

  // Initial scroll to bottom when regeneration starts
  scrollToBottom();

  if (currentAbortController) currentAbortController.abort();
  currentAbortController = new AbortController();
  setGeneratingState(true);

  fetch('/regenerate', {
    method: 'POST', headers: withCsrf({ 'Content-Type': 'application/json' }),
    signal: currentAbortController.signal,
    body: JSON.stringify({
      message: userText,
      system_prompt: $('#user-system-prompt').val(),
      set_name: $('#set-selector').val() || 'default',
      model_name: $('#modelSelect').val(),
      pair_index: pairIndex,
      web_search: $('#web-search-toggle').hasClass('btn-primary'),
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
              
              try { $target.find('.regenerate-button, .play-button').prop('disabled', false); $target.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
              setGeneratingState(false);
              currentAbortController = null;
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
            try { $target.find('.regenerate-button, .play-button').prop('disabled', false); $target.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
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
        try { $target.find('.regenerate-button, .play-button').prop('disabled', false); $target.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
        setGeneratingState(false);
        currentAbortController = null;
      });
};

function handleDeleteMessage(buttonElement) {
  const deleteBtn = $(buttonElement);
  const userMessageElement = deleteBtn.closest('.message.user-message');
  if (userMessageElement.length === 0) return;
  
  const aiMessageElement = userMessageElement.next('.ai-message');
  
  // Use data-original if available, fallback to text parsing (fragile)
  const userText = (userMessageElement.attr('data-original') || userMessageElement.find('.user-message-text').text() || userMessageElement.text() || '').replace(/^\s*You:\s*/, '').trim();
  const aiText = (aiMessageElement.attr('data-original') || (aiMessageElement.find('.ai-message-text').text() || '').trim());
  
  console.debug('Deleting message pair:', { userText, aiText });

  if (aiMessageElement.length) aiMessageElement.remove();
  userMessageElement.remove();
  
  fetch('/delete_message', { 
    method: 'POST', 
    headers: withCsrf({ 'Content-Type': 'application/json' }), 
    body: JSON.stringify({ 
      user_message: userText, 
      ai_message: aiText, 
      set_name: $('#set-selector').val() || 'default' 
    }) 
  })
  .then(r => { 
    if (r.status === 401) { window.location.href = '/login'; }
    return r.json();
  })
  .then(data => {
    if (data && data.status === 'error') {
      console.error('Server failed to delete message:', data.error);
    }
  })
  .catch(err => {
    console.error('Error deleting message:', err);
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

  // Initialize checkboxes
  if (window.APP_DATA) {
    $('#check-save-thoughts').prop('checked', window.APP_DATA.saveThoughts);
    $('#check-send-thoughts').prop('checked', window.APP_DATA.sendThoughts);
    $('#check-render-markdown').prop('checked', window.APP_DATA.renderMarkdown);
    $('#check-autoplay-tts').prop('checked', window.APP_DATA.autoplayTTS);
  }

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

  // Delegation for play, delete, and edit
  $(document).on('click', function(event) {
    const target = event.target;
    const playBtn = target.closest && target.closest('.play-button');
    if (playBtn) { window.playTTS(playBtn); return; }

    const editBtn = target.closest && target.closest('.edit-button');
    if (editBtn) {
      const $messageElement = $(editBtn).closest('.message.user-message');
      const $textSpan = $messageElement.find('.user-message-text');
      const originalText = $messageElement.attr('data-original') || $textSpan.text().replace(/^You:\s*/, '').trim();

      if ($messageElement.find('.edit-textarea').length > 0) return;

      const $textarea = $('<textarea>').addClass('edit-textarea form-control').val(originalText);
      const $actions = $('<div>').addClass('edit-actions mt-2');
      const $saveBtn = $('<button>').addClass('btn btn-sm btn-primary save-edit').text('Save');
      const $cancelBtn = $('<button>').addClass('btn btn-sm btn-secondary cancel-edit ms-2').text('Cancel');

      $actions.append($saveBtn).append($cancelBtn);
      $textSpan.hide();
      $messageElement.find('.regenerate-container').hide();
      $messageElement.prepend($textarea).append($actions);
      $textarea.focus();
      return;
    }

    const saveEditBtn = target.closest && target.closest('.save-edit');
    if (saveEditBtn) {
      const $messageElement = $(saveEditBtn).closest('.message.user-message');
      const newText = $messageElement.find('.edit-textarea').val().trim();
      if (!newText) return;

      const userMsgNodes = Array.from(document.querySelectorAll('.message.user-message'));
      const pairIndex = userMsgNodes.indexOf($messageElement[0]);

      $messageElement.attr('data-original', newText);
      $messageElement.find('.user-message-text').html(`<strong>You:</strong> ${renderMarkdown(newText)}`).show();
      $messageElement.find('.edit-textarea').remove();
      $messageElement.find('.edit-actions').remove();
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
      $messageElement.find('.edit-textarea').remove();
      $messageElement.find('.edit-actions').remove();
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

  // Load sets for logged-in users
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
      return fetch('/get_sets', { headers: withCsrf() })
        .then(r => r.json())
        .then(data => {
          const $selector = $('#set-selector');
          $selector.empty();
          let setExists = false;
          $.each(data, function(_, setInfo) {
            const setName = setInfo.name;
            $('<option>').val(setName).text(setName).appendTo($selector);
            if (window.APP_DATA.lastSet && setName === window.APP_DATA.lastSet) {
                setExists = true;
            }
          });
          
          if (setExists) {
              $selector.val(window.APP_DATA.lastSet);
          } else if (window.APP_DATA.lastSet) {
              // If last set was deleted or invalid, fallback to default but don't persist yet
              console.debug('Last set not found, falling back to default');
          }

          if (shouldTriggerChange) {
            $selector.trigger('change');
          }
        });
    }

    $('#set-selector').on('change', function() {
      const setName = $(this).val();
      savePreferences();
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
              const $aiMsg = appendMessage(`<strong>AI:</strong>&nbsp;<span class=\"ai-message-text\">${formattedAi}</span><div class=\"regenerate-container\"><button class=\"regenerate-button\"><i class=\"bi bi-arrow-repeat\"></i></button><button class=\"play-button\"><i class=\"bi bi-play-fill\"></i></button></div>`, 'ai-message');
              $aiMsg.attr('data-original', aiMsg);
            });
            setTimeout(function() { scrollToBottom(); }, 0);
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
                // Trigger change to load the newly created set
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
      const oldName = $('#set-selector').val();
      if (oldName === 'default') {
        appendMessage('<strong>Error:</strong> Cannot rename default set', 'error-message');
        return;
      }
      const newName = prompt('Enter new name for set:', oldName);
      if (newName && newName !== oldName) {
        fetch('/rename_set', {
          method: 'POST',
          headers: withCsrf({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ old_name: oldName, new_name: newName })
        })
        .then(r => r.json())
        .then(data => {
          if (data.status === 'success') {
            loadSets(false).then(() => {
              $('#set-selector').val(newName);
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
    fetch('/update_system_prompt', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        system_prompt: sysPromptText,
        set_name: setName,
        logged_in: window.APP_DATA && window.APP_DATA.loggedIn
      })
    })
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          appendMessage('<strong>System:</strong> System prompt saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
        }
        else appendMessage('<strong>Error:</strong> ' + (data.error || 'Failed to save system prompt.'), 'error-message');
      })
      .catch(error => { appendMessage('<strong>Error:</strong> ' + escapeHTML(error.message), 'error-message'); });
  });

  $('#save-memory').on('click', function() {
    const memText = $('#user-memory').val();
    const setName = $('#set-selector').val() || 'default';
    fetch('/update_memory', {
      method: 'POST',
      headers: withCsrf({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        memory: memText,
        set_name: setName,
        logged_in: window.APP_DATA && window.APP_DATA.loggedIn
      })
    })
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success') {
          appendMessage('<strong>System:</strong> Memory saved successfully.', 'system-message');
          if (typeof loadSets === 'function') loadSets(false);
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
      web_search: $('#web-search-toggle').hasClass('btn-primary'),
      save_thoughts: $('#check-save-thoughts').is(':checked'),
      send_thoughts: $('#check-send-thoughts').is(':checked')
    };

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
        if (response.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
        if (!response.ok) return response.text().then(t => { throw new Error(t || 'Network response was not ok'); }); 
        return response; 
      })
      .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        appendMessage(`<strong>AI:</strong><div class="thinking-container" style="display:none;"><button class="toggle-thinking" style="display:none;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;"></div></div><span class="ai-message-text">Thinking...</span><div class="regenerate-container"><button class="regenerate-button" disabled><i class="bi bi-arrow-repeat"></i></button><button class="play-button"><i class="bi bi-play-fill"></i></button></div>`, 'ai-message');
        
        const $targetElement = $('.ai-message:last-child');

        if (window.APP_DATA.autoplayTTS) {
          const playBtn = $targetElement.find('.play-button')[0];
          if (playBtn) setTimeout(() => window.playTTS(playBtn), 50);
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

              try { $targetElement.find('.regenerate-button, .play-button').prop('disabled', false); $targetElement.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
              setGeneratingState(false);
              currentAbortController = null;
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
            try { $targetElement.find('.regenerate-button, .play-button').prop('disabled', false); $targetElement.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
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
          try { $lastAI.find('.regenerate-button, .play-button').prop('disabled', false); $lastAI.find('.play-button').html('<i class="bi bi-play-fill"></i>'); } catch (e) {}
        } else {
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
