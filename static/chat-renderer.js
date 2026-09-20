(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatRenderer = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Owned browser message rendering: pure escaping/sanitizing plus cohesive
  // DOM builders for user/system/error/AI chrome, markdown and history
  // projection. Chat keeps DOM/event composition (mount, scroll, message
  // assembly, lightbox open/close); every DOM/markdown/highlighter need
  // arrives as an explicit injected dependency, never a generic getter bag:
  // - doc: document (createElement/createTextNode/createDocumentFragment)
  // - getMarked: () => marked parser (or undefined when not loaded)
  // - getHljs: () => highlight.js (or undefined when not loaded)
  // - createTrustedHtml: Trusted-Types policy wrapper (ttHtml adapter)
  // - isMarkdownEnabled: () => bool (APP_DATA.renderMarkdown check)
  // - getLocation: () => { href, origin } (page-location adapter)
  // - getStreamDecoder: () => ChatStreamDecoder (decodeComplete)
  // Parser/highlighter/decoder globals are read per call through the getters
  // (late binding wins over load-time capture), exactly where the original
  // inline code read them. No window/document access inside; console
  // diagnostics preserved verbatim.

  function escapeHTML(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function decodeHTMLEntities(str) {
    return String(str == null ? '' : str)
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#0*39;/g, "'")
      .replace(/&amp;/g, '&');
  }

  function sanitizeDataImageSrc(src) {
    if (src == null) return null;
    var raw = String(src);
    var m = /^data:image\/([A-Za-z0-9+.-]+);base64,([A-Za-z0-9+/=\s]+)$/.exec(raw);
    if (!m) return null;
    var subtype = m[1].replace(/[^A-Za-z0-9+.-]/g, '');
    var b64 = m[2].replace(/[^A-Za-z0-9+/=]/g, '');
    if (!subtype || !b64 || subtype !== m[1] || b64 !== m[2].replace(/[\s]/g, '')) {
      return null;
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
    return 'data:image/' + subtype + ';base64,' + b64;
  }

  function createChatRenderer(deps) {
    deps = deps || {};
    var doc = deps.document || null;
    var getMarked = deps.getMarked;
    var getHljs = deps.getHljs;
    var getStreamDecoder = deps.getStreamDecoder;
    var createTrustedHtml = (typeof deps.createTrustedHtml === 'function')
      ? deps.createTrustedHtml
      : function (html) { return html; };
    var isMarkdownEnabled = (typeof deps.isMarkdownEnabled === 'function')
      ? deps.isMarkdownEnabled
      : function () { return true; };
    var getLocation = (typeof deps.getLocation === 'function')
      ? deps.getLocation
      : function () { return { href: '', origin: '' }; };

    function sanitizeLightboxSrc(src) {
      var dataSrc = sanitizeDataImageSrc(src);
      if (dataSrc) return dataSrc;
      if (src == null) return null;
      try {
        var loc = getLocation();
        var base = (loc && loc.href) || '';
        var origin = (loc && loc.origin) || '';
        var U = (typeof URL !== 'undefined') ? URL : null;
        if (!U) return null;
        var u = new U(String(src), base);
        if (u.origin !== origin) return null;
        var m = /^\/history_image\/([A-Za-z0-9._~-]+)\/([0-9]+)\/([0-9]+)\/([0-9]+)$/.exec(u.pathname);
        if (!m) return null;
        var setId = m[1].replace(/[^A-Za-z0-9._~-]/g, '');
        var version = m[2].replace(/[^0-9]/g, '');
        var pairIndex = m[3].replace(/[^0-9]/g, '');
        var imgIdx = m[4].replace(/[^0-9]/g, '');
        if (!setId || setId !== m[1] || version !== m[2] || pairIndex !== m[3] || imgIdx !== m[4]) {
          return null;
        }
        var path = '/history_image/' + setId + '/' + version + '/' + pairIndex + '/' + imgIdx;
        if (!u.search) return path;
        if (u.search === '?size=thumb') return path + '?size=thumb';
        return null;
      } catch (e) {
        return null;
      }
    }

    function buildUserMessageSpan(text, imageSrc, opts) {
      var span = doc.createElement('span');
      span.className = 'user-message-text';

      var label = doc.createElement('strong');
      label.textContent = 'You:';
      span.appendChild(label);
      span.appendChild(doc.createTextNode(' '));

      var body = doc.createElement('span');
      body.className = 'user-message-body';
      var lines = String(text == null ? '' : text).split('\n');
      for (var i = 0; i < lines.length; i++) {
        if (i > 0) body.appendChild(doc.createElement('br'));
        body.appendChild(doc.createTextNode(lines[i]));
      }
      span.appendChild(body);

      var safeSrc = sanitizeDataImageSrc(imageSrc) || sanitizeLightboxSrc(imageSrc);
      if (safeSrc) {
        span.appendChild(doc.createElement('br'));
        var img = doc.createElement('img');
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

    function appendPlainTextWithBreaks(parent, text) {
      var lines = String(text == null ? '' : text).split('\n');
      for (var i = 0; i < lines.length; i++) {
        if (i > 0) parent.appendChild(doc.createElement('br'));
        parent.appendChild(doc.createTextNode(lines[i]));
      }
    }

    function buildStatusMessageContent(className, text) {
      var frag = doc.createDocumentFragment();
      var isError = className && className.indexOf('error-message') !== -1;
      var label = doc.createElement('strong');
      label.textContent = isError ? 'Error:' : 'System:';
      frag.appendChild(label);
      frag.appendChild(doc.createTextNode(' '));
      appendPlainTextWithBreaks(frag, text == null ? '' : String(text));
      return frag;
    }

    function buildSetsLoadErrorContent(errorText) {
      var frag = doc.createDocumentFragment();
      var label = doc.createElement('strong');
      label.textContent = 'Error:';
      frag.appendChild(label);
      frag.appendChild(doc.createTextNode(' '));
      appendPlainTextWithBreaks(
        frag,
        'Could not load saved sets: ' + String(errorText == null ? '' : errorText) + ' '
      );
      var a = doc.createElement('a');
      a.setAttribute('href', '/logout');
      a.textContent = 'Sign out';
      frag.appendChild(a);
      frag.appendChild(doc.createTextNode(' and log in again if this persists.'));
      return frag;
    }

    function buildAiLabelFragment() {
      var frag = doc.createDocumentFragment();
      var strong = doc.createElement('strong');
      strong.textContent = 'AI:';
      frag.appendChild(strong);
      return frag;
    }

    function buildAiRegenerateContainer(enabled) {
      var container = doc.createElement('div');
      container.className = 'regenerate-container';

      var regen = doc.createElement('button');
      regen.className = 'regenerate-button';
      regen.type = 'button';
      if (!enabled) regen.disabled = true;
      var regenIcon = doc.createElement('i');
      regenIcon.className = 'bi bi-arrow-repeat';
      regen.appendChild(regenIcon);
      container.appendChild(regen);

      var play = doc.createElement('button');
      play.className = 'play-button';
      play.type = 'button';
      var playIcon = doc.createElement('i');
      playIcon.className = 'bi bi-play-fill';
      play.appendChild(playIcon);
      container.appendChild(play);

      return container;
    }

    function buildAiHistoryChildren(safeHtml) {
      var frag = buildAiLabelFragment();
      frag.appendChild(doc.createTextNode('\u00A0'));
      var textSpan = doc.createElement('span');
      textSpan.className = 'ai-message-text';
      if (typeof safeHtml === 'string' && safeHtml) {
        textSpan.innerHTML = createTrustedHtml(safeHtml);
      }
      frag.appendChild(textSpan);
      frag.appendChild(buildAiRegenerateContainer(true));
      return frag;
    }

    function buildAiErrorChildren(errorText) {
      var frag = buildAiLabelFragment();
      frag.appendChild(doc.createTextNode(' '));
      var errSpan = doc.createElement('span');
      errSpan.className = 'error-message';
      errSpan.textContent = 'Error: ' + String(errorText == null ? '' : errorText);
      frag.appendChild(errSpan);
      frag.appendChild(buildAiRegenerateContainer(true));
      return frag;
    }

    function buildAiStreamChildren() {
      var frag = buildAiLabelFragment();

      var thinking = doc.createElement('div');
      thinking.className = 'thinking-container';
      thinking.style.display = 'none';

      var toggle = doc.createElement('button');
      toggle.className = 'toggle-thinking';
      toggle.style.display = 'none';
      toggle.type = 'button';
      var caret = doc.createElement('i');
      caret.className = 'bi bi-caret-right-fill';
      toggle.appendChild(caret);
      toggle.appendChild(doc.createTextNode(' Show Thinking'));
      thinking.appendChild(toggle);

      var thinkingContent = doc.createElement('div');
      thinkingContent.className = 'thinking-content';
      thinkingContent.style.display = 'none';
      thinking.appendChild(thinkingContent);
      frag.appendChild(thinking);

      var textSpan = doc.createElement('span');
      textSpan.className = 'ai-message-text';
      textSpan.textContent = 'Thinking...';
      frag.appendChild(textSpan);
      frag.appendChild(buildAiRegenerateContainer(false));
      return frag;
    }

    function configureMarked() {
      var markedLib = getMarked();
      if (typeof markedLib === 'undefined') {
        if (typeof console !== 'undefined' && console.warn) console.warn('Marked library not found');
        return;
      }
      if (typeof console !== 'undefined' && console.debug) console.debug('Initializing marked with highlight.js');
      var renderer = new markedLib.Renderer();

      renderer.code = function (args) {
        var text;
        var lang;
        if (typeof args === 'object' && !Array.isArray(args)) {
          text = args.text;
          lang = args.lang;
        } else {
          text = arguments[0];
          lang = arguments[1];
        }

        var language = String(lang || 'plaintext').replace(/[^a-zA-Z0-9_+#.-]/g, '') || 'plaintext';
        var rawCode = decodeHTMLEntities(text);
        var highlighted;

        if (typeof console !== 'undefined' && console.debug) console.debug('Rendering code block:', { language: language, textLength: rawCode.length });

        var hljsLib = getHljs();
        if (typeof hljsLib !== 'undefined') {
          try {
            var langObj = hljsLib.getLanguage(language);
            if (langObj) {
              highlighted = hljsLib.highlight(rawCode, { language: language }).value;
              if (typeof console !== 'undefined' && console.debug) console.debug('Highlight.js success for:', language);
            } else {
              highlighted = hljsLib.highlightAuto(rawCode).value;
              if (typeof console !== 'undefined' && console.debug) console.debug('Highlight.js auto-highlighting used');
            }
          } catch (e) {
            if (typeof console !== 'undefined' && console.error) console.error('Highlight.js error:', e);
            highlighted = escapeHTML(rawCode);
          }
        } else {
          if (typeof console !== 'undefined' && console.warn) console.warn('Highlight.js (hljs) is not defined');
          highlighted = escapeHTML(rawCode);
        }

        return '<div class="code-block-container"><div class="code-block-header"><span>' + escapeHTML(language) + '</span><button class="copy-code-button" type="button" title="Copy to clipboard"><i class="bi bi-clipboard"></i></button></div><pre><code class="hljs language-' + escapeHTML(language) + '">' + highlighted + '</code></pre></div>';
      };

      markedLib.use({
        renderer: renderer,
        gfm: true,
        breaks: true
      });
      if (typeof console !== 'undefined' && console.debug) console.debug('Marked configured with custom renderer');
    }

    function renderMarkdown(text) {
      if (text == null) text = '';
      else text = String(text);
      var safe = escapeHTML(text);
      if (!isMarkdownEnabled()) {
        return safe.replace(/\n/g, '<br>');
      }
      var markedLib = getMarked();
      if (typeof markedLib !== 'undefined') {
        try {
          return markedLib.parse(safe);
        } catch (e) {
          if (typeof console !== 'undefined' && console.error) console.error('Markdown parsing error:', e);
          return safe.replace(/\n/g, '<br>');
        }
      }
      return safe.replace(/\n/g, '<br>');
    }

    function formatAiMessage(text) {
      if (!text) return '';

      var parts = getStreamDecoder().decodeComplete(text);
      var thinkingParts = [parts.thinking];
      var visibleParts = [parts.visible];

      var html = '';
      var fullThinking = thinkingParts.join('').trim();
      if (fullThinking) {
        html += '<div class="thinking-container" style="display:block;"><button class="toggle-thinking" style="display:inline-block;"><i class="bi bi-caret-right-fill"></i> Show Thinking</button><div class="thinking-content" style="display:none;">' + escapeHTML(fullThinking).replace(/\n/g, '<br>') + '</div></div>';
      }

      html += renderMarkdown(visibleParts.join(''));
      return html;
    }

    return {
      escapeHTML: escapeHTML,
      decodeHTMLEntities: decodeHTMLEntities,
      sanitizeDataImageSrc: sanitizeDataImageSrc,
      sanitizeLightboxSrc: sanitizeLightboxSrc,
      buildUserMessageSpan: buildUserMessageSpan,
      appendPlainTextWithBreaks: appendPlainTextWithBreaks,
      buildStatusMessageContent: buildStatusMessageContent,
      buildSetsLoadErrorContent: buildSetsLoadErrorContent,
      buildAiLabelFragment: buildAiLabelFragment,
      buildAiHistoryChildren: buildAiHistoryChildren,
      buildAiErrorChildren: buildAiErrorChildren,
      buildAiStreamChildren: buildAiStreamChildren,
      buildAiRegenerateContainer: buildAiRegenerateContainer,
      configureMarked: configureMarked,
      renderMarkdown: renderMarkdown,
      formatAiMessage: formatAiMessage
    };
  }

  return {
    escapeHTML: escapeHTML,
    decodeHTMLEntities: decodeHTMLEntities,
    sanitizeDataImageSrc: sanitizeDataImageSrc,
    createChatRenderer: createChatRenderer
  };
}));
