'use strict';
// Security-protocol output of the REAL owned renderer
// (static/tts-playback.js is not involved; static/chat-renderer.js is
// required with a fake DOM leaf, the real stream decoder, and scripted
// markdown/highlighter/location deps).
//
// Protocol under test, not implementation shape:
// - untrusted text reaches the tree through text nodes only (no innerHTML
//   sink carries attacker text);
// - the single innerHTML sink (history bubble) receives only bytes that
//   passed through the injected Trusted-Types wrapper;
// - image sources are reconstructed allowlist URLs or rejected;
// - markdown input is escaped before parsing, never interpreted as markup.
const assert = require('node:assert/strict');

const rendererPath = process.argv[2];
const streamDecoderPath = process.argv[3];
assert(
  rendererPath && streamDecoderPath,
  'usage: node chat_renderer_test.js <static/chat-renderer.js> <static/stream-decoder.js>'
);
const Renderer = require(rendererPath);
const streamDecoder = require(streamDecoderPath);

function makeNode(tag) {
  return {
    tagName: tag,
    children: [],
    attributes: {},
    className: '',
    textContent: '',
    innerHTML: undefined,
    style: {},
    disabled: false,
    type: '',
    appendChild(child) { this.children.push(child); return child; },
    setAttribute(key, value) { this.attributes[key] = value; },
  };
}

function makeDoc() {
  return {
    createElement(tag) { return makeNode(tag); },
    createTextNode(text) { return { nodeType: 3, text: String(text) }; },
    createDocumentFragment() {
      return {
        isFragment: true,
        children: [],
        appendChild(child) { this.children.push(child); return child; },
      };
    },
  };
}

function collectTextNodes(node, acc) {
  acc = acc || [];
  if (node && node.nodeType === 3) acc.push(node.text);
  (node && node.children || []).forEach(child => collectTextNodes(child, acc));
  return acc;
}

function collectInnerHTML(node, acc) {
  acc = acc || [];
  if (node && typeof node.innerHTML === 'string') acc.push(node.innerHTML);
  (node && node.children || []).forEach(child => collectInnerHTML(child, acc));
  return acc;
}

function findAll(node, pred, acc) {
  acc = acc || [];
  if (pred(node)) acc.push(node);
  (node && node.children || []).forEach(child => findAll(child, pred, acc));
  return acc;
}

function makeRenderer(overrides) {
  overrides = overrides || {};
  const trusted = [];
  // Parser/highlighter globals arrive per call through getters over this
  // mutable cell, so late binding (scripts arriving after page wiring) wins
  // exactly like the page, where globals are read at each render.
  const libs = {
    marked: overrides.hasOwnProperty('marked') ? overrides.marked : undefined,
    hljs: overrides.hasOwnProperty('hljs') ? overrides.hljs : undefined,
  };
  const renderer = Renderer.createChatRenderer({
    document: overrides.document || makeDoc(),
    getMarked: () => libs.marked,
    getHljs: () => libs.hljs,
    createTrustedHtml: (html) => { trusted.push(html); return 'TRUSTED:' + html; },
    isMarkdownEnabled: overrides.isMarkdownEnabled || (() => true),
    getLocation: overrides.getLocation || (() => ({ href: 'https://chat/', origin: 'https://chat' })),
    // The page getter is a bare `ChatStreamDecoder` reference, so a missing
    // stream-decoder script surfaces ReferenceError from the getter itself.
    getStreamDecoder: overrides.getStreamDecoder || (() => streamDecoder),
  });
  return { renderer, trusted, libs };
}

(async () => {
  const failures = [];
  const check = (name, fn) => {
    try { fn(); } catch (error) {
      failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
    }
  };

  check('escapeHTML neutralizes markup before any sink', () => {
    assert.equal(
      Renderer.escapeHTML('<script>alert(1)</script>'),
      '&lt;script&gt;alert(1)&lt;/script&gt;');
    assert.equal(
      Renderer.decodeHTMLEntities(Renderer.escapeHTML('a<b>"c"\'d\'&e')),
      'a<b>"c"\'d\'&e');
  });

  check('renderMarkdown without marked falls back to escaped line breaks', () => {
    const { renderer } = makeRenderer({});
    assert.equal(renderer.renderMarkdown('<b>hi</b>\nnext'), '&lt;b&gt;hi&lt;/b&gt;<br>next');
  });

  check('renderMarkdown off renders no markdown', () => {
    const { renderer } = makeRenderer({ isMarkdownEnabled: () => false });
    assert.equal(renderer.renderMarkdown('**bold**'), '**bold**');
  });

  check('renderMarkdown delegates escaped input to the injected parser', () => {
    const seen = [];
    const { renderer } = makeRenderer({ marked: { parse: (safe) => { seen.push(safe); return 'PARSED'; } } });
    assert.equal(renderer.renderMarkdown('<i>x</i>'), 'PARSED');
    assert.deepEqual(seen, ['&lt;i&gt;x&lt;/i&gt;'], 'parser must receive escaped text, never raw markup');
  });

  check('sanitizeDataImageSrc allowlists data images only', () => {
    assert.equal(Renderer.sanitizeDataImageSrc('javascript:alert(1)'), null);
    assert.equal(Renderer.sanitizeDataImageSrc('data:text/html;base64,xx'), null);
    assert.equal(Renderer.sanitizeDataImageSrc('data:image/png;base64,aGk!!!'), null);
    assert.equal(
      Renderer.sanitizeDataImageSrc('data:image/png;base64,aGk='),
      'data:image/png;base64,aGk=');
    assert.equal(Renderer.sanitizeDataImageSrc(null), null);
  });

  check('SVG image sources are rejected by preview and lightbox rendering', () => {
    const { renderer } = makeRenderer({});
    const svg = 'data:image/svg+xml;base64,PHN2Zy8+';
    assert.equal(Renderer.sanitizeDataImageSrc(svg), null);
    assert.equal(Renderer.sanitizeDataImageSrc('data:image/SVG+XML;base64,PHN2Zy8+'), null);
    assert.equal(renderer.sanitizeLightboxSrc(svg), null);
    assert.deepEqual(findAll(renderer.buildUserMessageSpan('caption', svg, {}), node => node.tagName === 'img'), []);
  });

  check('user text reaches the tree as text, never markup', () => {
    const { renderer } = makeRenderer({});
    const evil = 'Hello <img src=x onerror=alert(1)>';
    const span = renderer.buildUserMessageSpan(evil, null, {});
    assert.deepEqual(collectInnerHTML(span), [], 'no innerHTML sink may carry user text');
    assert(collectTextNodes(span).join('').includes(evil), 'raw text survives verbatim as text nodes');
    assert.deepEqual(findAll(span, node => node.tagName === 'img'), [], 'no image without a source');
  });

  check('user image uses the reconstructed allowlist URL', () => {
    const { renderer } = makeRenderer({});
    const src = 'data:image/png;base64,aGk=';
    const deferred = renderer.buildUserMessageSpan('hi', src, { pairIndex: 3, thumbnail: true, deferSrc: true });
    const imgs = findAll(deferred, node => node.tagName === 'img');
    assert.equal(imgs.length, 1);
    assert.equal(imgs[0].attributes['data-pending-src'], src);
    assert(!('src' in imgs[0].attributes), 'deferred thumbnails must not set src eagerly');
    assert.equal(imgs[0].attributes['data-pair-index'], '3');
    const direct = renderer.buildUserMessageSpan('hi', src, {});
    assert.equal(findAll(direct, node => node.tagName === 'img')[0].attributes.src, src);
    const evil = renderer.buildUserMessageSpan('hi', 'javascript:alert(1)', {});
    assert.deepEqual(findAll(evil, node => node.tagName === 'img'), [], 'unsafe sources attach no image');
  });

  check('error chrome carries exception text as text with an enabled regenerate', () => {
    const { renderer } = makeRenderer({});
    const evil = 'boom <script>alert(1)</script>';
    const frag = renderer.buildAiErrorChildren(evil);
    assert.deepEqual(collectInnerHTML(frag), [], 'exception text must never reach innerHTML');
    const errors = findAll(frag, node => node.className === 'error-message');
    assert.equal(errors.length, 1);
    assert.equal(errors[0].textContent, 'Error: ' + evil);
    const regen = findAll(frag, node => node.className === 'regenerate-container');
    assert.equal(regen.length, 1);
    assert.equal(findAll(regen[0], node => node.tagName === 'button').length, 2);
  });

  check('history chrome sends only wrapped bytes to the single innerHTML sink', () => {
    const made = makeRenderer({});
    const frag = made.renderer.buildAiHistoryChildren('<b>hi</b>');
    assert.deepEqual(made.trusted, ['<b>hi</b>'], 'history HTML must pass the Trusted-Types wrapper');
    assert.deepEqual(collectInnerHTML(frag), ['TRUSTED:<b>hi</b>']);
  });

  check('status chrome labels errors and keeps text off innerHTML', () => {
    const { renderer } = makeRenderer({});
    const frag = renderer.buildStatusMessageContent('x error-message y', 'a<br>b');
    assert.deepEqual(collectInnerHTML(frag), []);
    assert(collectTextNodes(frag).join('').includes('a<br>b'));
    const labels = findAll(frag, node => node.tagName === 'strong');
    assert.equal(labels.length, 1);
    assert.equal(labels[0].textContent, 'Error:');
    const sys = renderer.buildStatusMessageContent('system-message', 'ok');
    assert.equal(findAll(sys, node => node.tagName === 'strong')[0].textContent, 'System:');
  });

  check('regenerate container honors the enabled flag', () => {
    const { renderer } = makeRenderer({});
    const on = renderer.buildAiRegenerateContainer(true);
    const off = renderer.buildAiRegenerateContainer(false);
    assert.equal(findAll(on, node => node.tagName === 'button').length, 2);
    assert.equal(findAll(off, node => node.tagName === 'button')[0].disabled, true);
  });

  check('lightbox sources stay same-origin allowlist paths', () => {
    const { renderer } = makeRenderer({});
    assert.equal(
      renderer.sanitizeLightboxSrc('/history_image/abc/1/2/3'),
      '/history_image/abc/1/2/3');
    assert.equal(
      renderer.sanitizeLightboxSrc('/history_image/abc/1/2/3?size=thumb'),
      '/history_image/abc/1/2/3?size=thumb');
    assert.equal(renderer.sanitizeLightboxSrc('/history_image/abc/1/2/3?size=evil'), null);
    assert.equal(renderer.sanitizeLightboxSrc('https://evil.example/history_image/abc/1/2/3'), null);
    assert.equal(
      renderer.sanitizeLightboxSrc('data:image/png;base64,aGk='),
      'data:image/png;base64,aGk=');
  });

  check('formatAiMessage escapes thinking and visible text via the real decoder', () => {
    const { renderer } = makeRenderer({});
    const out = renderer.formatAiMessage('<think>plan <b>x</b></think>Hello <script>y</script>');
    assert(!out.includes('<script>'), 'no raw markup may survive: ' + out);
    assert(out.includes('&lt;script&gt;'), 'visible text is escaped');
    assert(out.includes('&lt;b&gt;x&lt;/b&gt;'), 'thinking text is escaped');
    assert.equal(renderer.formatAiMessage(''), '');
  });

  check('configureMarked without marked warns instead of throwing', () => {
    const { renderer } = makeRenderer({});
    assert.doesNotThrow(() => renderer.configureMarked());
  });

  check('missing stream decoder surfaces ReferenceError from the getter', () => {
    const { renderer } = makeRenderer({
      getStreamDecoder: () => { return missingStreamDecoderForTest; },
    });
    assert.throws(() => renderer.formatAiMessage('hello'), ReferenceError);
  });

  check('markdown parser binds late: scripts arriving after wiring still win', () => {
    const made = makeRenderer({});
    assert.equal(made.renderer.renderMarkdown('hi'), 'hi', 'no parser yet: escaped fallback');
    made.libs.marked = { parse: (safe) => 'LATE:' + safe };
    assert.equal(made.renderer.renderMarkdown('hi'), 'LATE:hi', 'late parser applies per call');
    made.libs.marked = undefined;
    assert.equal(made.renderer.renderMarkdown('hi'), 'hi', 'unloaded parser falls back again');
  });

  check('renderMarkdown fallback and toggle touch no DOM', () => {
    let docCalls = 0;
    const doc = makeDoc();
    ['createElement', 'createTextNode', 'createDocumentFragment'].forEach((key) => {
      const orig = doc[key];
      doc[key] = function () { docCalls++; return orig.apply(doc, arguments); };
    });
    const fallback = makeRenderer({ document: doc });
    assert.equal(fallback.renderer.renderMarkdown('a\nb'), 'a<br>b');
    const toggled = makeRenderer({
      document: doc,
      isMarkdownEnabled: () => false,
      marked: { parse: () => { throw new Error('parser must not run when toggled off'); } },
    });
    assert.equal(toggled.renderer.renderMarkdown('**x**'), '**x**', 'toggle wins over a present parser');
    assert.equal(docCalls, 0, 'pure text paths must not read the DOM');
  });

  check('code fences read the highlighter per fence, not at configure', () => {
    let installed = null;
    const fakeMarked = {
      Renderer: function () {},
      use: function (opts) { installed = opts.renderer; },
      parse: function (safe) { return safe; },
    };
    const made = makeRenderer({ marked: fakeMarked });
    made.renderer.configureMarked();
    assert(installed && typeof installed.code === 'function', 'configure installs the fence renderer');
    const fence = (text, lang) => installed.code({ text, lang });
    const plain = fence('a&lt;b', 'js');
    assert(plain.includes('&lt;'), 'no highlighter yet: fence escapes, got: ' + plain);
    made.libs.hljs = {
      getLanguage: () => ({ name: 'js' }),
      highlight: (code) => ({ value: 'HL:' + code }),
    };
    const lit = fence('a&lt;b', 'js');
    assert(lit.includes('HL:a<b'), 'late highlighter applies per fence, got: ' + lit);
  });

  // Streaming re-renders the whole reply every frame. A closed fence must be
  // highlighted once (unknown languages fall back to highlightAuto, which
  // tries every grammar); only the trailing open fence re-highlights. No
  // per-block console.debug. Output stays byte-identical to an uncached run.
  check('streaming highlights a closed fence once and logs nothing per block', () => {
    const makeStubHljs = (stats) => ({
      getLanguage: (lang) => (lang === 'js' ? { name: 'js' } : null),
      highlight: (code) => { stats.highlightChars += code.length; return { value: 'HL:' + Renderer.escapeHTML(code) }; },
      highlightAuto: (code) => { stats.autoChars += code.length; return { value: 'AUTO:' + Renderer.escapeHTML(code) }; },
    });
    const install = (hljs) => {
      let installed = null;
      const made = makeRenderer({
        marked: { Renderer: function () {}, use: (opts) => { installed = opts.renderer; }, parse: (s) => s },
        hljs,
      });
      made.renderer.configureMarked();
      return (tok) => installed.code(tok);
    };
    const closedCode = Array.from({ length: 64 }, (_, i) => 'line ' + i + ' = value_' + i + ';').join('\n').padEnd(2048, 'x');
    const closedRaw = '```\n' + closedCode + '\n```';
    const tail = 'const growing = 1;\nconsole.log(growing);';
    const K = 30;
    const frames = [];
    for (let k = 1; k <= K; k++) {
      const openText = tail.slice(0, Math.ceil(tail.length * k / K));
      frames.push([
        { text: closedCode, lang: '', raw: closedRaw },
        { text: openText, lang: 'js', raw: '```js\n' + openText },
      ]);
    }

    const stats = { highlightChars: 0, autoChars: 0 };
    const code = install(makeStubHljs(stats));
    let debugs = 0;
    const origDebug = console.debug;
    console.debug = function () { debugs++; };
    const out = [];
    try {
      frames.forEach((frame) => out.push(frame.map((tok) => code(tok)).join('')));
    } finally {
      console.debug = origDebug;
    }

    const expectedOpenChars = frames.reduce((n, frame) => n + frame[1].text.length, 0);
    assert.equal(stats.autoChars, closedCode.length,
      'closed unlabeled fence must hit highlightAuto once across ' + K + ' frames, got chars=' + stats.autoChars);
    assert.equal(stats.highlightChars, expectedOpenChars,
      'the open fence still re-highlights every frame, got chars=' + stats.highlightChars);
    assert.equal(debugs, 0, 'no per-block console.debug while rendering, got ' + debugs);

    frames.forEach((frame, i) => {
      const fresh = install(makeStubHljs({ highlightChars: 0, autoChars: 0 }));
      assert.equal(out[i], frame.map((tok) => fresh(tok)).join(''), 'frame ' + i + ' must match an uncached render');
    });

    const reconfigured = { highlightChars: 0, autoChars: 0 };
    const reHl = makeStubHljs(reconfigured);
    let installedAgain = null;
    const made = makeRenderer({
      marked: { Renderer: function () {}, use: (opts) => { installedAgain = opts.renderer; }, parse: (s) => s },
      hljs: makeStubHljs(stats),
    });
    made.renderer.configureMarked();
    installedAgain.code(frames[0][0]);
    made.libs.hljs = reHl;
    const relit = installedAgain.code(frames[0][0]);
    assert.equal(reconfigured.autoChars, closedCode.length, 'a replaced highlighter must not serve the old cache');
    assert(relit.includes('AUTO:'), 'replaced highlighter output applies, got: ' + relit.slice(0, 80));
    made.libs.hljs = undefined;
    const plain = installedAgain.code(frames[0][0]);
    assert(!plain.includes('AUTO:'), 'an unloaded highlighter falls back to escaped text, not the cache');
  });

  if (failures.length) {
    console.error('chat renderer FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('chat renderer: untrusted text stays text, history HTML stays wrapped, sources stay allowlisted');
})().catch(error => { console.error(error); process.exitCode = 1; });
