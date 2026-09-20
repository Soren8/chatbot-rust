'use strict';
// Regression for CodeQL #70 js/incomplete-multi-character-sanitization:
// sanitizeForTTS must strip HTML tags completely so no tag fragment reaches
// the /tts JSON body (spoken text only, never an HTML sink).
//
// Boundary: a tag carrying a URL attribute must not survive because the URL
// strip runs after tag stripping and eats the tag's closing bracket, leaving
// a "<a href="" fragment. Nested tags must also leave no "<...>" behind.
// Plain tags, markdown links and empty markers keep their established
// speakable-text behavior.
const assert = require('node:assert/strict');

const voiceTextPath = process.argv[2];
assert(voiceTextPath, 'usage: node voice_text_sanitize_html_test.js <static/voice-text.js>');
const voiceText = require(voiceTextPath);

function testStripsPlainTagsPreservingWords() {
  // Given plain markup around speakable words,
  // when sanitized, then only the words are spoken.
  assert.equal(voiceText.sanitizeForTTS('Say <b>hi</b> now'), 'Say hi now');
  assert.equal(voiceText.sanitizeForTTS('<b><i>hi</i></b>'), 'hi');
}

function testStripsTagWithUrlAttributeCompletely() {
  // Given an anchor whose attribute holds a URL,
  // when sanitized, then no tag fragment survives (the URL strip must not
  // eat the closing bracket first) and the link text is spoken.
  assert.equal(voiceText.sanitizeForTTS('<a href="https://example.com/x">click</a>'), 'click');
  assert.equal(voiceText.sanitizeForTTS('Say <a href="https://example.com/x">click</a> now'), 'Say click now');
}

function testLeavesNoTagPatternOnNestedMarkup() {
  // Given plain nested markup,
  // when sanitized, then only the words are spoken.
  const out = voiceText.sanitizeForTTS('<div><span>nested</span></div>');
  assert.equal(out, 'nested');
  assert.match(out, /^[^<>]*$/);

  // Given nested markup carrying a URL attribute,
  // when sanitized, then no tag fragment survives and the link text is spoken.
  assert.equal(voiceText.sanitizeForTTS('Say <b><a href="https://example.com/x">click</a></b> now'), 'Say click now');
  assert.equal(voiceText.sanitizeForTTS('Outer <div><a href="https://example.com/y">link</a></div> end'), 'Outer link end');

  // Given a CodeQL-style nested-tag payload,
  // when sanitized, then no "<...>" tag re-forms; inert "ipt>" fragments
  // and speakable "alert(1)" remain.
  const crafted = voiceText.sanitizeForTTS('Say <scr<script>ipt>alert(1)</scr</script>ipt> now');
  assert.equal(crafted, 'Say ipt>alert(1)ipt> now');
  assert.ok(!/<[^>]+>/.test(crafted), 'no tag may re-form, got: ' + crafted);

  // Given three-level nested tags,
  // when sanitized, then no tag pattern remains and speech survives.
  const deep = voiceText.sanitizeForTTS('Say <scr<scr<script>ipt>ipt>ipt>alert(1)</scr</scr</script>ipt>ipt>ipt> now');
  assert.ok(!/<[^>]+>/.test(deep), 'no tag may re-form, got: ' + deep);
  assert.ok(deep.includes('alert(1)'), 'speakable text survives, got: ' + deep);
}

function testKeepsMarkdownLinkSemantics() {
  // Given an established markdown link and empty markers,
  // when sanitized, then link text survives and markers stay silent.
  assert.equal(voiceText.sanitizeForTTS('See [docs](https://example.com/x) now'), 'See docs now');
  assert.equal(voiceText.sanitizeForTTS('***'), '');
}

const cases = [
  ['plain tags strip leaving words', testStripsPlainTagsPreservingWords],
  ['tag with URL attribute strips completely', testStripsTagWithUrlAttributeCompletely],
  ['nested markup leaves no tag pattern', testLeavesNoTagPatternOnNestedMarkup],
  ['markdown links and markers keep semantics', testKeepsMarkdownLinkSemantics],
];

const failures = [];
for (const [name, fn] of cases) {
  try {
    fn();
  } catch (error) {
    failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
  }
}
if (failures.length) {
  console.error('voice-text html sanitize FAILED:\n' + failures.join('\n'));
  process.exitCode = 1;
} else {
  console.error('voice-text html sanitize: tags strip completely, links and markers keep semantics');
}
