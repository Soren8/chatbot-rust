'use strict';
// Exercises static/voice-text.js through its public API with explicit
// literal expectations (stable import, no source slicing).
//
// Boundary: late voice fragments join onto the in-flight user turn,
// a quick follow-up amends that turn while a late one opens a new /chat,
// a caret offset resolves to its sentence, trailing fragments hold their
// extendable endings while generation continues, and raw markdown is
// normalized before synthesis. The amend window stays a chat-owned
// literal; the module takes it as an explicit parameter so desktop and
// native share one policy value.
const assert = require('node:assert/strict');

const voiceTextPath = process.argv[2];
assert(voiceTextPath, 'usage: node voice_text_boundary_test.js <static/voice-text.js>');
const voiceText = require(voiceTextPath);

function testJoinVoiceUtterances() {
  // Given two empty fragments,
  // when joined, then the result is empty.
  assert.equal(voiceText.joinVoiceUtterances('', ''), '');
  assert.equal(voiceText.joinVoiceUtterances(null, undefined), '');

  // Given one empty side,
  // when joined, then the other side survives trimmed.
  assert.equal(voiceText.joinVoiceUtterances('  Hello  ', ''), 'Hello');
  assert.equal(voiceText.joinVoiceUtterances('', '  World '), 'World');
  assert.equal(voiceText.joinVoiceUtterances(null, 'Hi'), 'Hi');
  assert.equal(voiceText.joinVoiceUtterances('Hi', undefined), 'Hi');

  // Given an identical or overlapping fragment,
  // when joined, then it is not repeated.
  assert.equal(voiceText.joinVoiceUtterances('Hello', 'Hello'), 'Hello');
  assert.equal(voiceText.joinVoiceUtterances('Hello world', 'world'), 'Hello world');
  assert.equal(voiceText.joinVoiceUtterances('Hello', 'Hello world'), 'Hello world');

  // Given a genuinely new fragment,
  // when joined, then it appends with one space, trimmed.
  assert.equal(voiceText.joinVoiceUtterances('Hello', 'world'), 'Hello world');
  assert.equal(voiceText.joinVoiceUtterances('  Hello ', ' world  '), 'Hello world');

  // Given a same-word different-case fragment,
  // when joined, then overlap is case-sensitive and both are kept.
  assert.equal(voiceText.joinVoiceUtterances('Hello', 'hello'), 'Hello hello');
}

function testShouldAmendLastVoiceTurn() {
  const WINDOW = 2000;

  // Given no state at all,
  // when evaluated, then there is nothing to amend.
  assert.equal(voiceText.shouldAmendLastVoiceTurn(null, WINDOW), false);
  assert.equal(voiceText.shouldAmendLastVoiceTurn(undefined, WINDOW), false);
  assert.equal(voiceText.shouldAmendLastVoiceTurn({}, WINDOW), false);

  // Given no saved user turn,
  // when evaluated during generation, then it still opens a new turn.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: false, generating: true, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 1500,
  }, WINDOW), false);

  // Given an idle reply (neither generating nor speaking),
  // when evaluated, then there is nothing in flight to amend.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: false, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 1500,
  }, WINDOW), false);

  // Given an in-flight reply on either channel within the window,
  // when evaluated, then the fragment amends the live turn.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: false, ttsActive: true,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 1500,
  }, WINDOW), true);
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 2500,
  }, WINDOW), true);

  // Given a follow-up starting exactly at the window edge,
  // when evaluated, then the edge still amends; one millisecond later opens a new turn.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 3000,
  }, WINDOW), true);
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 3001,
  }, WINDOW), false);

  // Given missing timestamps,
  // when evaluated, then it cannot be a continuation.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: true,
    lastSpeechEndedAt: 0, utteranceStartedAt: 1500,
  }, WINDOW), false);
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: true,
  }, WINDOW), false);

  // Given clock skew (start stamped before end),
  // when evaluated, then the negative gap is still within the window.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: false,
    lastSpeechEndedAt: 3000, utteranceStartedAt: 2500,
  }, WINDOW), true);

  // Given a narrower caller window,
  // when evaluated, then the caller's window decides, not a module constant.
  assert.equal(voiceText.shouldAmendLastVoiceTurn({
    lastUserExists: true, generating: true, ttsActive: false,
    lastSpeechEndedAt: 1000, utteranceStartedAt: 1500,
  }, 100), false);
}

function testSentenceIndexAtOffset() {
  // Given no sentences,
  // when resolved, then there is no index.
  assert.equal(voiceText.sentenceIndexAtOffset(null, 3), -1);
  assert.equal(voiceText.sentenceIndexAtOffset([], 0), -1);

  const sents = [
    { start: 0, end: 5, text: 'Hello' },
    { start: 6, end: 11, text: 'world' },
  ];

  // Given an offset inside the first sentence,
  // when resolved, then it is the first sentence.
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 0), 0);
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 4), 0);

  // Given an offset exactly on the boundary between sentences,
  // when resolved, then the caret sits between them and belongs to the next.
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 5), 1);

  // Given an offset inside or at the end of the last sentence,
  // when resolved, then it is the last sentence.
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 6), 1);
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 11), 1);

  // Given an offset past the end or before the start,
  // when resolved, then it clamps to the last or first sentence.
  assert.equal(voiceText.sentenceIndexAtOffset(sents, 100), 1);
  assert.equal(voiceText.sentenceIndexAtOffset(sents, -5), 0);

  // Given whitespace before the first sentence,
  // when resolved, then it is still the first sentence.
  const late = [{ start: 5, end: 9, text: 'late' }];
  assert.equal(voiceText.sentenceIndexAtOffset(late, 0), 0);
  assert.equal(voiceText.sentenceIndexAtOffset(late, 9), 0);
}

function testSentenceEndsWithTerminator() {
  // Given ordinary completed endings,
  // when checked, then they stream at once.
  assert.equal(voiceText.sentenceEndsWithTerminator('Hello world.'), true);
  assert.equal(voiceText.sentenceEndsWithTerminator('Really?!'), true);
  assert.equal(voiceText.sentenceEndsWithTerminator('Wait...'), true);
  assert.equal(voiceText.sentenceEndsWithTerminator('He said "Hi."'), true);
  assert.equal(voiceText.sentenceEndsWithTerminator('It costs approx. 50 bucks.'), true);

  // Given text without any terminator,
  // when checked, then it waits for more text.
  assert.equal(voiceText.sentenceEndsWithTerminator('Hello world'), false);
  assert.equal(voiceText.sentenceEndsWithTerminator(''), false);

  // Given a colon ending,
  // when checked, then it waits for its continuation.
  assert.equal(voiceText.sentenceEndsWithTerminator('Reminder:'), false);
  assert.equal(voiceText.sentenceEndsWithTerminator('Steps:'), false);

  // Given a digit period that may extend to a decimal,
  // when checked, then it waits for the continuation.
  assert.equal(voiceText.sentenceEndsWithTerminator('Version 4.'), false);

  // Given an all-caps initialism period that may merge with what follows,
  // when checked raw, then single capitals still stream (the queue-level
  // hold comes from the sanitized form: 'U.S.' at the end keeps its dot
  // as 'US.', which the initialism rule below does hold).
  assert.equal(voiceText.sentenceEndsWithTerminator('He visited the U.S.'), true);
  assert.equal(voiceText.sentenceEndsWithTerminator('He visited the US.'), false);

  // Given a known abbreviation or honorific period,
  // when checked, then it waits for the continuation.
  assert.equal(voiceText.sentenceEndsWithTerminator('See etc.'), false);
  assert.equal(voiceText.sentenceEndsWithTerminator('Visit St.'), false);
  assert.equal(voiceText.sentenceEndsWithTerminator('It costs approx.'), false);
  assert.equal(voiceText.sentenceEndsWithTerminator('See mr.'), false);
}

function testSplitSentences() {
  // Given empty text,
  // when split, then there are no sentences.
  assert.deepEqual(voiceText.splitSentences(''), []);
  assert.deepEqual(voiceText.splitSentences(null), []);

  // Given two plain sentences,
  // when split, then offsets cover both with the gap skipped.
  assert.deepEqual(voiceText.splitSentences('Hello world. Still going.'), [
    { start: 0, end: 12, text: 'Hello world.' },
    { start: 13, end: 25, text: 'Still going.' },
  ]);

  // Given a version number with digit periods,
  // when split, then the number stays inside one sentence.
  assert.deepEqual(voiceText.splitSentences('Version 4.6 is out.'), [
    { start: 0, end: 19, text: 'Version 4.6 is out.' },
  ]);

  // Given an ellipsis run,
  // when split, then it is one terminator, not three sentences.
  assert.deepEqual(voiceText.splitSentences('Hello... Next.'), [
    { start: 0, end: 8, text: 'Hello...' },
    { start: 9, end: 14, text: 'Next.' },
  ]);

  // Given a paragraph break,
  // when split, then each paragraph is its own sentence.
  assert.deepEqual(voiceText.splitSentences('Para one.\n\nPara two.'), [
    { start: 0, end: 9, text: 'Para one.' },
    { start: 11, end: 20, text: 'Para two.' },
  ]);

  // Given an honorific period,
  // when split, then the title stays attached to its sentence.
  assert.deepEqual(voiceText.splitSentences('Visit St. Louis today.'), [
    { start: 0, end: 22, text: 'Visit St. Louis today.' },
  ]);

  // Given a dotted initialism followed by lowercase text,
  // when split, then it does not terminate the sentence.
  assert.deepEqual(
    voiceText.splitSentences('He visited the U.S. economy is strong.').map(s => s.text),
    ['He visited the U.S. economy is strong.']
  );

  // Given a colon before a newline,
  // when split, then the label is its own sentence.
  assert.deepEqual(voiceText.splitSentences('Steps:\nDo this first.'), [
    { start: 0, end: 6, text: 'Steps:' },
    { start: 7, end: 21, text: 'Do this first.' },
  ]);
}

function testSanitizeForTTS() {
  // Given markdown emphasis, links, code and headings,
  // when sanitized, then speakable text survives without markers.
  assert.equal(voiceText.sanitizeForTTS('**Key point.** More detail.'), 'Key point. More detail.');
  assert.equal(voiceText.sanitizeForTTS('Hello **world**'), 'Hello world');
  assert.equal(voiceText.sanitizeForTTS('See [docs](https://example.com/x) now'), 'See docs now');
  assert.equal(voiceText.sanitizeForTTS('`code` here'), 'code here');
  assert.equal(voiceText.sanitizeForTTS('# Heading'), 'Heading');
  assert.equal(voiceText.sanitizeForTTS('> quote'), 'quote');
  assert.equal(voiceText.sanitizeForTTS('See https://example.com now'), 'See now');

  // Given currency forms,
  // when sanitized, then amounts are spoken out.
  assert.equal(voiceText.sanitizeForTTS('$12.50'), '12 dollars and 50 cents');
  assert.equal(voiceText.sanitizeForTTS('$5'), '5 dollars');
  assert.equal(voiceText.sanitizeForTTS('$0.50'), '50 cents');

  // Given abbreviations, titles and initialisms,
  // when sanitized, then they are expanded for speech.
  assert.equal(voiceText.sanitizeForTTS('Dr. Smith'), 'Doctor Smith');
  assert.equal(voiceText.sanitizeForTTS('e.g. apples'), 'for example apples');
  assert.equal(voiceText.sanitizeForTTS('See etc.'), 'See etcetera.');
  assert.equal(voiceText.sanitizeForTTS('Visit the U.S. today'), 'Visit the US today');

  // Given symbols and times,
  // when sanitized, then they are spoken out.
  assert.equal(voiceText.sanitizeForTTS('50%'), '50 percent');
  assert.equal(voiceText.sanitizeForTTS('a & b'), 'a and b');
  assert.equal(voiceText.sanitizeForTTS('10 A.M.'), '10 AM.');
  assert.equal(voiceText.sanitizeForTTS('It is 20°C'), 'It is 20 degrees Celsius');

  // Given text with nothing speakable,
  // when sanitized, then it is empty so the caller streams silence.
  assert.equal(voiceText.sanitizeForTTS('***'), '');
  assert.equal(voiceText.sanitizeForTTS('    '), '');
}

const cases = [
  ['join appends late fragments without repeating overlap', testJoinVoiceUtterances],
  ['amend only within the caller window of an in-flight turn', testShouldAmendLastVoiceTurn],
  ['caret offset resolves to its sentence with boundary clamping', testSentenceIndexAtOffset],
  ['terminator holds extendable endings while ordinary endings stream', testSentenceEndsWithTerminator],
  ['split keeps numbers, titles and breaks in one sentence each', testSplitSentences],
  ['sanitize strips markdown and expands speech forms', testSanitizeForTTS],
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
  console.error('voice text FAILED:\n' + failures.join('\n'));
  process.exitCode = 1;
} else {
  console.error('voice text: fragments join, follow-ups amend, offsets resolve, sentences hold, speech normalizes');
}
