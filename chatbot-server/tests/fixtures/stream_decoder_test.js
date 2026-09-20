'use strict';
// Exercises static/stream-decoder.js through its public API with explicit
// literal expectations.
//
// Wire: <think>...</think> (or ...[BEGIN FINAL RESPONSE]) carries
// reasoning/status; [ConsoleError]...[/ConsoleError] carries console detail.
// Chat adapter strips console detail and flushes at EOF; regenerate adapter
// keeps markers visible and does not flush.
const assert = require('node:assert/strict');

const decoderPath = process.argv[2];
assert(decoderPath, 'usage: node stream_decoder_test.js <static/stream-decoder.js>');
const decoder = require(decoderPath);

function collect() {
  const visible = [];
  const thinking = [];
  const details = [];
  return {
    visible,
    thinking,
    details,
    sinks(strip) {
      return {
        stripConsoleDetail: strip,
        onVisible(s) { visible.push(s); },
        onThinking(s) { thinking.push(s); },
        onConsoleDetail(s) { details.push(s); }
      };
    },
    joined() {
      return { visible: visible.join(''), thinking: thinking.join('') };
    }
  };
}

function testCompleteProjectsHistory() {
  // Given a stored assistant turn with a think block,
  // when projected for history, then visible excludes thinking.
  const parts = decoder.decodeComplete('Hello <think>plan</think>world');
  assert.equal(parts.visible, 'Hello world');
  assert.equal(parts.thinking, 'plan');

  // Given the alternate close marker,
  // when projected, then it also terminates thinking.
  const alt = decoder.decodeComplete('Hello<think>secret[BEGIN FINAL RESPONSE]world');
  assert.equal(alt.visible, 'Helloworld');
  assert.equal(alt.thinking, 'secret');

  // Given an unclosed think block at end of stored text,
  // when projected, then the tail stays thinking, visible keeps the head.
  const open = decoder.decodeComplete('Answer <think>unclosed');
  assert.equal(open.visible, 'Answer ');
  assert.equal(open.thinking, 'unclosed');
}

function testIncrementalSplitAcrossThinkMarkers() {
  // Given think markers split across wire chunks,
  // when pushed incrementally with a final flush (chat adapter),
  // then the projection matches the whole-text projection.
  const c = collect();
  const state = decoder.createStreamState();
  decoder.pushChunk(state, 'Hello <th', c.sinks(false));
  assert.deepEqual(c.joined(), { visible: 'Hello ', thinking: '' });
  decoder.pushChunk(state, 'ink>plan</th', c.sinks(false));
  assert.deepEqual(c.joined(), { visible: 'Hello ', thinking: 'plan' });
  decoder.pushChunk(state, 'ink> world', c.sinks(false));
  decoder.flushRemainder(state, c.sinks(false));
  assert.deepEqual(c.joined(), { visible: 'Hello  world', thinking: 'plan' });

  const whole = decoder.decodeComplete('Hello <think>plan</think> world');
  assert.equal(c.joined().visible, whole.visible);
  assert.equal(c.joined().thinking, whole.thinking);
}

function testUnicodeAcrossChunks() {
  // Given emoji in visible and thinking text split across chunks,
  // when decoded, then characters survive intact and stay in their channel.
  const c = collect();
  const state = decoder.createStreamState();
  decoder.pushChunk(state, 'Hi 🌟 <think>bo', c.sinks(false));
  decoder.pushChunk(state, 't 🤖</think> bye 🌊', c.sinks(false));
  decoder.flushRemainder(state, c.sinks(false));
  assert.equal(c.joined().visible, 'Hi 🌟  bye 🌊');
  assert.equal(c.joined().thinking, 'bot 🤖');
}

function testChatStripsConsoleDetail() {
  // Given a provider error detail segment mid-stream,
  // when the chat adapter pushes it, then detail is reported once and
  // never appears in visible text.
  const c = collect();
  const state = decoder.createStreamState();
  decoder.pushChunk(state, 'part [ConsoleError]full chain[/ConsoleError] tail', c.sinks(true));
  decoder.flushRemainder(state, c.sinks(true));
  assert.deepEqual(c.details, ['full chain']);
  assert.equal(c.joined().visible, 'part  tail');
  assert.equal(c.joined().thinking, '');

  // Given an opening marker without its close in this chunk,
  // when pushed, then the markers are emitted as visible text: only complete
  // segments in the buffer are stripped. The later close does not retract
  // what was already emitted.
  const held = collect();
  const heldState = decoder.createStreamState();
  decoder.pushChunk(heldState, 'a [ConsoleError]partial', held.sinks(true));
  assert.deepEqual(held.details, []);
  assert.deepEqual(held.joined(), { visible: 'a [ConsoleError]partial', thinking: '' });
  decoder.pushChunk(heldState, ' chain[/ConsoleError] b', held.sinks(true));
  decoder.flushRemainder(heldState, held.sinks(true));
  assert.deepEqual(held.details, []);
  assert.equal(held.joined().visible, 'a [ConsoleError]partial chain[/ConsoleError] b');
}

function testRegenerateKeepsConsoleMarkersVisible() {
  // Given the regenerate adapter (no console stripping),
  // when the same error segment streams, then markers stay in visible text.
  const c = collect();
  const state = decoder.createStreamState();
  decoder.pushChunk(state, 'part [ConsoleError]full chain[/ConsoleError] tail', c.sinks(false));
  decoder.flushRemainder(state, c.sinks(false));
  assert.deepEqual(c.details, []);
  assert.equal(c.joined().visible, 'part [ConsoleError]full chain[/ConsoleError] tail');
}

function testEofFlushVersusDrop() {
  // Given a trailing partial tag held for the next chunk,
  // when the chat adapter flushes at EOF, then the hold is emitted as
  // visible text in the current state.
  const chat = collect();
  const chatState = decoder.createStreamState();
  decoder.pushChunk(chatState, 'Hello <th', chat.sinks(true));
  assert.equal(chat.joined().visible, 'Hello ');
  decoder.flushRemainder(chatState, chat.sinks(true));
  assert.equal(chat.joined().visible, 'Hello <th');

  // Given the same trailing hold,
  // when the regenerate adapter ends without flushing,
  // then the hold never reaches the message.
  const regen = collect();
  const regenState = decoder.createStreamState();
  decoder.pushChunk(regenState, 'Hello <th', regen.sinks(false));
  assert.equal(regen.joined().visible, 'Hello ');
  assert.equal(regenState.buffer, '<th');

  // Given an unclosed think block,
  // when flushed, then the tail is thinking; without flush it stays buffered.
  const thinkFlush = collect();
  const thinkState = decoder.createStreamState();
  decoder.pushChunk(thinkState, 'A<think>secret', thinkFlush.sinks(false));
  decoder.flushRemainder(thinkState, thinkFlush.sinks(false));
  assert.deepEqual(thinkFlush.joined(), { visible: 'A', thinking: 'secret' });

  const thinkDrop = collect();
  const thinkDropState = decoder.createStreamState();
  decoder.pushChunk(thinkDropState, 'A<think>secret', thinkDrop.sinks(false));
  assert.deepEqual(thinkDrop.joined(), { visible: 'A', thinking: 'secret' });
  assert.equal(thinkDropState.state, 'thinking');
}

function testMixedCallbackOrder() {
  // Given one chunk holding visible, thinking, and trailing visible text,
  // when pushed, then callbacks fire in wire order.
  const events = [];
  const state = decoder.createStreamState();
  decoder.pushChunk(state, 'a<think>b</think>c', {
    stripConsoleDetail: false,
    onVisible(s) { events.push(['visible', s]); },
    onThinking(s) { events.push(['thinking', s]); },
    onConsoleDetail() {}
  });
  decoder.flushRemainder(state, {
    onVisible(s) { events.push(['visible', s]); },
    onThinking(s) { events.push(['thinking', s]); }
  });
  assert.deepEqual(events, [['visible', 'a'], ['thinking', 'b'], ['visible', 'c']]);
}

const cases = [
  ['complete projects history', testCompleteProjectsHistory],
  ['incremental split across think markers', testIncrementalSplitAcrossThinkMarkers],
  ['mixed visible/thinking callback order', testMixedCallbackOrder],
  ['unicode across chunks', testUnicodeAcrossChunks],
  ['chat strips console detail', testChatStripsConsoleDetail],
  ['regenerate keeps console markers visible', testRegenerateKeepsConsoleMarkersVisible],
  ['eof flush versus drop', testEofFlushVersusDrop]
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
  console.error('stream decoder FAILED:\n' + failures.join('\n'));
  process.exitCode = 1;
} else {
  console.error('stream decoder: all scenarios project visible/thinking as contracted');
}
