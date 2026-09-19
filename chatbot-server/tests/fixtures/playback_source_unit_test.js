'use strict';
// Unit behavior for the shared explicit per-message playback source
// (static/playback-source.js): exact text projection and the per-message
// progress matrix, on the real unit with the real voice-text sanitizer and
// the real conversation request tracker. No DOM, no chat.
const assert = require('node:assert/strict');

const sourcePath = process.argv[2];
const voiceTextPath = process.argv[3];
const conversationStatePath = process.argv[4];
assert(
  sourcePath && voiceTextPath && conversationStatePath,
  'usage: node playback_source_unit_test.js <static/playback-source.js> <static/voice-text.js> <static/conversation-state.js>'
);
const playbackSource = require(sourcePath);
const voiceText = require(voiceTextPath);
const conversationState = require(conversationStatePath);

function project(original, fallback) {
  return playbackSource.projectSpeakableText(original, fallback, voiceText.sanitizeForTTS);
}

function checkProjection() {
  assert.equal(
    project('<think>reasoning here</think>Visible answer here.', ''),
    'Visible answer here.',
    'think block strips from the preferred original'
  );
  assert.equal(
    project('', 'Fallback visible here.'),
    'Fallback visible here.',
    'empty original falls back to visible text'
  );
  assert.equal(project('Thinking...', ''), '', 'Thinking... placeholder stays silent');
  assert.equal(project('', 'Thinking...'), '', 'visible placeholder stays silent');
  assert.equal(project('[Error] boom', ''), '', '[Error] text stays silent');
  assert.equal(project('Error: boom', ''), '', 'Error: text stays silent');
  assert.equal(
    project('Answer here.', 'Ignored fallback.'),
    'Answer here.',
    'preferred original wins over the fallback'
  );
  assert.equal(
    project('Answer here.', ''),
    'Answer here.',
    'stop suffix is not filtered by projection (the original simply never carries it)'
  );
  assert.equal(
    project('It costs approx. 50 bucks.', ''),
    'It costs approximately 50 bucks.',
    'projection sanitizes through the shared voice-text normalizer'
  );
}

function liveSource() {
  const chatRequests = conversationState.createChatRequestTracker();
  const seq = chatRequests.begin();
  const source = playbackSource.createMessageSource({
    sanitize: voiceText.sanitizeForTTS,
    isTrackerGenerating: () => chatRequests.isGenerating(),
    isTrackerLive: (s) => chatRequests.isLive(s),
    boundSeq: seq,
  });
  return { chatRequests, seq, source };
}

function checkProgress() {
  // Live-bound source reports generating while its request runs.
  {
    const { source } = liveSource();
    source.publish({ original: 'Hello world.', fallbackVisible: '' });
    assert.equal(source.isGenerating(), true, 'streaming message reports generating');
    assert.equal(source.getText(), 'Hello world.', 'live text projects');
  }
  // Explicit finish ends progress even while the tracker still runs.
  {
    const { source } = liveSource();
    source.publish({ original: 'Hello world.', fallbackVisible: '' });
    source.finish();
    assert.equal(source.isGenerating(), false, 'finished source stops progress');
    assert.equal(source.getText(), 'Hello world.', 'finished text still projects for draining');
  }
  // Settled tracker ends progress without an explicit finish.
  {
    const { chatRequests, seq, source } = liveSource();
    source.publish({ original: 'Hello world.', fallbackVisible: '' });
    chatRequests.finish(seq);
    assert.equal(source.isGenerating(), false, 'settled tracker stops progress');
  }
  // Historical message (never bound) never stalls on generation elsewhere.
  {
    const { source } = liveSource();
    const historical = playbackSource.createMessageSource({
      sanitize: voiceText.sanitizeForTTS,
      isTrackerGenerating: () => true,
      isTrackerLive: () => true,
      boundSeq: null,
    });
    historical.publish({ original: 'Older answer here.', fallbackVisible: '' });
    historical.finish();
    assert.equal(historical.isGenerating(), false, 'settled history stays idle while the tracker runs');
    assert.equal(historical.getText(), 'Older answer here.', 'historical text still projects');
    assert.equal(source.isGenerating(), true, 'live source unaffected by the settled one');
  }
  // Superseded sequence never reports generating.
  {
    const { chatRequests, source } = liveSource();
    source.publish({ original: 'Hello world.', fallbackVisible: '' });
    chatRequests.abortQuietly();
    assert.equal(source.isGenerating(), false, 'stale sequence stops progress');
  }
  // Regeneration restarts atomically: one notify carries the new sequence,
  // cleared text, and cleared finished flag.
  {
    const { chatRequests, seq, source } = liveSource();
    source.publish({ original: 'Old partial.', fallbackVisible: '' });
    const next = chatRequests.begin();
    assert.equal(next !== seq, true, 'precondition: replacement bumps the sequence');
    let calls = 0;
    const disconnect = source.subscribe(() => { calls++; });
    source.retarget(next, { original: '', fallbackVisible: '' });
    disconnect();
    assert.equal(calls, 1, 'retarget notifies exactly once');
    assert.equal(source.isGenerating(), true, 'migrated source follows the replacement request');
    assert.equal(source.getText(), '', 'reset text projects empty while streaming');
  }
  // Retarget also clears a previous terminal flag: regenerating settled
  // history restarts progress on the replacement sequence.
  {
    const { chatRequests, source } = liveSource();
    source.publish({ original: 'Old answer.', fallbackVisible: '' });
    source.finish();
    const next = chatRequests.begin();
    source.retarget(next, { original: '', fallbackVisible: '' });
    assert.equal(source.isGenerating(), true, 'retarget reopens progress after finish');
    assert.equal(source.getText(), '', 'retarget clears stale text');
  }
}

function checkSubscribe() {
  const { source } = liveSource();
  let calls = 0;
  const disconnect = source.subscribe(() => { calls++; });
  assert(disconnect, 'subscribe returns a disconnect function');
  source.publish({ original: 'One.' });
  assert.equal(calls, 1, 'text publishes notify subscribers');
  source.finish();
  assert.equal(calls, 2, 'finish notifies subscribers');
  disconnect();
  source.publish({ original: 'Two.' });
  assert.equal(calls, 2, 'disconnect stops notifications');
  assert.equal(source.getText(), 'Two.', 'text still updates after disconnect');
}

try {
  checkProjection();
  checkProgress();
  checkSubscribe();
  console.error('playback source unit: projection, progress and subscribe ok');
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
