'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2], 'utf8');
const conversationState = require(process.argv[3]);
assert(process.argv[3], 'usage: node native_tts_queue_test.js <static/chat.js> <static/conversation-state.js>');
const start = source.indexOf('  function playNativeVoiceModeTts(');
const end = source.indexOf('  window.playNativeVoiceModeTts =', start);
assert(start >= 0 && end > start, 'native TTS entry point must be available');

async function flush() {
  for (let i = 0; i < 40; i++) await Promise.resolve();
}

function session(sentences, generating = false, modern = true) {
  const posts = [];
  const enqueued = [];
  const cancelled = [];
  const state = { generating, sentences, ended: 0, listener: null, observer: null };
  const element = {
    0: {}, find() { return this; }, closest() { return this; }, last() { return this; },
    is() { return true; }, text() { return state.sentences.join(' '); },
    prop(name, value) { return value === undefined ? state.generating : this; },
    addClass() { return this; }, html() { return this; }
  };
  let timer = 0;
  // Generating state comes from the real conversation request tracker, the
  // single authority chat.js reads via chatRequests.isGenerating().
  const chatRequests = conversationState.createChatRequestTracker();
  if (generating) chatRequests.begin();
  const context = vm.createContext({
    console: { error() {} }, AbortController, Promise, Set, Map,
    setTimeout() { return ++timer; }, clearTimeout() {},
    $() { return element; }, chatRequests,
    CURRENT_AUDIO: null, CURRENT_AUDIO_BUTTON: null, nativeMicBridge: null,
    voiceSttAbortController: null, nativeVoiceTtsGeneration: 0,
    nativeVoiceTtsSessionPromise: null, nativeVoiceTtsSessionListener: null,
    voiceModeTtsSessionActive: false, voiceModeTtsPlaying: false,
    MAX_TTS_SENTENCE_RETRIES: 3, MAX_NATIVE_TTS_LOOKAHEAD: 4,
    sanitizeForTTS: text => text,
    getMessageTtsText: () => state.sentences.join(' '),
    splitSentences: () => state.sentences.map(text => ({ text })),
    sentenceEndsWithTerminator: text => /[.!?]$/.test(text),
    withCsrf: headers => headers,
    nativeVoiceTtsStreamUrl: token => 'https://chat/tts_stream/' + token,
    cancelNativeTtsToken: token => cancelled.push(token),
    sleepMs: () => Promise.resolve(),
    isRetryableVoiceStatus: status => status === 429 || status >= 500,
    stopCurrentDesktopTts() {}, resetPlayButtonUi() {}, clearMessageTtsPlayingUi() {},
    syncSendButtonState() {}, onVoiceModeTtsStarted() {},
    finishNativeVoiceTts() { state.ended++; },
    fetchVoiceRetry(url, options) {
      return new Promise((resolve, reject) => {
        posts.push({ text: JSON.parse(options.body).text, reject,
          resolve(token) { resolve({ headers: { get: () => token }, json: async () => ({ token }) }); }
        });
      });
    },
    MutationObserver: class {
      constructor(callback) { state.observer = callback; }
      observe() {} disconnect() { state.observer = null; }
    },
    window: { nativeVoiceTtsAvailable: true, voiceModeActive: true, NativeVoiceTts: {
      stop: async () => {},
      beginSession: async () => modern ? { generation: 1, maxQueuedClips: 4 } : { generation: 1 },
      addListener: async (name, listener) => { state.listener = listener; return { remove() {} }; },
      enqueue: async url => { enqueued.push(url.split('/').pop()); },
      markEndOfQueue: async () => { state.ended++; }
    } }
  });
  context.invalidateNativeVoiceTts = () => {
    context.nativeVoiceTtsGeneration++;
    context.nativeVoiceTtsSessionPromise = null;
  };
  vm.runInContext(source.slice(start, end), context);
  context.playNativeVoiceModeTts({}, generating ? {} : { sentences });
  return { posts, enqueued, cancelled, state, context,
    consume(token) { state.listener({ type: 'clipConsumed', generation: 1, url: 'https://chat/tts_stream/' + token }); }
  };
}

async function readyHeadDoesNotWaitForSlowTailAndWindowRefills() {
  const s = session(['One.', 'Two.', 'Three.', 'Four.', 'Five.', 'Six.']);
  await flush();
  assert.equal(s.posts.length, 4, 'only four sentences may get tokens ahead of playback');
  s.posts[1].resolve('two');
  await flush();
  assert.deepEqual(s.enqueued, [], 'out-of-order token must wait for first');
  s.posts[0].resolve('one');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two'], 'ready head must start without waiting for slow tail tokens');
  s.posts[2].resolve('three');
  s.posts[3].resolve('four');
  await flush();
  assert.equal(s.posts.length, 4, 'token responses alone must not expand the window');
  s.consume('one');
  s.consume('one');
  await flush();
  assert.equal(s.posts.length, 5, 'one consumed clip releases exactly one slot');
  assert.equal(s.state.ended, 0, 'unknown tail cannot mark end of queue');
  s.posts[4].resolve('five');
  s.consume('two');
  await flush();
  s.posts[5].resolve('six');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two', 'three', 'four', 'five', 'six']);
  assert.equal(s.state.ended, 1, 'end is marked after all URLs have been enqueued');
}

async function streamingTextFillsWindowWithoutWaitingForGenerationToEnd() {
  const s = session(['One.'], true);
  await flush();
  s.state.sentences = ['One.', 'Two.', 'Three.', 'unfinished'];
  s.state.observer();
  await flush();
  assert.deepEqual(s.posts.map(p => p.text), ['One.', 'Two.', 'Three.'],
    'completed streaming sentences overlap token requests while fragments wait');
  assert.equal(s.state.ended, 0, 'generation still active');
  s.context.CURRENT_AUDIO.stop();
}

async function failedHeadRetriesInOrderWithoutRepostingReadyTail() {
  const s = session(['One.', 'Two.']);
  await flush();
  s.posts[1].resolve('two');
  s.posts[0].reject(new Error('network lost'));
  await flush();
  assert.deepEqual(s.posts.map(p => p.text), ['One.', 'Two.', 'One.']);
  assert.deepEqual(s.enqueued, [], 'ready tail waits through head retry');
  s.posts[2].resolve('one');
  await flush();
  assert.deepEqual(s.enqueued, ['one', 'two'], 'retry plays each sentence once in order');
}

async function stopCancelsLateTokensWithoutEnqueueingThem() {
  const s = session(['One.', 'Two.']);
  await flush();
  s.context.CURRENT_AUDIO.stop();
  s.posts[0].resolve('late-one');
  s.posts[1].resolve('late-two');
  await flush();
  assert.deepEqual(s.enqueued, [], 'stopped session must not enqueue late tokens');
  assert(s.cancelled.includes('late-one') && s.cancelled.includes('late-two'), 'late tokens released');
}

async function olderApkDoesNotWaitForUnsupportedConsumptionEvents() {
  const s = session(['One.', 'Two.', 'Three.', 'Four.', 'Five.'], false, false);
  await flush();
  for (let i = 0; i < 5; i++) {
    assert(s.posts[i], 'old APK continues issuing tokens without clipConsumed');
    s.posts[i].resolve(String(i));
    await flush();
  }
  assert.equal(s.enqueued.length, 5);
  assert.equal(s.state.ended, 1);
}

(async () => {
  await readyHeadDoesNotWaitForSlowTailAndWindowRefills();
  await streamingTextFillsWindowWithoutWaitingForGenerationToEnd();
  await failedHeadRetriesInOrderWithoutRepostingReadyTail();
  await stopCancelsLateTokensWithoutEnqueueingThem();
  await olderApkDoesNotWaitForUnsupportedConsumptionEvents();
})().catch(error => { console.error(error); process.exitCode = 1; });
