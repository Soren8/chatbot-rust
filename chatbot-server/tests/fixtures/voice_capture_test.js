'use strict';
// Drives the shipped native capture state machine using the same 20 ms PCM
// events and sparse 32 ms Silero metadata emitted by NativeMic.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const capture = require(process.argv[2]);
require(process.argv[3]);
const NativeAudio = globalThis.NativeAudio;
const lifecycleMod = require(process.argv[4]);
const vadGlobal = { ort: {}, console };
vadGlobal.self = vadGlobal;
vm.runInNewContext(fs.readFileSync(path.join(path.dirname(process.argv[2]), 'deps/vad/bundle.min.js'), 'utf8'), vadGlobal);
const vadBundle = vadGlobal.vad;

const FRAME_SAMPLES = 320;
const scoreCadence = [0, 32, 0, 32, 32];
let scoreCadenceIndex = 0;
function makeLifecycle(ttsActive) {
  const lifecycle = lifecycleMod.createVoiceLifecycle({
    now: () => Date.now(), createAudio: () => null,
    createAbortController: () => new AbortController(), revokeUrl: () => {},
    resetPlayButton: () => {}, clearMessageUi: () => {}, syncSendButton: () => {},
    isVoiceModeActive: () => true, stopNativePlayback: () => {},
  });
  lifecycle.stopDesktopPlayback();
  if (ttsActive) lifecycle.beginDesktopPlayback({});
  return lifecycle;
}
function makeHost(lifecycle, hooks) {
  hooks = hooks || {};
  return {
    nativeAudio: NativeAudio, voiceLifecycle: lifecycle,
    now: () => Date.now(), log: () => {}, report: () => {}, reportThrottled: () => {},
    isVoiceModeActive: () => true,
    // handleBargeIn stops TTS, ending the session the gate checks.
    onBargeIn: () => { lifecycle.stopDesktopPlayback(); if (hooks.onBargeIn) hooks.onBargeIn(); },
    onUtteranceEnd: hooks.onUtteranceEnd || (() => {}),
    onUtteranceStartedAt: hooks.onUtteranceStartedAt || (() => {}),
    recorder: {
      ensurePermission: async () => {}, start: async (options) => { hooks.startOptions = options; return { vadEnabled: true }; },
      stop: async () => { hooks.stops = (hooks.stops || 0) + 1; },
      addListener: (name, callback) => {
        hooks.listeners = hooks.listeners || {};
        hooks.listeners[name] = callback;
        return { remove() { delete hooks.listeners[name]; } };
      },
    },
    registry: {
      isCurrent: (inst) => hooks.current === inst,
      getStopPromise: () => hooks.stopPromise || null,
      setStopPromise: (promise) => { hooks.stopPromise = promise; },
    },
  };
}
function sendPacket(vad, durationMs, probability, amplitude) {
  vad._onNativePcm(new Int16Array(FRAME_SAMPLES).fill(amplitude || 0),
    durationMs ? probability : null, durationMs);
}
function feedFresh(vad, probability, count, amplitude) {
  for (let n = 0; n < count; n++) {
    let duration;
    do {
      duration = scoreCadence[scoreCadenceIndex++ % scoreCadence.length];
      sendPacket(vad, duration, probability, amplitude);
    } while (duration === 0);
  }
}
// Real vad-web FrameProcessor behind a fake MicVAD, dispatching events the way
// MicVAD.handleFrameProcessorEvent does.
async function desktopVad(tts, hooks) {
  hooks = hooks || {};
  const lifecycle = makeLifecycle(tts);
  const host = makeHost(lifecycle, hooks);
  let probability = 0;
  let options;
  let processor;
  host.vadLib = { MicVAD: { new: async (provided) => {
    options = Object.assign({}, vadBundle.getDefaultRealTimeVADOptions('v5'), provided);
    processor = new vadBundle.FrameProcessor(async () => ({ isSpeech: probability }), () => {}, options, 32);
    processor.resume();
    return processor;
  } } };
  host.isTtsActive = () => lifecycle.isTtsActive();
  host.onSpeechStart = hooks.onSpeechStart || (() => {});
  host.onSpeechEnd = hooks.onSpeechEnd || (() => {});
  await capture.createVAD(host, { id: 'desktop-regression' });
  const M = vadBundle.Message;
  const dispatch = (e) => {
    if (e.msg === M.FrameProcessed) options.onFrameProcessed(e.probs, e.frame);
    else if (e.msg === M.SpeechStart) options.onSpeechStart();
    else if (e.msg === M.SpeechRealStart) options.onSpeechRealStart();
    else if (e.msg === M.VADMisfire) options.onVADMisfire();
    else if (e.msg === M.SpeechEnd) options.onSpeechEnd(e.audio);
  };
  return {
    lifecycle,
    async feed(p, count) {
      probability = p;
      for (let i = 0; i < count; i++) await processor.process(new Float32Array(512).fill(0.01), dispatch);
    },
  };
}

function readyVad(tts, hooks) {
  hooks = hooks || {};
  const host = makeHost(makeLifecycle(tts), hooks);
  const vad = new capture.NativeMicUtteranceVAD(host, hooks && hooks.onError);
  hooks.current = vad;
  vad.isRecording = true;
  return { vad, host };
}

(async () => {
  const failures = [];
  const check = (name, fn) => { try { fn(); } catch (e) { failures.push(name + ': ' + e.message); } };
  const checkAsync = async (name, fn) => { try { await fn(); } catch (e) { failures.push(name + ': ' + e.message); } };

  check('loud confidence-negative coughs and background noise never start capture', () => {
    const { vad } = readyVad(false);
    feedFresh(vad, 0.05, 100, 24000); // 3.2 seconds of loud negative frames
    assert.equal(vad.inSpeech, false);
    assert.equal(vad.hasSpeechCapture(), false);
  });

  check('positive neural speech starts capture after 120 ms evidence', () => {
    const { vad } = readyVad(false);
    feedFresh(vad, 0.5, 3, 1000);
    assert.equal(vad.inSpeech, false, '96 ms must not pass the start gate');
    feedFresh(vad, 0.5, 1, 1000);
    assert.equal(vad.inSpeech, true, '128 ms fresh neural evidence starts capture');
    assert(vad.hasSpeechCapture(), 'pre-roll PCM is retained');
  });

  check('short hey records without stopping TTS', () => {
    let barges = 0;
    const { vad } = readyVad(true, { onBargeIn: () => { barges++; } });
    feedFresh(vad, 0.8, 6, 1800); // 192 ms
    assert.equal(vad.inSpeech, true);
    assert.equal(barges, 0);
  });

  check('confident speech stops TTS on four consecutive frames above 0.85, before silence', () => {
    let barges = 0;
    const { vad } = readyVad(true, { onBargeIn: () => { barges++; } });
    feedFresh(vad, 0.9, 3, 1300);
    assert.equal(barges, 0, 'three confident frames do not interrupt');
    feedFresh(vad, 0.9, 1, 1300);
    assert.equal(barges, 1, 'fourth consecutive confident frame interrupts');
    assert.equal(vad.inSpeech, true, 'barge-in occurs during capture, before end silence');
  });

  check('a two-second moderate-confidence cough never stops TTS', () => {
    let barges = 0;
    const { vad } = readyVad(true, { onBargeIn: () => { barges++; } });
    feedFresh(vad, 0.7, 62, 20000);
    assert.equal(barges, 0, 'duration alone must not interrupt; only confidence does');
  });

  check('idle listen records without barging in', () => {
    let barges = 0;
    const { vad } = readyVad(false, { onBargeIn: () => { barges++; } });
    feedFresh(vad, 0.7, 100, 1200); // sustained speech while no TTS session is active
    assert(vad.inSpeech, 'idle listen records speech');
    assert.equal(barges, 0, 'idle listen never interrupts');
  });

  check('cough and hey do not barge in; sustained speech does at confirmation', () => {
    let barges = 0;
    const cough = readyVad(true, { onBargeIn: () => { barges++; } }).vad;
    feedFresh(cough, 0.05, 24, 24000); // repeated loud cough/noise confidence negatives
    assert.equal(cough.inSpeech, false);
    assert.equal(barges, 0);

    const hey = readyVad(true, { onBargeIn: () => { barges++; } }).vad;
    feedFresh(hey, 0.8, 6, 1800); // 192 ms
    assert.equal(hey.inSpeech, true);
    assert.equal(barges, 0, 'short hey does not interrupt');

    const talk = readyVad(true, { onBargeIn: () => { barges++; } }).vad;
    feedFresh(talk, 0.9, 19, 1300);
    assert.equal(barges, 1, 'sustained speech interrupts exactly once');
    assert(talk.inSpeech, 'barge-in occurs before silence/end-of-utterance');
  });

  check('negative confidence ends a valid sentence after 1.5 seconds', () => {
    let ended = 0;
    const { vad } = readyVad(false, { onUtteranceEnd: () => { ended++; } });
    feedFresh(vad, 0.8, 16, 900); // 512 ms speech
    assert.equal(vad.inSpeech, true);
    feedFresh(vad, 0.05, 48, 18000);
    assert.equal(vad.inSpeech, false);
    assert.equal(ended, 1);
  });

  await checkAsync('voice-mode opts into native Silero and rejects an old APK response', async () => {
    const calls = [];
    const hooks = { current: null };
    const host = makeHost(makeLifecycle(false), hooks);
    host.recorder.start = async (options) => { calls.push(options); return { vadEnabled: true }; };
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    hooks.current = vad;
    await vad.start();
    assert.deepEqual(calls, [{ vad: true }]);
    await vad.stop();

    const oldHooks = { current: null };
    const oldHost = makeHost(makeLifecycle(false), oldHooks);
    oldHost.recorder.start = async () => ({ started: true });
    const oldVad = new capture.NativeMicUtteranceVAD(oldHost, () => {});
    oldHooks.current = oldVad;
    oldHost.registry.isCurrent = (inst) => inst === oldVad;
    await assert.rejects(() => oldVad.start(), /Native Silero VAD unavailable/);
    assert.equal(oldHooks.stops, 1, 'old plugin that started recording must be stopped');
  });

  await checkAsync('permission resolves before native Silero capture starts', async () => {
    const calls = [];
    const hooks = { current: null };
    const host = makeHost(makeLifecycle(false), hooks);
    host.recorder.ensurePermission = async () => { calls.push('permission'); };
    host.recorder.start = async (options) => { calls.push('start'); assert.deepEqual(options, { vad: true }); return { vadEnabled: true }; };
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    hooks.current = vad;
    await vad.start();
    assert.deepEqual(calls, ['permission', 'start']);
    await vad.stop();
  });

  await checkAsync('permission denial never starts native capture', async () => {
    const calls = [];
    const hooks = { current: null };
    const host = makeHost(makeLifecycle(false), hooks);
    host.recorder.ensurePermission = async () => { calls.push('permission'); throw new Error('Microphone permission denied'); };
    host.recorder.start = async () => { calls.push('start'); return { vadEnabled: true }; };
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    hooks.current = vad;
    await assert.rejects(() => vad.start(), /permission/i);
    assert.deepEqual(calls, ['permission']);
  });

  await checkAsync('desktop ordinary speech is captured with onset padding', async () => {
    const ended = [];
    const d = await desktopVad(false, { onSpeechEnd: (audio) => ended.push(audio) });
    await d.feed(0.1, 16);
    await d.feed(0.5, 100);
    await d.feed(0.8, 7);
    await d.feed(0, 50);
    assert.equal(ended.length, 1, 'sentence ends normally');
    assert(ended[0].length >= (11 + 107) * 512, 'onset padding and sentence audio are retained');
  });

  await checkAsync('desktop speech scoring between 0.25 and 0.3 is captured, not misfired', async () => {
    const ended = [];
    const d = await desktopVad(false, { onSpeechEnd: (audio) => ended.push(audio) });
    await d.feed(0.1, 16);
    for (let i = 0; i < 10; i++) {
      await d.feed(0.35, 1);
      await d.feed(0.28, 2);
    }
    await d.feed(0, 50);
    assert.equal(ended.length, 1, 'hysteresis keeps 960 ms of speech that only sometimes reaches 0.3');
    assert(ended[0].length >= 30 * 512);
  });

  await checkAsync('desktop short sound is rejected', async () => {
    const ended = [];
    const d = await desktopVad(false, { onSpeechEnd: (audio) => ended.push(audio) });
    await d.feed(0.1, 16);
    await d.feed(0.5, 7);
    await d.feed(0, 50);
    assert.equal(ended.length, 0, '224 ms sound is not submitted as speech');
  });

  await checkAsync('desktop barge-in uses the same confidence gate as native', async () => {
    let barges = 0;
    const cough = await desktopVad(true, { onBargeIn: () => { barges++; } });
    await cough.feed(0.7, 62);
    assert.equal(barges, 0, 'a two-second moderate-confidence cough never stops TTS');

    const talk = await desktopVad(true, { onBargeIn: () => { barges++; } });
    await talk.feed(0.9, 3);
    assert.equal(barges, 0);
    await talk.feed(0.9, 1);
    assert.equal(barges, 1, 'fourth consecutive confident frame interrupts');
  });

  await checkAsync('missing VAD metadata fails closed and stops capture despite an error callback', async () => {
    let errors = 0;
    const hooks = { onError: () => { errors++; } };
    const { vad } = readyVad(false, hooks);
    sendPacket(vad, undefined, undefined, 0);
    assert.equal(vad.isRecording, false);
    assert.equal(errors, 1);
    await hooks.stopPromise;
    assert.equal(hooks.stops, 1, 'native capture stops even when the callback only reports the error');
  });

  await checkAsync('stale bridge stop never stops the replacement recorder', async () => {
    const hooks = { stops: 0, current: null };
    const host = makeHost(makeLifecycle(true), hooks);
    const oldVad = new capture.NativeMicUtteranceVAD(host, () => {});
    const newVad = new capture.NativeMicUtteranceVAD(host, () => {});
    oldVad.isRecording = true;
    newVad.isRecording = true;
    hooks.current = newVad;
    await oldVad.stop();
    assert.equal(hooks.stops || 0, 0);
    await newVad.stop();
    assert.equal(hooks.stops, 1);
  });

  if (failures.length) {
    console.error('voice capture FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('voice capture: native Silero confidence, timing, fail-stop, and stale-session checks passed');
})().catch((e) => { console.error(e); process.exitCode = 1; });
