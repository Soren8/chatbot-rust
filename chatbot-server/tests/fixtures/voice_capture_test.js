'use strict';
// Dual invariant on the SHIPPED native capture (static/voice-capture.js) with
// the SHIPPED thresholds (static/native-audio.js) and the REAL voice
// lifecycle owner: a cough and a short "hey" must record but never stop TTS;
// sustained noisy speech must stop TTS at real-speech confirm
// (REAL_SPEECH_MS), not at utterance start or end-of-speech. No simulation of
// the gate logic here — the assertions drive the actual class frame by frame.
// Deterministic synth below ports native_vad_speech_like.rs exactly.
const assert = require('node:assert/strict');

const capturePath = process.argv[2];
const nativeAudioPath = process.argv[3];
const lifecyclePath = process.argv[4];
assert(
  capturePath && nativeAudioPath && lifecyclePath,
  'usage: node voice_capture_test.js <static/voice-capture.js> <static/native-audio.js> <static/voice-lifecycle.js>'
);
const capture = require(capturePath);
require(nativeAudioPath);
const NativeAudio = globalThis.NativeAudio;
assert(NativeAudio && typeof NativeAudio.pcm16IsSpeechLike === 'function',
  'native-audio.js must set globalThis.NativeAudio');
const lifecycleMod = require(lifecyclePath);

const SR = 16000;
const FRAME = 320; // 20 ms @ 16 kHz
const FRAME_MS = 20;

function lcgWhite(i) {
  let bits = (Math.imul((i + 1) >>> 0, 747796405) + 2891336453) >>> 0;
  bits ^= bits >>> 16;
  bits >>>= 0;
  bits = Math.imul(bits, 2246822519) >>> 0;
  bits ^= bits >>> 13;
  bits >>>= 0;
  return (bits / 4294967295) * 2 - 1;
}

function sineFrame(freqHz, amp, n, sampleRate) {
  const out = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = Math.round(Math.sin(2 * Math.PI * freqHz * i / sampleRate) * amp);
  }
  return out;
}

function noisyVowel(freqHz, amp, n, sampleRate, noiseGain) {
  let lp = 0;
  const out = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    const s = Math.sin(2 * Math.PI * freqHz * i / sampleRate) * amp;
    lp = lp * 0.75 + lcgWhite(i + 99) * 0.25;
    out[i] = Math.max(-32768, Math.min(32767, Math.round(s + lp * noiseGain * 8000)));
  }
  return out;
}

function coughBurst(n, sampleRate) {
  let lp = 0;
  const out = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    if (i === 0) { out[i] = 25000; continue; }
    if (i === 1) { out[i] = -20000; continue; }
    const white = lcgWhite(i);
    lp = lp * 0.75 + white * 0.25;
    const t = i / sampleRate;
    const env = Math.exp(-t / 0.10);
    out[i] = Math.max(-32768, Math.min(32767, Math.round(lp * env * 16000)));
  }
  return out;
}

function framesOf(pcm, frameSize) {
  const frames = [];
  for (let i = 0; i + frameSize <= pcm.length; i += frameSize) {
    frames.push(pcm.slice(i, i + frameSize));
  }
  return frames;
}

function makeLifecycle(voiceModeActive) {
  const lifecycle = lifecycleMod.createVoiceLifecycle({
    now: () => Date.now(),
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => !!voiceModeActive,
    stopNativePlayback: () => {},
  });
  lifecycle.stopDesktopPlayback();
  if (voiceModeActive) lifecycle.beginDesktopPlayback({});
  return lifecycle;
}

function makeHost(lifecycle, hooks) {
  hooks = hooks || {};
  return {
    nativeAudio: NativeAudio,
    voiceLifecycle: lifecycle,
    now: () => Date.now(),
    log: () => {},
    report: () => {},
    reportThrottled: () => {},
    isVoiceModeActive: () => true,
    onBargeIn: hooks.onBargeIn || (() => {}),
    onUtteranceEnd: hooks.onUtteranceEnd || (() => {}),
    onUtteranceStartedAt: hooks.onUtteranceStartedAt || (() => {}),
    recorder: {
      ensurePermission: async () => {},
      start: async () => {},
      stop: async () => {},
      addListener: () => ({ remove() {} }),
    },
    registry: {
      isCurrent: () => true,
      getStopPromise: () => null,
      setStopPromise: () => {},
    },
  };
}

function feedAll(vad, frames) {
  for (const frame of frames) vad._onNativePcm(frame);
}

(async () => {
  const failures = [];
  const check = (name, fn) => {
    try { fn(); } catch (error) {
      failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
    }
  };
  const checkAsync = async (name, fn) => {
    try { await fn(); } catch (error) {
      failures.push(name + ': ' + (error && error.message ? error.message : String(error)));
    }
  };

  // Preconditions on the shipped classifiers (same bar as the Rust dual test:
  // duration+voicing must reject the cough, not the start gate).
  const cough = framesOf(coughBurst(FRAME * 16, SR), FRAME);
  check('cough body is speech-like (start gate reaches it)', () => {
    let body = 0;
    for (let f = 1; f < 9; f++) {
      if (NativeAudio.pcm16IsSpeechLike(cough[f])) body++;
    }
    assert(body >= 6, 'cough body speech-like ' + body + '/8');
  });
  check('cough rolling window is not voiced', () => {
    const win = NativeAudio.mergePcm16Chunks(cough.slice(1, 1 + 5));
    assert(!NativeAudio.pcm16IsVoicedSpeech(win), 'cough window must not look voiced');
  });

  const speech = noisyVowel(200.0, 1200, FRAME * 40, SR, 0.35);
  const speechFrames = framesOf(speech, FRAME);
  const hey = speechFrames.slice(0, 10);
  check('noisy table vowel frames are speech-like', () => {
    for (const frame of hey) assert(NativeAudio.pcm16IsSpeechLike(frame), 'hey frame must start recording');
  });
  check('noisy table vowel window is voiced', () => {
    const win = NativeAudio.mergePcm16Chunks(hey.slice(0, 5));
    assert(NativeAudio.pcm16IsVoicedSpeech(win), 'hey window must look voiced');
  });

  // Cough records but never barges in.
  check('cough records but never barges in', () => {
    const lifecycle = makeLifecycle(true);
    let barges = 0;
    const vad = new capture.NativeMicUtteranceVAD(
      makeHost(lifecycle, { onBargeIn: () => { barges++; } }), () => {});
    vad.isRecording = true;
    for (const frame of cough) {
      vad._onNativePcm(frame);
      assert.equal(barges, 0, 'cough must not barge in (likeMs=' + vad.speechLikeMs + ' voicedMs=' + vad.voicedMs + ')');
    }
    assert(vad.inSpeech, 'cough must still start recording');
  });

  // Short hey records but never barges in.
  check('short hey records but never barges in', () => {
    const lifecycle = makeLifecycle(true);
    let barges = 0;
    const vad = new capture.NativeMicUtteranceVAD(
      makeHost(lifecycle, { onBargeIn: () => { barges++; } }), () => {});
    vad.isRecording = true;
    feedAll(vad, hey);
    assert(vad.inSpeech, 'a short hey must still start recording');
    assert.equal(barges, 0, 'a short hey must not stop TTS (likeMs=' + vad.speechLikeMs + ' voicedMs=' + vad.voicedMs + ')');
  });

  // Sustained noisy speech barges in once, at real-speech confirm.
  check('sustained noisy speech barges in at confirm', () => {
    const lifecycle = makeLifecycle(true);
    let bargeAt = null;
    let barges = 0;
    const vad = new capture.NativeMicUtteranceVAD(
      makeHost(lifecycle, { onBargeIn: () => { barges++; } }), () => {});
    vad.isRecording = true;
    speechFrames.forEach((frame, i) => {
      vad._onNativePcm(frame);
      if (barges > 0 && bargeAt === null) bargeAt = (i + 1) * FRAME_MS;
    });
    assert(bargeAt !== null, 'sustained noisy speech must barge in');
    const realMs = NativeAudio.REAL_SPEECH_MS;
    assert(bargeAt >= realMs - 40 && bargeAt <= realMs + 120,
      'barge-in at ' + bargeAt + ' ms must be at real-speech confirm (~' + realMs + '), not start or end-of-speech');
    assert.equal(barges, 1, 'barge-in fires exactly once');
  });

  // Idle listen records without barging in.
  check('idle listen records without barging in', () => {
    const lifecycle = makeLifecycle(false);
    let barges = 0;
    const host = makeHost(lifecycle, { onBargeIn: () => { barges++; } });
    host.isVoiceModeActive = () => true;
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    vad.isRecording = true;
    feedAll(vad, hey);
    assert(vad.inSpeech && barges === 0, 'idle listen must record a short utterance without barging in');
  });

  // start() awaits the permission gate before touching the recorder.
  await checkAsync('start awaits permission before recorder start', async () => {
    const lifecycle = makeLifecycle(true);
    const calls = [];
    let current = null;
    const host = makeHost(lifecycle, {});
    host.recorder = {
      ensurePermission: async () => { calls.push('permission'); },
      start: async () => { calls.push('start'); },
      stop: async () => {},
      addListener: () => ({ remove() {} }),
    };
    host.registry = {
      isCurrent: (inst) => current === inst,
      getStopPromise: () => null,
      setStopPromise: () => {},
    };
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    current = vad;
    await vad.start();
    assert.deepEqual(calls, ['permission', 'start'], 'permission gate runs before recorder start: ' + JSON.stringify(calls));
  });

  // start() fails closed on deny without touching the recorder.
  await checkAsync('start fails closed on permission deny', async () => {
    const lifecycle = makeLifecycle(true);
    const calls = [];
    let current = null;
    const host = makeHost(lifecycle, {});
    host.recorder = {
      ensurePermission: async () => { calls.push('permission'); throw new Error('Microphone permission denied'); },
      start: async () => { calls.push('start'); },
      stop: async () => {},
      addListener: () => ({ remove() {} }),
    };
    host.registry = {
      isCurrent: (inst) => current === inst,
      getStopPromise: () => null,
      setStopPromise: () => {},
    };
    const vad = new capture.NativeMicUtteranceVAD(host, () => {});
    current = vad;
    await assert.rejects(() => vad.start(), /permission/i);
    assert.deepEqual(calls, ['permission'], 'denied permission must not reach recorder start');
  });

  // stop() of a stale bridge never stops the newer recorder.
  await checkAsync('stale bridge stop never stops the newer recorder', async () => {
    const lifecycle = makeLifecycle(true);
    const stops = [];
    let current = null;
    let stopPromise = null;
    const host = makeHost(lifecycle, {});
    host.recorder = {
      ensurePermission: async () => {},
      start: async () => {},
      stop: async () => { stops.push(1); },
      addListener: () => ({ remove() {} }),
    };
    host.registry = {
      isCurrent: (inst) => current === inst,
      getStopPromise: () => stopPromise,
      setStopPromise: (promise) => { stopPromise = promise; },
    };
    const older = new capture.NativeMicUtteranceVAD(host, () => {});
    older.isRecording = true;
    older.nativeListener = { remove() {} };
    const newer = new capture.NativeMicUtteranceVAD(host, () => {});
    newer.isRecording = true;
    newer.nativeListener = { remove() {} };
    current = newer;
    await older.stop();
    assert.equal(stops.length, 0, 'stale stop must not touch the newer recorder');
    await newer.stop();
    assert.equal(stops.length, 1, 'current stop still stops the recorder');
  });

  if (failures.length) {
    console.error('voice capture FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
    return;
  }
  console.error('voice capture: cough/hey record without barge-in, sustained speech barges in at confirm');
})().catch(error => { console.error(error); process.exitCode = 1; });
