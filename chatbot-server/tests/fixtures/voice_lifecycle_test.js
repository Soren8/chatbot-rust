'use strict';
// Behavior contract for static/voice-lifecycle.js: SINGLE owned voice
// lifecycle for desktop + native TTS (currentAudio/Button, desktop session,
// sessionActive/playing, bargeFrames, cooldown, native-generation stale
// guards). Completion/stopping go through the owner; chat.js keeps only thin
// adapters. No queue algorithm here.
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node voice_lifecycle_test.js <static/voice-lifecycle.js>');
const L = require(modPath);

assert.equal(L.TTS_LISTEN_COOLDOWN_MS, 400, 'cooldown stays 400 ms');
assert.equal(L.BARGE_IN_FRAMES_DESKTOP, 4, 'barge needs 4 high-confidence frames');
assert.equal(L.BARGE_IN_SPEECH_PROB, 0.85, 'barge speech prob stays 0.85');

function harness(opts) {
  opts = opts || {};
  let now = opts.now != null ? opts.now : 10000;
  let voiceMode = !!opts.voiceMode;
  const calls = { resetButtons: [], clears: 0, syncs: 0, nativeStops: 0, revoked: [] };
  const audio = {
    paused: false,
    src: '',
    dataset: {},
    onended: 'x', onerror: 'x', onloadeddata: 'x',
    pause() { this.paused = true; },
    removeAttribute() {},
  };
  const owner = L.createVoiceLifecycle({
    now: () => now,
    createAudio: () => audio,
    createAbortController: () => new AbortController(),
    revokeUrl: (url) => { calls.revoked.push(url); },
    resetPlayButton: (btn) => { calls.resetButtons.push(btn || null); },
    clearMessageUi: () => { calls.clears++; },
    syncSendButton: () => { calls.syncs++; },
    isVoiceModeActive: () => voiceMode,
    stopNativePlayback: () => { calls.nativeStops++; },
  });
  return {
    owner, calls, audio,
    setNow(v) { now = v; },
    setVoiceMode(v) { voiceMode = !!v; },
  };
}

// Stale desktop completion never touches the replacement playback.
{
  const h = harness({ voiceMode: true });
  const btnA = { id: 'A' };
  h.owner.stopDesktopPlayback();
  const sessA = h.owner.beginDesktopPlayback(btnA);
  assert.equal(h.owner.isLiveDesktop(sessA), true, 'new desktop play is live');
  assert.equal(h.owner.isTtsActive(), true, 'desktop session marks TTS active in voice mode');
  // Replacement play after a stop bumps the session.
  h.owner.stopDesktopPlayback();
  const btnB = { id: 'B' };
  const sessB = h.owner.beginDesktopPlayback(btnB);
  assert.notEqual(sessA, sessB, 'stop bumps the desktop session');
  assert.equal(h.owner.isLiveDesktop(sessA), false, 'stale session never validates');
  assert.equal(h.owner.isLiveDesktop(sessB), true, 'replacement stays live');
  assert.equal(h.owner.isCurrentButton(btnA), false, 'stale button is not current');
  assert.equal(h.owner.isCurrentButton(btnB), true, 'replacement button is current');
}

// Manual desktop stop ends the session and bumps so in-flight work goes stale.
{
  const h = harness({ voiceMode: true });
  const btn = { id: 'btn' };
  h.owner.stopDesktopPlayback();
  const sess = h.owner.beginDesktopPlayback(btn);
  assert.equal(h.owner.isTtsActive(), true);
  h.owner.stopDesktopPlayback();
  assert.equal(h.owner.isLiveDesktop(sess), false, 'stopped session is stale');
  assert.equal(h.owner.isTtsActive(), false, 'stop clears TTS active');
  assert.equal(h.owner.hasCurrentAudio(), false);
  assert.equal(h.calls.syncs >= 1, true, 'stop syncs the send button');
}

// Desktop complete arms the AEC cooldown only in voice mode.
{
  const voice = harness({ voiceMode: true, now: 5000 });
  voice.owner.stopDesktopPlayback();
  const sess = voice.owner.beginDesktopPlayback({ id: 'v' });
  assert.equal(voice.owner.isLiveDesktop(sess), true);
  voice.owner.completeDesktopPlayback(voice.owner.getCurrentButton());
  assert.equal(voice.owner.isTtsActive(), false, 'complete ends the session');
  assert.equal(voice.owner.isInCooldown(), true, 'voice-mode complete arms the listen cooldown');
  voice.setNow(5000 + 400 + 1);
  assert.equal(voice.owner.isInCooldown(), false, 'cooldown expires after 400 ms');

  const plain = harness({ voiceMode: false, now: 8000 });
  plain.owner.stopDesktopPlayback();
  plain.owner.beginDesktopPlayback({ id: 'p' });
  plain.owner.completeDesktopPlayback(plain.owner.getCurrentButton());
  assert.equal(plain.owner.isInCooldown(), false, 'plain click-to-play never arms the cooldown');
}

// stop-all without preserve arms; preserveListen clears for immediate barge-in.
{
  const h = harness({ voiceMode: true, now: 20000 });
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 's' });
  h.owner.stopAllPlayback();
  assert.equal(h.owner.isTtsActive(), false);
  assert.equal(h.owner.isInCooldown(), true, 'manual stop arms the cooldown');

  h.setNow(21000);
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 's2' });
  h.owner.stopAllPlayback({ preserveListen: true });
  assert.equal(h.owner.isInCooldown(), false, 'barge-in preserveListen clears the cooldown');
}

// Stale native finish stays silent; live finish ends and arms in voice mode.
{
  const h = harness({ voiceMode: true, now: 30000 });
  h.setVoiceMode(true);
  const btnA = { id: 'nA' };
  h.owner.invalidateNativeSession();
  const genA = h.owner.beginNativePlayback(btnA, () => {});
  assert.equal(h.owner.isLiveNativeGeneration(genA), true);
  assert.equal(h.owner.isTtsActive(), true, 'native begin marks TTS active');
  // Replacement invalidates the old generation.
  h.owner.invalidateNativeSession();
  const btnB = { id: 'nB' };
  const genB = h.owner.beginNativePlayback(btnB, () => {});
  assert.equal(h.owner.isLiveNativeGeneration(genA), false, 'old native generation is stale');
  const syncsBefore = h.calls.syncs;
  assert.equal(h.owner.finishNativePlayback(genA, btnA), false, 'stale finish reports not-live');
  assert.equal(h.owner.isLiveNativeGeneration(genB), true, 'stale finish never touches the replacement');
  assert.equal(h.owner.isCurrentButton(btnB), true);
  assert.equal(h.calls.syncs, syncsBefore, 'stale finish stays silent');
  assert.equal(h.owner.finishNativePlayback(genB, btnB), true, 'live finish reports live');
  assert.equal(h.owner.isTtsActive(), false, 'live finish ends the session');
  assert.equal(h.owner.isInCooldown(), true, 'voice-mode native finish arms the cooldown');
}

// Barge frames: three high-confidence frames wait; the fourth fires once.
{
  const h = harness({ voiceMode: true });
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 'b' });
  assert.equal(h.owner.noteFrameProcessed(0.9), false);
  assert.equal(h.owner.noteFrameProcessed(0.9), false);
  assert.equal(h.owner.noteFrameProcessed(0.9), false, 'three frames must not barge in');
  assert.equal(h.owner.noteFrameProcessed(0.9), true, 'fourth high-confidence frame barges in');
  assert.equal(h.owner.noteFrameProcessed(0.9), false, 'counter resets after firing');
  assert.equal(h.owner.noteFrameProcessed(0.1), false, 'low prob resets without firing');
  assert.equal(h.owner.noteFrameProcessed(0.9), false, 'needs four again after a reset');
}

// Idle frames never barge; low/silence resets the counter.
{
  const h = harness({ voiceMode: false });
  assert.equal(h.owner.noteFrameProcessed(0.99), false, 'idle TTS must not barge in');
  assert.deepEqual(h.owner.snapshot().bargeFrames, 0);
  h.setVoiceMode(true);
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 'i' });
  h.owner.noteFrameProcessed(0.9);
  h.owner.noteFrameProcessed(0.9);
  h.owner.noteFrameProcessed(0.1);
  assert.deepEqual(h.owner.snapshot().bargeFrames, 0, 'non-speech resets the gate');
}

// Desktop and native share one owner; independent owners share nothing.
{
  const h = harness({ voiceMode: true });
  h.owner.stopDesktopPlayback();
  const dsess = h.owner.beginDesktopPlayback({ id: 'd' });
  assert.equal(h.owner.isLiveDesktop(dsess), true);
  h.owner.invalidateNativeSession();
  const ngen = h.owner.beginNativePlayback({ id: 'n' }, () => {});
  assert.equal(h.owner.isLiveNativeGeneration(ngen), true, 'one owner drives both paths');
  assert.equal(h.owner.isTtsActive(), true);

  const a = harness({ voiceMode: true });
  const b = harness({ voiceMode: true });
  a.owner.stopDesktopPlayback();
  a.owner.beginDesktopPlayback({ id: 'only-a' });
  assert.equal(b.owner.isTtsActive(), false, 'owners are independent');
  assert.notDeepEqual(a.owner.snapshot().desktopSession, b.owner.snapshot().desktopSession);
}

// Preload/blob bookkeeping stays in the owner (no chat globals).
{
  const h = harness({});
  const p = Promise.resolve({ blobUrl: null, blob: {}, cleanUp() {} });
  h.owner.setPreload('1:hi', p);
  assert.equal(h.owner.hasPreload('1:hi'), true);
  assert.equal(h.owner.getPreload('1:hi'), p);
  h.owner.deletePreload('1:hi');
  assert.equal(h.owner.hasPreload('1:hi'), false);
  h.owner.adoptBlobUrl('blob:1');
  h.owner.adoptBlobUrl('blob:2');
  assert.deepEqual(h.calls.revoked, ['blob:1'], 'replacing the clip revokes the previous URL');
  h.owner.releaseBlobUrlIfCurrent('blob:2');
  assert.equal(h.owner.snapshot().currentBlobUrl, null);
}

// Flags-only session: plain click-to-play holds currentAudio but is not a
// voice session, so barge-in/utterance routing must stay off.
{
  const h = harness({ voiceMode: false });
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 'plain' });
  assert.equal(h.owner.isTtsActive(), true, 'plain play holds current audio');
  assert.equal(h.owner.hasActiveVoiceSession(), false, 'plain play is not a voice session');
  h.owner.notePlaybackStarted();
  assert.equal(h.owner.hasActiveVoiceSession(), true, 'playback start marks the voice session');
  h.owner.notePlaybackEnded();
  assert.equal(h.owner.hasActiveVoiceSession(), false, 'playback end clears the voice session');
}

// Desktop begin runs STT abort between the barge-frame reset and sessionActive.
{
  const h = harness({ voiceMode: true });
  h.owner.stopDesktopPlayback();
  h.owner.beginDesktopPlayback({ id: 'first' });
  h.owner.noteFrameProcessed(0.9);
  assert.equal(h.owner.snapshot().bargeFrames, 1);
  h.owner.stopDesktopPlayback();
  let atAbort = null;
  h.owner.beginDesktopPlayback({ id: 'second' }, function abortStt() {
    atAbort = h.owner.snapshot();
  });
  assert.deepEqual(atAbort && atAbort.bargeFrames, 0, 'barge frames reset before STT abort');
  assert.equal(atAbort && atAbort.sessionActive, false, 'STT abort runs before sessionActive');
  assert.equal(h.owner.snapshot().sessionActive, true, 'sessionActive set after STT abort');
}

// Native finish order: guard, onEnded, clear flags/UI, cleanup, cooldown, sync.
{
  const h = harness({ voiceMode: true, now: 40000 });
  h.owner.invalidateNativeSession();
  const gen = h.owner.beginNativePlayback({ id: 'n' }, () => {});
  const order = [];
  const live = h.owner.finishNativePlayback(gen, { id: 'n' }, {
    onEnded() { order.push('ended'); },
    cleanup() { order.push('cleanup'); },
  });
  assert.equal(live, true);
  assert.deepEqual(order, ['ended', 'cleanup'], 'onEnded runs before cleanup');
  assert.equal(h.calls.syncs >= 1, true, 'finish syncs');
  assert.equal(h.owner.isInCooldown(), true, 'voice-mode finish arms the cooldown');
  h.owner.invalidateNativeSession();
  assert.equal(h.owner.finishNativePlayback(gen, { id: 'n' }, {
    onEnded() { order.push('stale-ended'); },
    cleanup() { order.push('stale-cleanup'); },
  }), false, 'stale finish stays silent');
  assert.deepEqual(order, ['ended', 'cleanup'], 'stale finish runs no callbacks');
}

// Lifecycle errors propagate; the owner never swallows them.
{
  const throwing = L.createVoiceLifecycle({
    now: () => { throw new Error('clock gone'); },
    createAudio: () => { throw new Error('no audio'); },
    createAbortController: () => { throw new Error('no abort'); },
    revokeUrl: () => {},
    resetPlayButton: () => { throw new Error('reset gone'); },
    clearMessageUi: () => { throw new Error('clear gone'); },
    syncSendButton: () => { throw new Error('sync gone'); },
    isVoiceModeActive: () => { throw new Error('mode gone'); },
    stopNativePlayback: () => { throw new Error('native gone'); },
  });
  assert.throws(() => throwing.getDesktopAudio(), /no audio/);
  assert.throws(() => throwing.beginDesktopPlayback({}), /no abort/);
  assert.throws(() => throwing.isInCooldown(), /clock gone/);
  assert.throws(() => throwing.armListenCooldown(), /clock gone/);
  assert.throws(() => throwing.stopAllPlayback(), /clock gone/);
  const badNative = L.createVoiceLifecycle({
    now: () => 1000,
    createAudio: () => null,
    createAbortController: () => new AbortController(),
    revokeUrl: () => {},
    resetPlayButton: () => {},
    clearMessageUi: () => {},
    syncSendButton: () => {},
    isVoiceModeActive: () => false,
    stopNativePlayback: () => { throw new Error('native gone'); },
  });
  assert.throws(() => badNative.stopAllPlayback(), /native gone/);
}

console.error('voice-lifecycle: stale guards, cooldown, barge gates and owner isolation hold');
