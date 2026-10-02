'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const path = process.argv[2];
assert(path, 'usage: node native_audio_wav_test.js <static/native-audio.js>');
const context = vm.createContext({ Blob, console });
vm.runInContext(fs.readFileSync(path, 'utf8'), context, { filename: path });
const audio = context.NativeAudio;
assert(audio, 'native-audio.js must expose globalThis.NativeAudio');

function readText(view, offset, length) {
  return String.fromCharCode(...new Uint8Array(view.buffer, view.byteOffset + offset, length));
}
async function wavSamples(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assert.equal(readText(view, 0, 4), 'RIFF');
  assert.equal(view.getUint32(4, true), bytes.length - 8);
  assert.equal(readText(view, 8, 4), 'WAVE');
  assert.equal(readText(view, 12, 4), 'fmt ');
  assert.equal(view.getUint32(16, true), 16);
  assert.equal(view.getUint16(20, true), 1);
  assert.equal(view.getUint16(22, true), 1);
  assert.equal(view.getUint32(24, true), 16000);
  assert.equal(view.getUint32(28, true), 32000);
  assert.equal(view.getUint16(32, true), 2);
  assert.equal(view.getUint16(34, true), 16);
  assert.equal(readText(view, 36, 4), 'data');
  assert.equal(view.getUint32(40, true), bytes.length - 44);
  return Array.from({ length: (bytes.length - 44) / 2 }, (_, i) => view.getInt16(44 + i * 2, true));
}

(async () => {
  const samples = [0, 1000, -2500, 5000, -12000, 32767, -32768];
  const pcmWav = await wavSamples(audio.pcm16ToWavBlob(new Int16Array(samples), 16000));
  assert.deepEqual(pcmWav, samples, 'PCM16 samples must round-trip without amplitude clamping');
  assert.deepEqual(await wavSamples(audio.pcm16ToWavBlob(new Int16Array([1, 2, 3]), 16000)), [1, 2, 3]);

  const floatWav = await wavSamples(audio.float32ToWavBlob(new Float32Array([-1, 0, 1, -2, 2]), 16000));
  assert.deepEqual(floatWav, [-32768, 0, 32767, -32768, 32767], 'Float32 samples clamp to [-1, 1] and scale asymmetrically');

  const cases = [
    { rate: 16000, channels: 1, index: 8, header: [0xFF, 0xF1, 0x60, 0x40, 0x0D, 0x7F, 0xFC] },
  ];
  for (const { rate, channels, index, header } of cases) {
    const adts = Array.from(audio.createAdtsHeader(100, rate, channels));
    assert.equal((adts[2] >> 2) & 0x0F, index, 'sample-rate index for ' + rate + ' Hz');
    assert.deepEqual(adts, header);
  }

  assert.deepEqual(Array.from(audio.pcm16ToFloat32(new Int16Array([0, 32767, -32768]))), [0, 32767 / 32768, -1]);
  assert.deepEqual(Array.from(audio.mergePcm16Chunks([new Int16Array([1, 2]), new Int16Array([-3])])), [1, 2, -3]);
  console.log('PASS native-audio.js PCM16/Float32 WAV, sample conversion, chunk merge and ADTS');
})().catch(error => { console.error(error); process.exitCode = 1; });
