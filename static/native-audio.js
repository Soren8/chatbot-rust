/**
 * Native (Capacitor) microphone audio helpers — PCM16 @ 16 kHz for Parakeet STT.
 * Loaded before chat.js; exposes window.NativeAudio.
 */
(function (global) {
  'use strict';

  const NATIVE_MIC_SAMPLE_RATE = 16000;
  /** Minimum buffered audio before starting Silero VAD (avoids initial underruns). */
  const VAD_PREFETCH_SAMPLES = 4800; // 300 ms @ 16 kHz
  /** Short pre-roll for native RMS VAD (Silero used more; 600 ms caused noise false positives). */
  const SPEECH_PREROLL_SAMPLES = 1600; // 100 ms @ 16 kHz
  /** RMS barge-in during TTS — matches Android Auto VoiceScreen. */
  const BARGE_IN_RMS_THRESHOLD = 800;
  const BARGE_IN_RMS_FRAMES = 3; // ~60 ms at 20 ms native frames
  /** Stricter threshold for starting an STT utterance (impacts exceed this less often). */
  const SPEECH_RMS_THRESHOLD = 1400;
  const SPEECH_START_FRAMES = 6; // ~120 ms sustained speech before capture
  const SPEECH_END_SILENCE_MS = 800;
  /** Minimum ms with RMS above SPEECH_RMS_THRESHOLD before sending to STT. */
  const SPEECH_MIN_ACTIVE_MS = 350;
  /** Min PCM bytes (excl. WAV header), aligned with VoiceScreen (~125 ms floor). */
  const SPEECH_MIN_PCM_BYTES = 4000;

  function decodeNativePcmBase64(b64) {
    const binary = atob(b64);
    const byteLen = binary.length;
    if (byteLen === 0) return new Int16Array(0);
    const bytes = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    if (byteLen % 2 !== 0) {
      throw new Error('native PCM chunk has odd byte length');
    }
    return new Int16Array(bytes.buffer, bytes.byteOffset, byteLen / 2);
  }

  function pcm16ToFloat32(pcm16) {
    const out = new Float32Array(pcm16.length);
    for (let i = 0; i < pcm16.length; i++) {
      out[i] = pcm16[i] / 32768;
    }
    return out;
  }

  function pcm16Rms(pcm16) {
    if (!pcm16 || pcm16.length === 0) return 0;
    let sum = 0;
    for (let i = 0; i < pcm16.length; i++) {
      sum += pcm16[i] * pcm16[i];
    }
    return Math.sqrt(sum / pcm16.length);
  }

  /** Rolling buffer of PCM16 chunks; retains the most recent maxSamples. */
  function Pcm16RingBuffer(maxSamples) {
    this.maxSamples = maxSamples;
    this._chunks = [];
    this._total = 0;
  }

  Pcm16RingBuffer.prototype.push = function (pcm16) {
    if (!pcm16 || pcm16.length === 0) return;
    this._chunks.push(pcm16.slice());
    this._total += pcm16.length;
    while (this._total > this.maxSamples && this._chunks.length > 0) {
      const head = this._chunks.shift();
      this._total -= head.length;
    }
  };

  Pcm16RingBuffer.prototype.snapshotChunks = function () {
    return this._chunks.slice();
  };

  Pcm16RingBuffer.prototype.clear = function () {
    this._chunks = [];
    this._total = 0;
  };

  function mergePcm16Chunks(chunks) {
    if (!chunks || chunks.length === 0) return new Int16Array(0);
    const total = chunks.reduce(function (sum, c) { return sum + c.length; }, 0);
    const merged = new Int16Array(total);
    let offset = 0;
    chunks.forEach(function (chunk) {
      merged.set(chunk, offset);
      offset += chunk.length;
    });
    return merged;
  }

  function buildWavBlob(pcmBytes, sampleCount, sampleRate) {
    const buffer = new ArrayBuffer(44 + sampleCount * 2);
    const view = new DataView(buffer);
    function writeStr(off, str) {
      for (let i = 0; i < str.length; i++) view.setUint8(off + i, str.charCodeAt(i));
    }
    writeStr(0, 'RIFF');
    view.setUint32(4, 36 + sampleCount * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeStr(36, 'data');
    view.setUint32(40, sampleCount * 2, true);
    new Uint8Array(buffer, 44).set(new Uint8Array(pcmBytes));
    return new Blob([buffer], { type: 'audio/wav' });
  }

  /** Encode signed 16-bit PCM (little-endian) as WAV. */
  function pcm16ToWavBlob(pcm16, sampleRate) {
    const rate = sampleRate || NATIVE_MIC_SAMPLE_RATE;
    const pcmBytes = new Uint8Array(pcm16.buffer, pcm16.byteOffset, pcm16.byteLength);
    return buildWavBlob(pcmBytes, pcm16.length, rate);
  }

  /** Encode float32 samples in [-1, 1] as 16-bit PCM WAV. */
  function float32ToWavBlob(samples, sampleRate) {
    const rate = sampleRate || NATIVE_MIC_SAMPLE_RATE;
    const pcm16 = new Int16Array(samples.length);
    for (let i = 0; i < samples.length; i++) {
      const clamped = Math.max(-1, Math.min(1, samples[i]));
      pcm16[i] = clamped < 0
        ? Math.max(-32768, Math.round(clamped * 32768))
        : Math.min(32767, Math.round(clamped * 32767));
    }
    return pcm16ToWavBlob(pcm16, rate);
  }

  /**
   * FIFO of float32 samples for feeding a ScriptProcessor / AudioWorklet clock.
   * Partial chunk consumption avoids dropping samples at chunk boundaries.
   */
  function PcmSampleBuffer() {
    this._chunks = [];
    this._available = 0;
  }

  PcmSampleBuffer.prototype.push = function (samples) {
    if (!samples || samples.length === 0) return;
    this._chunks.push(samples);
    this._available += samples.length;
  };

  PcmSampleBuffer.prototype.available = function () {
    return this._available;
  };

  PcmSampleBuffer.prototype.read = function (count) {
    const out = new Float32Array(count);
    let written = 0;
    while (written < count && this._chunks.length > 0) {
      const head = this._chunks[0];
      const need = count - written;
      if (head.length <= need) {
        out.set(head, written);
        written += head.length;
        this._chunks.shift();
      } else {
        out.set(head.subarray(0, need), written);
        this._chunks[0] = head.subarray(need);
        written += need;
      }
    }
    this._available -= written;
    return out;
  };

  PcmSampleBuffer.prototype.clear = function () {
    this._chunks = [];
    this._available = 0;
  };

  function waitForSamples(buffer, minSamples, timeoutMs) {
    const deadline = Date.now() + (timeoutMs || 2000);
    return new Promise(function (resolve) {
      function tick() {
        if (buffer.available() >= minSamples || Date.now() >= deadline) {
          resolve(buffer.available());
          return;
        }
        setTimeout(tick, 25);
      }
      tick();
    });
  }

  global.NativeAudio = {
    VOICE_MODE_NATIVE_VAD_VERSION: 5,
    NATIVE_MIC_SAMPLE_RATE: NATIVE_MIC_SAMPLE_RATE,
    VAD_PREFETCH_SAMPLES: VAD_PREFETCH_SAMPLES,
    SPEECH_PREROLL_SAMPLES: SPEECH_PREROLL_SAMPLES,
    BARGE_IN_RMS_THRESHOLD: BARGE_IN_RMS_THRESHOLD,
    BARGE_IN_RMS_FRAMES: BARGE_IN_RMS_FRAMES,
    SPEECH_RMS_THRESHOLD: SPEECH_RMS_THRESHOLD,
    SPEECH_START_FRAMES: SPEECH_START_FRAMES,
    SPEECH_END_SILENCE_MS: SPEECH_END_SILENCE_MS,
    SPEECH_MIN_ACTIVE_MS: SPEECH_MIN_ACTIVE_MS,
    SPEECH_MIN_PCM_BYTES: SPEECH_MIN_PCM_BYTES,
    decodeNativePcmBase64: decodeNativePcmBase64,
    pcm16ToFloat32: pcm16ToFloat32,
    pcm16Rms: pcm16Rms,
    mergePcm16Chunks: mergePcm16Chunks,
    pcm16ToWavBlob: pcm16ToWavBlob,
    float32ToWavBlob: float32ToWavBlob,
    PcmSampleBuffer: PcmSampleBuffer,
    Pcm16RingBuffer: Pcm16RingBuffer,
    waitForSamples: waitForSamples,
  };
})(typeof window !== 'undefined' ? window : globalThis);
