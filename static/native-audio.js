/**
 * Native (Capacitor) microphone audio helpers — PCM16 @ 16 kHz for Parakeet STT.
 * Loaded before chat.js; exposes window.NativeAudio.
 */
(function (global) {
  'use strict';

  const NATIVE_MIC_SAMPLE_RATE = 16000;
  /** Minimum buffered audio before starting Silero VAD (avoids initial underruns). */
  const VAD_PREFETCH_SAMPLES = 4800; // 300 ms @ 16 kHz
  /** Pre-roll so unvoiced onsets before the speech-like gate reach STT. */
  const SPEECH_PREROLL_SAMPLES = 8000; // 500 ms @ 16 kHz
  /**
   * Two-phase native VAD (desktop Silero analog). Do not collapse these gates.
   * Phase 1 SPEECH_START_FRAMES: start *recording*. Coughs may enter this. Do
   *   not stop TTS here; do not AND extra classifiers onto start or table speech
   *   never records.
   * Phase 2 REAL_SPEECH_MS + voicing: barge-in. A cough or short "hey" must fail;
   *   sustained speech must pass immediately, not at end-of-speech.
   * Dual test: cough_and_hey_do_not_barge_in_sustained_noisy_speech_does.
   */
  /** Speakerphone-distance energy floor. Speech-like shape is required on top. */
  const SPEECH_RMS_THRESHOLD = 500;
  const SPEECH_START_FRAMES = 6; // ~120 ms of speech-like frames before *recording* (like Silero onSpeechStart)
  /** Consecutive non-speech-like energy frames that reset the start counter (allows one plosive). */
  const SPEECH_START_MISS_FRAMES = 2;
  /** Voiced-speech ZCR band at 16 kHz. Below is rumble/DC; above is hiss/noise. */
  const SPEECH_ZCR_MIN = 0.01;
  const SPEECH_ZCR_MAX = 0.30;
  /** Peak/RMS above this is an impulse (cough, clap), not sustained speech. */
  const SPEECH_CREST_MAX = 9;
  /** Peak normalized autocorr in the 80–400 Hz band. Loose enough for noisy table speech. */
  const SPEECH_PERIODICITY_MIN = 0.15;
  /** Autocorr lags at 16 kHz: 400 Hz → 40 samples, 80 Hz → 200 samples. */
  const SPEECH_PITCH_LAG_MIN = 40;
  const SPEECH_PITCH_LAG_MAX = 200;
  /** Rolling window for voiced evidence (~100 ms). */
  const SPEECH_VOICED_WINDOW_FRAMES = 5;
  /** Speech-like duration before barge-in. Longer than desktop minSpeechMs (400) because native has no Silero. */
  const REAL_SPEECH_MS = 600;
  /** Voiced-window hits required inside that span. A cough/"hey" does not reach this. */
  const REAL_SPEECH_VOICED_MS = 120;
  const SPEECH_END_SILENCE_MS = 1500;
  /** Minimum ms with RMS above SPEECH_RMS_THRESHOLD before sending to STT. */
  const SPEECH_MIN_ACTIVE_MS = 350;
  /** Min PCM bytes (excl. WAV header), aligned with VoiceScreen (~125 ms floor). */
  const SPEECH_MIN_PCM_BYTES = 4000;
  /**
   * Voice-mode STT wire budget: no upload leg may exceed 500 kbps, compressed
   * or not. The AAC leg below runs far under it; the WAV fallback is exactly
   * NATIVE_MIC_SAMPLE_RATE * 16-bit mono = 256 kbps. Clamp here so a future
   * quality bump cannot silently blow the budget on spotty links.
   */
  const STT_WIRE_BITRATE_CAP_BPS = 500000;
  /** AAC-LC target for STT uploads when WebCodecs is available. */
  const STT_AAC_BITRATE_BPS = 32000;

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

  function pcm16ZeroCrossingRate(pcm16) {
    if (!pcm16 || pcm16.length < 2) return 0;
    let crossings = 0;
    for (let i = 1; i < pcm16.length; i++) {
      const prev = pcm16[i - 1];
      const cur = pcm16[i];
      if ((prev >= 0 && cur < 0) || (prev < 0 && cur >= 0)) {
        if (prev !== 0 || cur !== 0) crossings++;
      }
    }
    return crossings / (pcm16.length - 1);
  }

  function pcm16PeakAbs(pcm16) {
    if (!pcm16 || pcm16.length === 0) return 0;
    let peak = 0;
    for (let i = 0; i < pcm16.length; i++) {
      const a = pcm16[i] < 0 ? -pcm16[i] : pcm16[i];
      if (a > peak) peak = a;
    }
    return peak;
  }

  /** True when the frame has speech shape (voiced band + not an impulse), not just energy. */
  function pcm16IsSpeechLike(pcm16, rms) {
    if (!pcm16 || pcm16.length === 0) return false;
    const energy = rms == null ? pcm16Rms(pcm16) : rms;
    if (energy < SPEECH_RMS_THRESHOLD) return false;
    const zcr = pcm16ZeroCrossingRate(pcm16);
    if (zcr < SPEECH_ZCR_MIN || zcr > SPEECH_ZCR_MAX) return false;
    return pcm16PeakAbs(pcm16) / energy <= SPEECH_CREST_MAX;
  }

  /** Peak normalized autocorrelation in the pitch-lag band (voiced speech). */
  function pcm16PitchPeriodicity(pcm16) {
    const n = pcm16 && pcm16.length ? pcm16.length : 0;
    if (n < 80) return 0;
    const maxLag = Math.min(SPEECH_PITCH_LAG_MAX, (n >> 1) - 1);
    if (maxLag < SPEECH_PITCH_LAG_MIN) return 0;
    const energyPrefix = new Float64Array(n + 1);
    for (let i = 0; i < n; i++) {
      const x = pcm16[i];
      energyPrefix[i + 1] = energyPrefix[i] + x * x;
    }
    let best = 0;
    for (let lag = SPEECH_PITCH_LAG_MIN; lag <= maxLag; lag++) {
      const limit = n - lag;
      let corr = 0;
      for (let i = 0; i < limit; i++) {
        corr += pcm16[i] * pcm16[i + lag];
      }
      const e1 = energyPrefix[limit];
      const e2 = energyPrefix[n] - energyPrefix[lag];
      if (e1 < 1 || e2 < 1) continue;
      const norm = corr / Math.sqrt(e1 * e2);
      if (norm > best) best = norm;
    }
    return best;
  }

  /** True when a short window looks periodic (vowel), not a cough body. */
  function pcm16IsVoicedSpeech(pcm16) {
    if (!pcm16 || pcm16.length < 640) return false;
    if (pcm16Rms(pcm16) < SPEECH_RMS_THRESHOLD) return false;
    return pcm16PitchPeriodicity(pcm16) >= SPEECH_PERIODICITY_MIN;
  }

  /** Voiced evidence (ms) from overlapping SPEECH_VOICED_WINDOW_FRAMES slices. */
  function pcm16VoicedMsFromChunks(chunks, frameMs) {
    const w = SPEECH_VOICED_WINDOW_FRAMES;
    const ms = frameMs == null ? 20 : frameMs;
    if (!chunks || chunks.length < w) return 0;
    let voicedMs = 0;
    for (let i = w; i <= chunks.length; i++) {
      if (pcm16IsVoicedSpeech(mergePcm16Chunks(chunks.slice(i - w, i)))) {
        voicedMs += ms;
      }
    }
    return voicedMs;
  }

  /** Desktop onSpeechRealStart analog: sustained speech-like + some voicing. */
  function pcm16RealSpeechDetected(speechLikeMs, voicedMs) {
    return speechLikeMs >= REAL_SPEECH_MS && voicedMs >= REAL_SPEECH_VOICED_MS;
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

  const AAC_SAMPLE_RATES = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350
  ];

  function getAacSampleRateIndex(rate) {
    for (let i = 0; i < AAC_SAMPLE_RATES.length; i++) {
      if (AAC_SAMPLE_RATES[i] === rate) return i;
    }
    return 8; // default to 16000 Hz
  }

  /**
   * 7-byte ADTS framing header for raw AAC-LC access units.
   * Enables standard ffmpeg/browser demuxing of WebCodecs audio chunks.
   */
  function createAdtsHeader(dataLength, sampleRate, channelConfig) {
    const frameLength = 7 + dataLength;
    const rateIdx = getAacSampleRateIndex(sampleRate);
    const channels = channelConfig || 1;
    const header = new Uint8Array(7);

    header[0] = 0xFF;
    header[1] = 0xF1;
    header[2] = ((1 << 6) | ((rateIdx & 0x0F) << 2) | ((channels >> 2) & 1)) & 0xFF;
    header[3] = (((channels & 3) << 6) | ((frameLength >> 11) & 0x03)) & 0xFF;
    header[4] = (frameLength >> 3) & 0xFF;
    header[5] = (((frameLength & 7) << 5) | 0x1F) & 0xFF;
    header[6] = 0xFC;
    return header;
  }

  /**
   * One log line per STT encode decision (codec choice and any fallback
   * reason). Goes to the browser console and, on Android, to adb logcat via
   * the Logger plugin (window.nativeLog is defined by chat.js, which loads
   * after this file — encodeAudioForStt only runs after page load, so it is
   * always present by call time there; guard anyway for other embedders).
   * Machine-readable tags (`reason=...`) let server-side grep / adb filters
   * reveal whether compression is actually engaged or we silently sent WAV.
   */
  function sttCodecLog(message) {
    if (typeof console !== 'undefined' && console.info) {
      console.info('[VAD] ' + message);
    }
    if (typeof globalThis.nativeLog === 'function') {
      try { globalThis.nativeLog('VAD', message); } catch (_) { /* ignore */ }
    }
  }

  /** Wire size of the raw sample buffer, for compression-ratio logging. */
  function sampleBufferBytes(samples) {
    if (samples && samples.byteLength != null) {
      return samples.byteLength;
    }
    return (samples ? samples.length : 0) * 2;
  }

  /**
   * Encode PCM audio samples using WebCodecs AudioEncoder into ADTS AAC.
   */
  function encodeAacAdts(samples, sampleRate, aacConfig) {
    return new Promise(function (resolve, reject) {
      let f32;
      if (samples instanceof Float32Array) {
        f32 = samples;
      } else if (samples instanceof Int16Array) {
        f32 = new Float32Array(samples.length);
        for (let i = 0; i < samples.length; i++) {
          f32[i] = samples[i] < 0 ? samples[i] / 32768 : samples[i] / 32767;
        }
      } else {
        f32 = new Float32Array(samples);
      }

      const chunks = [];
      const encoder = new AudioEncoder({
        output: function (chunk) {
          const buf = new Uint8Array(chunk.byteLength);
          chunk.copyTo(buf);
          const adts = createAdtsHeader(chunk.byteLength, sampleRate, 1);
          chunks.push(adts);
          chunks.push(buf);
        },
        error: function (e) {
          reject(e);
        }
      });

      encoder.configure(aacConfig);

      const frameSize = 1024;
      let offset = 0;
      let timestampMicros = 0;
      const microsPerFrame = Math.round((frameSize * 1000000) / sampleRate);

      while (offset < f32.length) {
        const remaining = f32.length - offset;
        let frameData;
        if (remaining >= frameSize) {
          frameData = f32.subarray(offset, offset + frameSize);
        } else {
          frameData = new Float32Array(frameSize);
          frameData.set(f32.subarray(offset));
        }

        const audioData = new AudioData({
          format: 'f32',
          sampleRate: sampleRate,
          numberOfFrames: frameSize,
          numberOfChannels: 1,
          timestamp: timestampMicros,
          data: frameData
        });

        encoder.encode(audioData);
        audioData.close();

        offset += frameSize;
        timestampMicros += microsPerFrame;
      }

      encoder.flush().then(function () {
        encoder.close();
        resolve(new Blob(chunks, { type: 'audio/aac' }));
      }).catch(function (err) {
        try { encoder.close(); } catch (_) {}
        reject(err);
      });
    });
  }

  /**
   * Encode audio samples for STT upload.
   * Uses hardware-accelerated WebCodecs (AAC-LC with ADTS) when available for wire
   * compression (8-10x bandwidth reduction over spotty connections), falling back
   * to PCM16 WAV.
   */
  async function encodeAudioForStt(samples, sampleRate) {
    const rate = sampleRate || NATIVE_MIC_SAMPLE_RATE;
    if (!samples || samples.length === 0) {
      return {
        blob: new Blob([], { type: 'audio/wav' }),
        filename: 'recording.wav',
        mimeType: 'audio/wav'
      };
    }

    const pcmBytes = sampleBufferBytes(samples);
    let webcodecsAvailable = false;
    if (typeof globalThis !== 'undefined'
        && typeof globalThis.AudioEncoder === 'function'
        && typeof globalThis.AudioData === 'function') {
      if (typeof window !== 'undefined' && window.isSecureContext === false) {
        // WebCodecs is gated to secure contexts. Plain HTTP origins (the
        // Android physical flavor is http://<tailscale-host>:80) can never
        // compress — say so instead of failing silently every utterance.
        sttCodecLog('STT codec fallback: reason=insecure-context'
          + ' (plain HTTP disables WebCodecs; sending WAV bytes=' + pcmBytes + ')');
      } else {
        webcodecsAvailable = true;
      }
    } else {
      sttCodecLog('STT codec fallback: reason=no-webcodecs'
        + ' (AudioEncoder unavailable; sending WAV bytes=' + pcmBytes + ')');
    }

    if (webcodecsAvailable) {
      try {
        const aacConfig = {
          codec: 'mp4a.40.2',
          sampleRate: rate,
          numberOfChannels: 1,
          bitrate: Math.min(STT_AAC_BITRATE_BPS, STT_WIRE_BITRATE_CAP_BPS)
        };
        const support = await AudioEncoder.isConfigSupported(aacConfig);
        if (support && support.supported) {
          const encodedBlob = await encodeAacAdts(samples, rate, aacConfig);
          if (encodedBlob && encodedBlob.size > 0) {
            const ratio = pcmBytes > 0 ? (pcmBytes / encodedBlob.size).toFixed(1) : '0.0';
            sttCodecLog('STT codec: aac bytes=' + encodedBlob.size
              + ' pcmBytes=' + pcmBytes + ' ratio=' + ratio + 'x');
            return {
              blob: encodedBlob,
              filename: 'recording.aac',
              mimeType: 'audio/aac'
            };
          }
          sttCodecLog('STT codec fallback: reason=empty-output'
            + ' (encoder produced 0 bytes; sending WAV bytes=' + pcmBytes + ')');
        } else {
          sttCodecLog('STT codec fallback: reason=unsupported-config'
            + ' (AudioEncoder.isConfigSupported rejected mp4a.40.2 @' + rate
            + 'Hz; sending WAV bytes=' + pcmBytes + ')');
        }
      } catch (err) {
        sttCodecLog('STT codec fallback: reason=encoder-error err=' + (err && err.message ? err.message : String(err))
          + '; sending WAV bytes=' + pcmBytes);
        if (typeof console !== 'undefined' && console.warn) {
          console.warn('AudioEncoder STT compression failed, falling back to WAV:', err);
        }
      }
    }

    let wavBlob;
    if (samples instanceof Float32Array) {
      wavBlob = float32ToWavBlob(samples, rate);
    } else {
      wavBlob = pcm16ToWavBlob(samples, rate);
    }
    return {
      blob: wavBlob,
      filename: 'recording.wav',
      mimeType: 'audio/wav'
    };
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
    VOICE_MODE_NATIVE_VAD_VERSION: 13,
    NATIVE_MIC_SAMPLE_RATE: NATIVE_MIC_SAMPLE_RATE,
    VAD_PREFETCH_SAMPLES: VAD_PREFETCH_SAMPLES,
    SPEECH_PREROLL_SAMPLES: SPEECH_PREROLL_SAMPLES,
    SPEECH_RMS_THRESHOLD: SPEECH_RMS_THRESHOLD,
    SPEECH_START_FRAMES: SPEECH_START_FRAMES,
    SPEECH_START_MISS_FRAMES: SPEECH_START_MISS_FRAMES,
    SPEECH_ZCR_MIN: SPEECH_ZCR_MIN,
    SPEECH_ZCR_MAX: SPEECH_ZCR_MAX,
    SPEECH_CREST_MAX: SPEECH_CREST_MAX,
    SPEECH_PERIODICITY_MIN: SPEECH_PERIODICITY_MIN,
    SPEECH_PITCH_LAG_MIN: SPEECH_PITCH_LAG_MIN,
    SPEECH_PITCH_LAG_MAX: SPEECH_PITCH_LAG_MAX,
    SPEECH_VOICED_WINDOW_FRAMES: SPEECH_VOICED_WINDOW_FRAMES,
    REAL_SPEECH_MS: REAL_SPEECH_MS,
    REAL_SPEECH_VOICED_MS: REAL_SPEECH_VOICED_MS,
    SPEECH_END_SILENCE_MS: SPEECH_END_SILENCE_MS,
    SPEECH_MIN_ACTIVE_MS: SPEECH_MIN_ACTIVE_MS,
    SPEECH_MIN_PCM_BYTES: SPEECH_MIN_PCM_BYTES,
    decodeNativePcmBase64: decodeNativePcmBase64,
    pcm16ToFloat32: pcm16ToFloat32,
    pcm16Rms: pcm16Rms,
    pcm16ZeroCrossingRate: pcm16ZeroCrossingRate,
    pcm16PeakAbs: pcm16PeakAbs,
    pcm16IsSpeechLike: pcm16IsSpeechLike,
    pcm16PitchPeriodicity: pcm16PitchPeriodicity,
    pcm16IsVoicedSpeech: pcm16IsVoicedSpeech,
    pcm16VoicedMsFromChunks: pcm16VoicedMsFromChunks,
    pcm16RealSpeechDetected: pcm16RealSpeechDetected,
    mergePcm16Chunks: mergePcm16Chunks,
    pcm16ToWavBlob: pcm16ToWavBlob,
    float32ToWavBlob: float32ToWavBlob,
    createAdtsHeader: createAdtsHeader,
    encodeAudioForStt: encodeAudioForStt,
    PcmSampleBuffer: PcmSampleBuffer,
    Pcm16RingBuffer: Pcm16RingBuffer,
    waitForSamples: waitForSamples,
  };
})(typeof window !== 'undefined' ? window : globalThis);
