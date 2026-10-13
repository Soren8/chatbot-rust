/**
 * Native (Capacitor) microphone audio helpers — PCM16 @ 16 kHz for Parakeet STT.
 * Loaded before chat.js; exposes window.NativeAudio.
 */
(function (global) {
  'use strict';

  const NATIVE_MIC_SAMPLE_RATE = 16000;
  /** Minimum buffered audio before starting Silero VAD (avoids initial underruns). */
  const VAD_PREFETCH_SAMPLES = 4800; // 300 ms @ 16 kHz
  /** Pre-roll so unvoiced onset samples reach STT after Silero confirms speech. */
  const SPEECH_PREROLL_SAMPLES = 8000; // 500 ms @ 16 kHz
  /** Silero-positive duration before interrupting TTS. */
  const REAL_SPEECH_MS = 600;
  const SPEECH_START_MS = 120;
  const SPEECH_END_SILENCE_MS = 1500;
  /** Minimum Silero-positive duration before sending to STT. */
  const SPEECH_MIN_ACTIVE_MS = 400;
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
  /** Opus target for STT uploads (the guaranteed Chromium software encoder).
   * 16k keeps uploads viable over relayed/degraded links; opus stays
   * STT-grade for speech at this rate. Actual wire rate runs higher
   * (~1.4x) due to one Ogg page per packet framing overhead. */
  const STT_OPUS_BITRATE_BPS = 16000;

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
    // Codec engagement (or the reason it fell back) must reach the server:
    // without this the field logs show WAV uploads with no explanation.
    // chat.js exposes window.reportVoice; guarded for standalone loads.
    if (typeof globalThis.reportVoice === 'function') {
      try { globalThis.reportVoice('VOICE', message); } catch (_) { /* ignore */ }
    }
  }

  /** Wire size of the raw sample buffer, for compression-ratio logging. */
  function sampleBufferBytes(samples) {
    if (samples && samples.byteLength != null) {
      return samples.byteLength;
    }
    return (samples ? samples.length : 0) * 2;
  }

  /** Shared sample-to-float32 conversion for the WebCodecs encoders. */
  function toFloat32Samples(samples) {
    if (samples instanceof Float32Array) {
      return samples;
    }
    if (samples instanceof Int16Array) {
      const f32 = new Float32Array(samples.length);
      for (let i = 0; i < samples.length; i++) {
        f32[i] = samples[i] < 0 ? samples[i] / 32768 : samples[i] / 32767;
      }
      return f32;
    }
    return new Float32Array(samples);
  }

  /**
   * Encode PCM audio samples using WebCodecs AudioEncoder into ADTS AAC.
   */
  function encodeAacAdts(samples, sampleRate, aacConfig) {
    return new Promise(function (resolve, reject) {
      const f32 = toFloat32Samples(samples);

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
   * Ordered STT encoder candidates probed at runtime via
   * AudioEncoder.isConfigSupported. The device — not our assumptions —
   * decides: AAC encoding rides the hardware MediaCodec path and varies by
   * device/WebView (stock Chrome vs GrapheneOS Vanadium diverge here),
   * while opus is Chromium's built-in software encoder and works wherever
   * AudioEncoder exists. First supported candidate wins.
   */
  function sttEncoderCandidates(rate, aacCap, opusCap) {
    return [
      {
        label: 'aac-32k', filename: 'recording.aac', mimeType: 'audio/aac', frame: 'adts',
        config: { codec: 'mp4a.40.2', sampleRate: rate, numberOfChannels: 1, bitrate: aacCap }
      },
      {
        label: 'aac-default', filename: 'recording.aac', mimeType: 'audio/aac', frame: 'adts',
        config: { codec: 'mp4a.40.2', sampleRate: rate, numberOfChannels: 1 }
      },
      {
        label: 'aac-64k', filename: 'recording.aac', mimeType: 'audio/aac', frame: 'adts',
        config: {
          codec: 'mp4a.40.2', sampleRate: rate, numberOfChannels: 1,
          bitrate: Math.min(64000, aacCap)
        }
      },
      {
        label: 'opus-16k', filename: 'recording.opus', mimeType: 'audio/ogg;codecs=opus',
        frame: 'ogg',
        config: { codec: 'opus', sampleRate: rate, numberOfChannels: 1, bitrate: opusCap }
      }
    ];
  }

  /** First-supported probe result, cached: device codecs don't change at runtime. */
  let sttEncoderProbeCache = null;
  let sttEncoderProbePending = null;

  /**
   * Probe every STT encoder candidate and log the full support matrix via
   * sttCodecLog (console + logcat + server). This is the line that answers
   * "what codecs does this actual device support" in field logs.
   */
  async function probeSttEncoders(rate, aacCap, opusCap) {
    if (sttEncoderProbeCache && sttEncoderProbeCache.rate === rate) {
      return sttEncoderProbeCache.selected;
    }
    if (sttEncoderProbePending) return sttEncoderProbePending;
    sttEncoderProbePending = (async function () {
      const matrix = [];
      let selected = null;
      const candidates = sttEncoderCandidates(rate, aacCap, opusCap);
      for (let i = 0; i < candidates.length; i++) {
        const cand = candidates[i];
        let ok = false;
        try {
          const support = await AudioEncoder.isConfigSupported(cand.config);
          ok = !!(support && support.supported);
        } catch (err) {
          ok = false;
        }
        matrix.push(cand.label + '=' + (ok ? 'yes' : 'no'));
        if (ok && !selected) selected = cand;
      }
      sttCodecLog('STT codec probe @' + rate + 'Hz: ' + matrix.join(' ')
        + ' selected=' + (selected ? selected.label : 'wav-fallback'));
      sttEncoderProbeCache = { rate: rate, selected: selected };
      sttEncoderProbePending = null;
      return selected;
    })();
    return sttEncoderProbePending;
  }

  /** CRC-32 table for Ogg page checksums (poly 0x04C11DB7). */
  const OGG_CRC_TABLE = (function () {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = (n << 24) >>> 0;
      for (let k = 0; k < 8; k++) {
        c = (c & 0x80000000) ? (((c << 1) ^ 0x04C11DB7) >>> 0) : (((c << 1) >>> 0));
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function oggCrc32(bytes) {
    let crc = 0;
    for (let i = 0; i < bytes.length; i++) {
      crc = (((crc << 8) ^ OGG_CRC_TABLE[((crc >>> 24) ^ bytes[i]) & 0xFF]) >>> 0);
    }
    return crc >>> 0;
  }

  /**
   * One Ogg page wrapping a single packet (header_type 2=BOS, 0=body, 4=EOS).
   * Granule position counts 48 kHz samples for Opus regardless of input rate.
   */
  function createOggPage(packet, headerType, granulePos, serial, seq) {
    const segCount = Math.max(1, Math.ceil(packet.length / 255));
    const headerLen = 27 + segCount;
    const page = new Uint8Array(headerLen + packet.length);
    const view = new DataView(page.buffer, page.byteOffset, page.byteLength);
    page[0] = 0x4F; page[1] = 0x67; page[2] = 0x67; page[3] = 0x53; // OggS
    page[4] = 0; // stream structure version
    page[5] = headerType;
    view.setUint32(6, granulePos % 4294967296, true);
    view.setUint32(10, Math.floor(granulePos / 4294967296), true);
    view.setUint32(14, serial, true);
    view.setUint32(18, seq >>> 0, true);
    view.setUint32(22, 0, true); // checksum placeholder
    page[26] = segCount;
    let remaining = packet.length;
    for (let i = 0; i < segCount; i++) {
      const take = Math.min(255, remaining);
      page[27 + i] = take;
      remaining -= take;
    }
    page.set(packet, headerLen);
    view.setUint32(22, oggCrc32(page), true);
    return page;
  }

  /** 19-byte OpusHead identification header (mono, mapping family 0). */
  function createOpusHeadPacket(sampleRate) {
    const pkt = new Uint8Array(19);
    const magic = 'OpusHead';
    for (let i = 0; i < magic.length; i++) pkt[i] = magic.charCodeAt(i);
    pkt[8] = 1; // version
    pkt[9] = 1; // channel count
    pkt[10] = 0; pkt[11] = 0; // pre-skip
    const view = new DataView(pkt.buffer, pkt.byteOffset, pkt.byteLength);
    view.setUint32(12, sampleRate, true); // input sample rate
    view.setInt16(16, 0, true); // output gain
    pkt[18] = 0; // channel mapping family
    return pkt;
  }

  /** OpusTags comment header with an empty user-comment list. */
  function createOpusTagsPacket() {
    const vendor = 'chatbot-stt';
    const pkt = new Uint8Array(8 + 4 + vendor.length + 4);
    const magic = 'OpusTags';
    for (let i = 0; i < magic.length; i++) pkt[i] = magic.charCodeAt(i);
    const view = new DataView(pkt.buffer, pkt.byteOffset, pkt.byteLength);
    view.setUint32(8, vendor.length, true);
    for (let i = 0; i < vendor.length; i++) pkt[12 + i] = vendor.charCodeAt(i);
    view.setUint32(12 + vendor.length, 0, true); // zero user comments
    return pkt;
  }

  /**
   * Encode PCM samples with the WebCodecs opus encoder into Ogg-Opus.
   * Raw opus packets need a container for ffmpeg; Ogg framing is small and
   * self-describing (OpusHead + OpusTags + one page per packet).
   */
  function encodeOpusOgg(samples, sampleRate, opusConfig) {
    return new Promise(function (resolve, reject) {
      const f32 = toFloat32Samples(samples);

      const packets = [];
      const encoder = new AudioEncoder({
        output: function (chunk) {
          const buf = new Uint8Array(chunk.byteLength);
          chunk.copyTo(buf);
          packets.push({ data: buf, durationMicros: chunk.duration || 20000 });
        },
        error: function (e) {
          reject(e);
        }
      });

      encoder.configure(opusConfig);

      const frameSize = 960; // 60 ms @ 16 kHz input frames; encoder emits ~20 ms packets
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
        if (packets.length === 0) {
          resolve(new Blob([], { type: 'audio/ogg;codecs=opus' }));
          return;
        }
        const serial = (((Math.random() * 0x7FFFFFFE) | 0) + 1) >>> 0;
        const pages = [];
        let seq = 0;
        pages.push(createOggPage(createOpusHeadPacket(sampleRate), 2, 0, serial, seq++));
        pages.push(createOggPage(createOpusTagsPacket(), 0, 0, serial, seq++));
        let granule = 0;
        for (let i = 0; i < packets.length; i++) {
          granule += Math.max(1, Math.round((packets[i].durationMicros * 48000) / 1000000));
          const last = (i === packets.length - 1);
          pages.push(createOggPage(packets[i].data, last ? 4 : 0, granule, serial, seq++));
        }
        resolve(new Blob(pages, { type: 'audio/ogg;codecs=opus' }));
      }).catch(function (err) {
        try { encoder.close(); } catch (_) {}
        reject(err);
      });
    });
  }

  /**
   * Encode audio samples for STT upload.
   * Probes the device's actual encoders (AAC variants, then opus) and uses
   * the first one the device accepts, falling back to PCM16 WAV.
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
        // emulator flavor, or any http URL) can never compress — say so
        // instead of failing silently every utterance.
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
      // Device codecs don't change at runtime; the probe logs the matrix once.
      const cap = Math.min(STT_AAC_BITRATE_BPS, STT_WIRE_BITRATE_CAP_BPS);
      const opusCap = Math.min(STT_OPUS_BITRATE_BPS, STT_WIRE_BITRATE_CAP_BPS);
      const selected = await probeSttEncoders(rate, cap, opusCap);
      if (selected) {
        try {
          const encodeStartMs = (typeof performance !== 'undefined'
            && typeof performance.now === 'function')
            ? performance.now() : Date.now();
          const encodedBlob = selected.frame === 'ogg'
            ? await encodeOpusOgg(samples, rate, selected.config)
            : await encodeAacAdts(samples, rate, selected.config);
          const encodeNowMs = (typeof performance !== 'undefined'
            && typeof performance.now === 'function')
            ? performance.now() : Date.now();
          const encodeMs = Math.max(0, Math.round(encodeNowMs - encodeStartMs));
          if (encodedBlob && encodedBlob.size > 0) {
            const ratio = pcmBytes > 0 ? (pcmBytes / encodedBlob.size).toFixed(1) : '0.0';
            // Stable log contract: AAC success keeps the legacy
            // `STT codec: aac bytes=...` shape; the variant (which AAC
            // candidate won) rides along as a suffix. Opus mirrors it.
            // encodeMs profiles the on-phone WebCodecs pass.
            if (selected.frame === 'ogg') {
              sttCodecLog('STT codec: opus bytes=' + encodedBlob.size
                + ' pcmBytes=' + pcmBytes + ' ratio=' + ratio + 'x'
                + ' variant=' + selected.label + ' encodeMs=' + encodeMs);
            } else {
              sttCodecLog('STT codec: aac bytes=' + encodedBlob.size
                + ' pcmBytes=' + pcmBytes + ' ratio=' + ratio + 'x'
                + ' variant=' + selected.label + ' encodeMs=' + encodeMs);
            }
            return {
              blob: encodedBlob,
              filename: selected.filename,
              mimeType: selected.mimeType
            };
          }
          sttCodecLog('STT codec fallback: reason=empty-output'
            + ' (encoder ' + selected.label + ' produced 0 bytes; sending WAV bytes='
            + pcmBytes + ')');
        } catch (err) {
          sttCodecLog('STT codec fallback: reason=encoder-error encoder=' + selected.label
            + ' err=' + (err && err.message ? err.message : String(err))
            + '; sending WAV bytes=' + pcmBytes);
          if (typeof console !== 'undefined' && console.warn) {
            console.warn('AudioEncoder STT compression failed, falling back to WAV:', err);
          }
        }
      } else {
        sttCodecLog('STT codec fallback: reason=unsupported-config'
          + ' (device rejected all STT encoder candidates @' + rate
          + 'Hz; sending WAV bytes=' + pcmBytes + ')');
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
    VOICE_MODE_NATIVE_VAD_VERSION: 14,
    NATIVE_MIC_SAMPLE_RATE: NATIVE_MIC_SAMPLE_RATE,
    VAD_PREFETCH_SAMPLES: VAD_PREFETCH_SAMPLES,
    SPEECH_PREROLL_SAMPLES: SPEECH_PREROLL_SAMPLES,
    REAL_SPEECH_MS: REAL_SPEECH_MS,
    SPEECH_START_MS: SPEECH_START_MS,
    SPEECH_END_SILENCE_MS: SPEECH_END_SILENCE_MS,
    SPEECH_MIN_ACTIVE_MS: SPEECH_MIN_ACTIVE_MS,
    SPEECH_MIN_PCM_BYTES: SPEECH_MIN_PCM_BYTES,
    decodeNativePcmBase64: decodeNativePcmBase64,
    pcm16ToFloat32: pcm16ToFloat32,
    mergePcm16Chunks: mergePcm16Chunks,
    pcm16ToWavBlob: pcm16ToWavBlob,
    float32ToWavBlob: float32ToWavBlob,
    createAdtsHeader: createAdtsHeader,
    createOggPage: createOggPage,
    createOpusHeadPacket: createOpusHeadPacket,
    createOpusTagsPacket: createOpusTagsPacket,
    sttEncoderCandidates: sttEncoderCandidates,
    probeSttEncoders: probeSttEncoders,
    encodeAudioForStt: encodeAudioForStt,
    PcmSampleBuffer: PcmSampleBuffer,
    Pcm16RingBuffer: Pcm16RingBuffer,
    waitForSamples: waitForSamples,
  };
})(typeof window !== 'undefined' ? window : globalThis);
