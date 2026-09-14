package com.chatbot.app.audio;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import io.github.jaredmdobson.concentus.OpusDecoder;
import io.github.jaredmdobson.concentus.OpusException;

/**
 * Streaming Ogg-Opus to PCM16 decoder for TTS clips.
 *
 * <p>Native playback sinks (AudioTrack) take raw PCM, so the Opus wire format
 * from /tts_stream must be decoded on-phone. This mirrors the WavStreamDecoder
 * shape already used by the voice TTS plugin: bytes are fed in network order,
 * Ogg pages are parsed incrementally, audio packets decode via the pure-Java
 * concentus decoder (no NDK, no OEM MediaCodec variance), and decoded PCM is
 * drained with takePcm(). Mono only — the server always encodes mono.
 *
 * <p><b>Why decode at 48 kHz and then downsample.</b> Concentus 1.0.2's CELT
 * de-emphasis ignores its {@code accum} flag when the decoder resamples
 * ({@code Fs < 48000}): it overwrites the output buffer instead of adding to
 * it. libopus instead adds the downsampled CELT signal on top of the SILK
 * signal that {@code OpusDecoder} already wrote into the same buffer. Hybrid
 * (SILK+CELT) packets therefore lose their SILK layer and decode to near
 * silence at 24 kHz, which is what the server's 24 kbps mono hybrid stream
 * uses. At 48 kHz the decoder does not resample ({@code downsample == 1}), the
 * {@code accum} branch is correct, and hybrid audio is reconstructed intact.
 * We decode at 48 kHz and band-limit/downsample to the OpusHead rate with the
 * FIR below. This is the only output rate supported by the public API that
 * avoids the library's broken resampling path; it is a workaround for
 * <a href="https://github.com/lostromb/concentus">Concentus</a>, not a change
 * to the wire format.
 */
public class OggOpusStreamDecoder {
    /** Opus stores and decodes natively at 48 kHz; only this rate avoids the CELT accum bug. */
    private static final int DECODE_SAMPLE_RATE = 48000;
    private static final int MAX_OUTPUT_SAMPLES_120MS_48K = 5760;
    /** Ogg page capture pattern: every page starts with these four bytes. */
    private static final String OGG_PAGE_MAGIC = "OggS";
    /** First audio-header packet of an Ogg-Opus stream. */
    private static final String OPUS_HEAD_MAGIC = "OpusHead";

    private final ByteArrayOutputStream staging = new ByteArrayOutputStream(8192);
    private final ByteArrayOutputStream pcm = new ByteArrayOutputStream(8192);
    private int stagingConsumed;

    private OpusDecoder decoder;
    private int sampleRate = 24000;
    private int serial = -1;
    private boolean sawHead;
    private boolean sawTags;
    private boolean sawEndOfStream;
    private boolean truncated;
    private long preskipRemaining;
    private FirDownsampler downsampler;

    /** Decoded PCM16 little-endian sample rate, from OpusHead (24000). */
    public int sampleRate() {
        return sampleRate;
    }

    public boolean sawOpusHead() {
        return sawHead;
    }

    public boolean sawEndOfStream() {
        return sawEndOfStream;
    }

    /** True when the stream ended mid-page: the clip was truncated. */
    public boolean hasIncompleteData() {
        return truncated || (stagingAvail() > 0) || (sawHead && !sawEndOfStream);
    }

    /** Feed freshly read network bytes. */
    public void feed(byte[] buf, int n) throws IOException {
        staging.write(buf, 0, n);
        parseAvailable();
    }

    /** Drain decoded PCM16 bytes accumulated since the last call. */
    public byte[] takePcm() {
        byte[] out = pcm.toByteArray();
        pcm.reset();
        return out;
    }

    /** Mark end of input; flags truncation when pages are left hanging. */
    public void finish() {
        if (stagingAvail() > 0 || (sawHead && !sawEndOfStream)) {
            truncated = true;
        }
    }

    private int stagingAvail() {
        return staging.size() - stagingConsumed;
    }

    private byte[] stagingBytes() {
        return staging.toByteArray();
    }

    private void parseAvailable() throws IOException {
        byte[] all = stagingBytes();
        while (true) {
            int avail = all.length - stagingConsumed;
            if (avail < 27) {
                return;
            }
            int base = stagingConsumed;
            if (all[base] != OGG_PAGE_MAGIC.charAt(0) || all[base + 1] != OGG_PAGE_MAGIC.charAt(1)
                    || all[base + 2] != OGG_PAGE_MAGIC.charAt(2)
                    || all[base + 3] != OGG_PAGE_MAGIC.charAt(3)) {
                throw new IOException("not an Ogg stream");
            }
            int segCount = all[base + 26] & 0xFF;
            if (avail < 27 + segCount) {
                return;
            }
            int bodyLen = 0;
            int[] lacing = new int[segCount];
            for (int i = 0; i < segCount; i++) {
                lacing[i] = all[base + 27 + i] & 0xFF;
                bodyLen += lacing[i];
            }
            if (avail < 27 + segCount + bodyLen) {
                return;
            }
            int headerType = all[base + 5] & 0xFF;
            int pageSerial = readLe32(all, base + 14);
            if (serial == -1) {
                serial = pageSerial;
            } else if (pageSerial != serial) {
                throw new IOException("Ogg serial changed mid-stream");
            }
            byte[] body = new byte[bodyLen];
            System.arraycopy(all, base + 27 + segCount, body, 0, bodyLen);
            stagingConsumed += 27 + segCount + bodyLen;
            all = stagingBytes();
            handlePageBody(body, lacing, headerType);
        }
    }

    private void handlePageBody(byte[] body, int[] lacing, int headerType) throws IOException {
        if ((headerType & 0x04) != 0) {
            sawEndOfStream = true;
        }
        // Split the page body into packets on lacing boundaries: a packet
        // ends at the first segment shorter than 255 bytes.
        int pos = 0;
        int packetStart = 0;
        for (int i = 0; i < lacing.length; i++) {
            pos += lacing[i];
            if (lacing[i] < 255) {
                byte[] packet = new byte[pos - packetStart];
                System.arraycopy(body, packetStart, packet, 0, packet.length);
                packetStart = pos;
                handlePacket(packet);
            }
        }
        if (packetStart != pos) {
            // A continued packet spans pages; our server muxer never emits
            // those (Opus packets cap at 1275 bytes, pages hold ~4KB).
            throw new IOException("continued Ogg packet unsupported");
        }
    }

    private void handlePacket(byte[] packet) throws IOException {
        if (!sawHead) {
            parseOpusHead(packet);
            sawHead = true;
            return;
        }
        if (!sawTags) {
            sawTags = true;
            return;
        }
        decodeAudioPacket(packet);
    }

    private void parseOpusHead(byte[] packet) throws IOException {
        if (packet.length < 19 || !startsWithMagic(packet, OPUS_HEAD_MAGIC)) {
            throw new IOException("first Ogg packet is not OpusHead");
        }
        int channels = packet[9] & 0xFF;
        if (channels != 1) {
            throw new IOException("only mono Opus TTS is supported, got " + channels);
        }
        int rate = readLe32(packet, 12);
        if (rate != 8000 && rate != 12000 && rate != 16000 && rate != 24000 && rate != 48000) {
            throw new IOException("unsupported Opus input rate " + rate);
        }
        sampleRate = rate;
        // Pre-skip is counted in 48 kHz samples, matching the decode rate.
        preskipRemaining = ((packet[11] & 0xFF) << 8) | (packet[10] & 0xFF);
        try {
            decoder = new OpusDecoder(DECODE_SAMPLE_RATE, 1);
        } catch (OpusException e) {
            throw new IOException("opus decoder init failed: " + e.getMessage());
        }
        if (sampleRate != DECODE_SAMPLE_RATE) {
            downsampler = new FirDownsampler(DECODE_SAMPLE_RATE, sampleRate);
        }
    }

    private void decodeAudioPacket(byte[] packet) throws IOException {
        if (decoder == null) {
            throw new IOException("audio packet before OpusHead");
        }
        short[] out = new short[MAX_OUTPUT_SAMPLES_120MS_48K];
        int decoded;
        try {
            decoded = decoder.decode(packet, 0, packet.length, out, 0,
                    MAX_OUTPUT_SAMPLES_120MS_48K, false);
        } catch (OpusException e) {
            throw new IOException("opus decode failed: " + e.getMessage());
        }
        int skip = (int) Math.min(preskipRemaining, decoded);
        preskipRemaining -= skip;
        if (downsampler == null) {
            for (int i = skip; i < decoded; i++) {
                appendPcm(out[i]);
            }
        } else {
            downsampler.process(out, skip, decoded, pcm);
        }
    }

    private void appendPcm(short s) {
        pcm.write(s & 0xFF);
        pcm.write((s >> 8) & 0xFF);
    }

    private static boolean startsWithMagic(byte[] packet, String magic) {
        if (packet.length < magic.length()) {
            return false;
        }
        for (int i = 0; i < magic.length(); i++) {
            if (packet[i] != (byte) magic.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static int readLe32(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    /**
     * Streaming integer-factor FIR decimator for the Opus output rates, which
     * all divide 48 kHz evenly (factor 2/3/4/6). Coefficients are a
     * Blackman-windowed sinc low-pass at the output Nyquist; the filter's
     * group delay is compensated by sampling the convolution centre. State is
     * deterministic, so the same bytes decode identically regardless of how
     * they are chunked across {@code feed()} calls.
     */
    private static final class FirDownsampler {
        private final int factor;
        private final int taps;
        private final int delay;
        private final int[] coefficients;
        private final short[] history;
        private int historyPos;
        private long inputCount;
        private long nextCenter;

        FirDownsampler(int inRate, int outRate) {
            if (inRate % outRate != 0) {
                throw new IllegalArgumentException("rates not integer-divisible: " + inRate + "/" + outRate);
            }
            this.factor = inRate / outRate;
            this.taps = 64 * factor + 1;
            this.delay = (taps - 1) / 2;
            this.coefficients = design(taps, factor);
            this.history = new short[taps];
            this.nextCenter = delay;
        }

        void process(short[] in, int from, int to, ByteArrayOutputStream out) {
            if (from >= to) {
                return;
            }
            for (int i = from; i < to; i++) {
                history[historyPos] = in[i];
                historyPos++;
                if (historyPos == taps) {
                    historyPos = 0;
                }
                if (inputCount == nextCenter) {
                    long acc = 0;
                    int idx = historyPos - 1;
                    for (int k = 0; k < taps; k++) {
                        if (idx < 0) {
                            idx += taps;
                        }
                        acc += (long) coefficients[k] * history[idx];
                        idx--;
                    }
                    int y = (int) (acc >> 15);
                    if (y > 32767) {
                        y = 32767;
                    } else if (y < -32768) {
                        y = -32768;
                    }
                    out.write(y & 0xFF);
                    out.write((y >> 8) & 0xFF);
                    nextCenter += factor;
                }
                inputCount++;
            }
        }

        /** Q15 Blackman-windowed sinc low-pass at the output Nyquist, DC-normalized. */
        private static int[] design(int taps, int factor) {
            int delay = (taps - 1) / 2;
            double fc = 0.5 / factor;
            double[] h = new double[taps];
            double sum = 0.0;
            for (int n = 0; n < taps; n++) {
                int x = n - delay;
                double v = x == 0 ? 2.0 * fc : Math.sin(2.0 * Math.PI * fc * x) / (Math.PI * x);
                double w = 0.42 - 0.5 * Math.cos(2.0 * Math.PI * n / (taps - 1))
                        + 0.08 * Math.cos(4.0 * Math.PI * n / (taps - 1));
                h[n] = v * w;
                sum += h[n];
            }
            int[] coef = new int[taps];
            for (int n = 0; n < taps; n++) {
                coef[n] = (int) Math.round(h[n] / sum * 32768.0);
            }
            return coef;
        }
    }
}
