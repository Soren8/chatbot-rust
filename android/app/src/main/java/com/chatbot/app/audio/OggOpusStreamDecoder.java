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
 */
public class OggOpusStreamDecoder {
    private static final int MAX_OUTPUT_SAMPLES_120MS_24K = 2880;
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
        // Pre-skip is counted in 48 kHz samples; convert to output rate.
        long preskip48 = ((packet[11] & 0xFF) << 8) | (packet[10] & 0xFF);
        preskipRemaining = (preskip48 * sampleRate) / 48000;
        try {
            decoder = new OpusDecoder(sampleRate, 1);
        } catch (OpusException e) {
            throw new IOException("opus decoder init failed: " + e.getMessage());
        }
    }

    private void decodeAudioPacket(byte[] packet) throws IOException {
        if (decoder == null) {
            throw new IOException("audio packet before OpusHead");
        }
        short[] out = new short[MAX_OUTPUT_SAMPLES_120MS_24K];
        int decoded;
        try {
            decoded = decoder.decode(packet, 0, packet.length, out, 0,
                    MAX_OUTPUT_SAMPLES_120MS_24K, false);
        } catch (OpusException e) {
            throw new IOException("opus decode failed: " + e.getMessage());
        }
        int skip = (int) Math.min(preskipRemaining, decoded);
        preskipRemaining -= skip;
        for (int i = skip; i < decoded; i++) {
            short s = out[i];
            pcm.write(s & 0xFF);
            pcm.write((s >> 8) & 0xFF);
        }
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
}
