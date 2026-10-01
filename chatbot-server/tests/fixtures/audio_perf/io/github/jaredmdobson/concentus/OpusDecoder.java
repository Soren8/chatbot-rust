package io.github.jaredmdobson.concentus;

/**
 * Off-device stub of the concentus decoder: every packet decodes to one
 * deterministic 20 ms frame at 48 kHz derived from the packet bytes, so the
 * Ogg demux and PCM output path can be checked exactly without the jar.
 */
public class OpusDecoder {
    public static final int FRAME_SAMPLES = 960;

    public OpusDecoder(int sampleRate, int channels) throws OpusException {
        if (sampleRate != 48000 || channels != 1) {
            throw new OpusException("stub expects 48 kHz mono, got " + sampleRate + "/" + channels);
        }
    }

    public int decode(byte[] in, int inOffset, int length, short[] out, int outOffset,
            int frameSize, boolean decodeFec) throws OpusException {
        if (length <= 0 || frameSize < FRAME_SAMPLES) {
            throw new OpusException("bad stub decode call");
        }
        for (int i = 0; i < FRAME_SAMPLES; i++) {
            out[outOffset + i] = sample(in, inOffset, length, i);
        }
        return FRAME_SAMPLES;
    }

    public static short sample(byte[] in, int offset, int length, int i) {
        return (short) ((in[offset + (i % length)] & 0xFF) * 211 + i * 29 - 27000);
    }
}
