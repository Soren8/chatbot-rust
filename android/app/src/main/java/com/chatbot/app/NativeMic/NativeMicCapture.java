package com.chatbot.app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.BooleanSupplier;

/** Android-free 16-bit mono capture loop: read sizing, read errors, and fixed 20 ms frames. */
public final class NativeMicCapture {
    /** Fixed 20 ms frames for steady JS consumption (320 samples * 2 bytes). */
    public static final int CHUNK_SAMPLES = 320;
    private static final int BYTES_PER_SAMPLE = 2;

    public interface Source {
        int read(short[] buffer, int offset, int length);
    }

    public interface FrameSink {
        void onFrame(byte[] pcm);
    }

    private NativeMicCapture() {
    }

    /** {@code AudioRecord.getMinBufferSize} reports bytes; reads count 16-bit mono samples. */
    public static int readSamples(int minBufferBytes) {
        return Math.max(1, minBufferBytes / BYTES_PER_SAMPLE);
    }

    /**
     * Reads until {@code running} is false (returns 0) or a read fails (returns the negative
     * AudioRecord error, which the recorder cannot recover from). A pending partial frame is
     * flushed either way.
     */
    public static int run(Source source, int readSamples, BooleanSupplier running, FrameSink sink) {
        short[] readBuffer = new short[readSamples];
        short[] chunkBuffer = new short[CHUNK_SAMPLES];
        int chunkFill = 0;
        int readError = 0;
        while (running.getAsBoolean()) {
            int read = source.read(readBuffer, 0, readSamples);
            if (read < 0) {
                readError = read;
                break;
            }
            int offset = 0;
            while (offset < read) {
                int toCopy = Math.min(CHUNK_SAMPLES - chunkFill, read - offset);
                System.arraycopy(readBuffer, offset, chunkBuffer, chunkFill, toCopy);
                chunkFill += toCopy;
                offset += toCopy;
                if (chunkFill == CHUNK_SAMPLES) {
                    sink.onFrame(toLittleEndianBytes(chunkBuffer, CHUNK_SAMPLES));
                    chunkFill = 0;
                }
            }
        }
        if (chunkFill > 0) {
            sink.onFrame(toLittleEndianBytes(chunkBuffer, chunkFill));
        }
        return readError;
    }

    static byte[] toLittleEndianBytes(short[] shorts, int count) {
        byte[] bytes = new byte[count * BYTES_PER_SAMPLE];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().put(shorts, 0, count);
        return bytes;
    }
}
