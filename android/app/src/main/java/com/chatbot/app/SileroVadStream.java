package com.chatbot.app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Accumulates native 16 kHz PCM20 packets into Silero V5's 512-sample input frames. */
final class SileroVadStream implements AutoCloseable {
    static final int MODEL_FRAME_SAMPLES = 512;
    static final int MODEL_FRAME_MS = 32;
    private static final float PCM_SCALE = 1.0f / 32768.0f;

    interface Model extends AutoCloseable {
        float infer(float[] frame) throws Exception;

        @Override
        void close() throws Exception;
    }

    static final class Evidence {
        private static final Evidence NONE = new Evidence(false, 0.0f);
        private final boolean hasScore;
        private final float probability;

        private Evidence(boolean hasScore, float probability) {
            this.hasScore = hasScore;
            this.probability = probability;
        }

        static Evidence none() {
            return NONE;
        }

        static Evidence score(float probability) {
            return new Evidence(true, probability);
        }

        boolean hasScore() {
            return hasScore;
        }

        float probability() {
            if (!hasScore) {
                throw new IllegalStateException("No Silero score is available for this PCM packet");
            }
            return probability;
        }

        int durationMs() {
            return hasScore ? MODEL_FRAME_MS : 0;
        }
    }

    private final Model model;
    private final float[] inputFrame = new float[MODEL_FRAME_SAMPLES];
    private int inputSamples;
    private boolean closed;

    SileroVadStream(Model model) {
        if (model == null) {
            throw new IllegalArgumentException("Silero model is required");
        }
        this.model = model;
    }

    /** Returns one fresh score at most; capture packets are capped at 320 samples. */
    Evidence accept(byte[] pcm16le) throws Exception {
        if (closed) {
            throw new IllegalStateException("Silero stream is closed");
        }
        if ((pcm16le.length & 1) != 0) {
            throw new IllegalArgumentException("PCM16 data must contain whole samples");
        }

        ByteBuffer samples = ByteBuffer.wrap(pcm16le).order(ByteOrder.LITTLE_ENDIAN);
        Evidence evidence = Evidence.none();
        while (samples.remaining() >= 2) {
            inputFrame[inputSamples++] = samples.getShort() * PCM_SCALE;
            if (inputSamples == MODEL_FRAME_SAMPLES) {
                float probability = model.infer(inputFrame);
                if (!Float.isFinite(probability) || probability < 0.0f || probability > 1.0f) {
                    throw new IllegalStateException("Silero returned an invalid probability");
                }
                inputSamples = 0;
                evidence = Evidence.score(probability);
            }
        }
        return evidence;
    }

    @Override
    public void close() throws Exception {
        if (!closed) {
            closed = true;
            model.close();
        }
    }
}
