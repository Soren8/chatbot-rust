package com.chatbot.app;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

public class SileroVadStreamTest {
    @Test
    public void accumulatesTwentyMillisecondPcmIntoPersistentThirtyTwoMillisecondFrames() throws Exception {
        RecordingModel model = new RecordingModel();
        SileroVadStream stream = new SileroVadStream(model);

        assertFalse(stream.accept(pcmFrame(320, 0)).hasScore());
        SileroVadStream.Evidence first = stream.accept(pcmFrame(320, 320));
        assertTrue(first.hasScore());
        assertEquals(0.61f, first.probability(), 0.0001f);
        assertEquals(32, first.durationMs());
        assertEquals(1, model.inputFrames.size());
        assertEquals(512, model.inputFrames.get(0).length);

        assertFalse(stream.accept(pcmFrame(320, 640)).hasScore());
        SileroVadStream.Evidence second = stream.accept(pcmFrame(320, 960));
        assertTrue(second.hasScore());
        assertEquals(0.72f, second.probability(), 0.0001f);
        assertEquals(32, second.durationMs());
        assertEquals(2, model.inputFrames.size());
        assertEquals(512, model.inputFrames.get(1).length);
        assertEquals(0f, model.inputFrames.get(0)[0], 0.0001f);
        assertEquals(511f / 32768f, model.inputFrames.get(0)[511], 0.0001f);
        assertEquals(512f / 32768f, model.inputFrames.get(1)[0], 0.0001f);
        assertEquals(1023f / 32768f, model.inputFrames.get(1)[511], 0.0001f);
        assertEquals("the session remains open across adjacent frames", 0, model.closeCount);
        stream.close();
        assertEquals(1, model.closeCount);
    }

    @Test
    public void resetClosesOldModelAndStartsWithNoBufferedSamplesOrRecurrentHistory() throws Exception {
        RecordingModel firstModel = new RecordingModel();
        SileroVadStream first = new SileroVadStream(firstModel);
        first.accept(pcmFrame(320, 0));
        first.close();
        assertEquals(1, firstModel.closeCount);

        RecordingModel restartedModel = new RecordingModel();
        SileroVadStream restarted = new SileroVadStream(restartedModel);
        SileroVadStream.Evidence evidence = restarted.accept(pcmFrame(320, 0));
        assertFalse(evidence.hasScore());
        assertNotSame(first, restarted);
        assertEquals(0, restartedModel.inputFrames.size());

        restarted.close();
        assertEquals(1, restartedModel.closeCount);
    }

    @Test
    public void shippedOnnxModelRunsRealInferenceAndAReopenedSessionResetsItsState() throws Exception {
        String modelPath = System.getProperty("chatbot.sileroModelPath");
        assertNotNull("Gradle must provide the path to the shipped Silero model", modelPath);

        float firstScore = scoreSilenceFromFreshModel(modelPath);
        assertTrue("silence should remain below the shipped positive threshold", firstScore < 0.3f);

        float restartedScore = scoreSilenceFromFreshModel(modelPath);
        assertEquals(firstScore, restartedScore, 0.000001f);
    }

    private static float scoreSilenceFromFreshModel(String modelPath) throws Exception {
        SileroVadOnnxModel model = SileroVadOnnxModel.fromModelBytes(
                Files.readAllBytes(Paths.get(modelPath)));
        SileroVadStream stream = new SileroVadStream(model);
        try {
            assertFalse(stream.accept(silencePcm(320)).hasScore());
            SileroVadStream.Evidence evidence = stream.accept(silencePcm(320));
            assertTrue(evidence.hasScore());
            assertEquals(32, evidence.durationMs());
            float firstScore = evidence.probability();
            assertFalse(stream.accept(silencePcm(320)).hasScore());
            SileroVadStream.Evidence continued = stream.accept(silencePcm(320));
            assertTrue(continued.hasScore());
            assertTrue(Float.isFinite(continued.probability()));
            return firstScore;
        } finally {
            stream.close();
        }
    }

    private static byte[] silencePcm(int length) {
        return new byte[length * 2];
    }

    private static byte[] pcmFrame(int length, int firstSample) {
        ByteBuffer pcm = ByteBuffer.allocate(length * 2).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < length; i++) {
            pcm.putShort((short) (firstSample + i));
        }
        return pcm.array();
    }

    private static final class RecordingModel implements SileroVadStream.Model {
        private final List<float[]> inputFrames = new ArrayList<>();
        private int closeCount;

        @Override
        public float infer(float[] frame) {
            inputFrames.add(frame.clone());
            return inputFrames.size() == 1 ? 0.61f : 0.72f;
        }

        @Override
        public void close() {
            closeCount++;
        }
    }
}
