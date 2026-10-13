package com.chatbot.app;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.LongBuffer;
import java.util.HashMap;
import java.util.Map;

import android.content.res.AssetManager;

import ai.onnxruntime.NodeInfo;
import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OnnxValue;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;
import ai.onnxruntime.TensorInfo;

/** Persistent ONNX Runtime adapter for the exact Silero V5 graph shipped to the Web client. */
final class SileroVadOnnxModel implements SileroVadStream.Model {
    static final String ASSET_NAME = "silero_vad_v5.onnx";
    private static final int SAMPLE_RATE = 16000;
    private static final int STATE_VALUES = 2 * 1 * 128;
    private static final long[] INPUT_SHAPE = {1, SileroVadStream.MODEL_FRAME_SAMPLES};
    private static final long[] STATE_SHAPE = {2, 1, 128};
    private static final long[] SAMPLE_RATE_SHAPE = {1};

    private final OrtEnvironment environment;
    private final OrtSession session;
    private final float[] state = new float[STATE_VALUES];
    private boolean closed;

    private SileroVadOnnxModel(OrtEnvironment environment, OrtSession session) {
        this.environment = environment;
        this.session = session;
    }

    static SileroVadOnnxModel fromAssets(AssetManager assets) throws IOException, OrtException {
        return fromModelBytes(readAsset(assets, ASSET_NAME));
    }

    static SileroVadOnnxModel fromModelBytes(byte[] modelBytes) throws OrtException {
        return create(OrtEnvironment.getEnvironment(), modelBytes);
    }

    private static SileroVadOnnxModel create(OrtEnvironment environment, byte[] modelBytes)
            throws OrtException {
        OrtSession.SessionOptions options = new OrtSession.SessionOptions();
        options.setIntraOpNumThreads(1);
        options.setInterOpNumThreads(1);
        OrtSession session = null;
        try {
            session = environment.createSession(modelBytes, options);
            validateModel(session);
            return new SileroVadOnnxModel(environment, session);
        } catch (OrtException | RuntimeException | LinkageError error) {
            if (session != null) {
                session.close();
            }
            throw error;
        } finally {
            options.close();
        }
    }

    private static void validateModel(OrtSession session) throws OrtException {
        Map<String, NodeInfo> inputs = session.getInputInfo();
        Map<String, NodeInfo> outputs = session.getOutputInfo();
        if (!inputs.keySet().containsAll(java.util.Arrays.asList("input", "state", "sr"))
                || !outputs.keySet().containsAll(java.util.Arrays.asList("output", "stateN"))) {
            throw new OrtException("Bundled Silero V5 model has unexpected tensor names");
        }
        long[] inputShape = ((TensorInfo) inputs.get("input").getInfo()).getShape();
        long[] stateShape = ((TensorInfo) inputs.get("state").getInfo()).getShape();
        if (inputShape.length != 2 || (inputShape[0] != -1 && inputShape[0] != 1)
                || (inputShape[1] != -1
                        && inputShape[1] != SileroVadStream.MODEL_FRAME_SAMPLES)
                || stateShape.length != 3 || (stateShape[0] != -1 && stateShape[0] != 2)
                || (stateShape[1] != -1 && stateShape[1] != 1)
                || (stateShape[2] != -1 && stateShape[2] != 128)) {
            throw new OrtException("Bundled Silero V5 model has unexpected input dimensions");
        }
    }

    @Override
    public float infer(float[] frame) throws OrtException {
        if (closed) {
            throw new IllegalStateException("Silero ONNX session is closed");
        }
        if (frame.length != SileroVadStream.MODEL_FRAME_SAMPLES) {
            throw new IllegalArgumentException("Silero V5 requires 512-sample frames");
        }

        try (OnnxTensor inputTensor = OnnxTensor.createTensor(environment,
                    directFloats(frame), INPUT_SHAPE);
             OnnxTensor stateTensor = OnnxTensor.createTensor(environment,
                    directFloats(state), STATE_SHAPE);
             OnnxTensor sampleRateTensor = OnnxTensor.createTensor(environment,
                    directLongs(new long[] {SAMPLE_RATE}), SAMPLE_RATE_SHAPE)) {
            Map<String, OnnxTensor> inputs = new HashMap<>();
            inputs.put("input", inputTensor);
            inputs.put("state", stateTensor);
            inputs.put("sr", sampleRateTensor);
            try (OrtSession.Result result = session.run(inputs)) {
                float probability = readProbability(result.get("output")
                        .orElseThrow(() -> new OrtException("Silero output is missing")));
                updateState(result.get("stateN")
                        .orElseThrow(() -> new OrtException("Silero recurrent state is missing")));
                return probability;
            }
        }
    }

    private static float readProbability(OnnxValue output) throws OrtException {
        Object value = output.getValue();
        if (!(value instanceof float[][])) {
            throw new OrtException("Silero output has an unexpected tensor shape");
        }
        float[][] values = (float[][]) value;
        if (values.length != 1 || values[0].length != 1) {
            throw new OrtException("Silero output has an unexpected tensor size");
        }
        return values[0][0];
    }

    private void updateState(OnnxValue output) throws OrtException {
        Object value = output.getValue();
        if (!(value instanceof float[][][])) {
            throw new OrtException("Silero recurrent state has an unexpected tensor shape");
        }
        float[][][] values = (float[][][]) value;
        if (values.length != 2 || values[0].length != 1 || values[1].length != 1
                || values[0][0].length != 128 || values[1][0].length != 128) {
            throw new OrtException("Silero recurrent state has an unexpected tensor size");
        }
        for (int layer = 0; layer < 2; layer++) {
            System.arraycopy(values[layer][0], 0, state, layer * 128, 128);
        }
    }

    @Override
    public void close() throws OrtException {
        if (!closed) {
            closed = true;
            java.util.Arrays.fill(state, 0.0f);
            session.close();
        }
    }

    private static FloatBuffer directFloats(float[] values) {
        FloatBuffer buffer = ByteBuffer.allocateDirect(values.length * Float.BYTES)
                .order(ByteOrder.nativeOrder()).asFloatBuffer();
        buffer.put(values).flip();
        return buffer;
    }

    private static LongBuffer directLongs(long[] values) {
        LongBuffer buffer = ByteBuffer.allocateDirect(values.length * Long.BYTES)
                .order(ByteOrder.nativeOrder()).asLongBuffer();
        buffer.put(values).flip();
        return buffer;
    }

    private static byte[] readAsset(AssetManager assets, String name) throws IOException {
        try (InputStream input = assets.open(name)) {
            return readFully(input);
        }
    }

    private static byte[] readFully(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}
