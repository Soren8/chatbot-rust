import com.chatbot.app.NativeMicCapture;
import java.util.ArrayList;
import java.util.List;

public final class NativeMicCaptureTest {
    private static final int SAMPLE_RATE = 16000;
    /** AudioRecord read error codes. */
    private static final int ERROR = -1;
    private static final int ERROR_BAD_VALUE = -2;
    private static final int ERROR_INVALID_OPERATION = -3;
    private static final int ERROR_DEAD_OBJECT = -6;
    /** Reads allowed before a test source forces the loop to end; a spinning loop hits it. */
    private static final int SPIN_CAP = 1000;

    private static final List<String> failures = new ArrayList<>();

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    /** Scripted AudioRecord: returns each entry in turn (sample count, or a negative error), then 0. */
    private static final class ScriptedSource implements NativeMicCapture.Source {
        final int[] script;
        final List<Integer> requested = new ArrayList<>();
        int reads;
        short next;

        ScriptedSource(int... script) {
            this.script = script;
        }

        boolean running() {
            return reads < SPIN_CAP && reads < script.length + 1;
        }

        @Override
        public int read(short[] buffer, int offset, int length) {
            requested.add(length);
            int result = reads < script.length ? script[reads] : 0;
            reads++;
            for (int i = 0; i < result; i++) {
                buffer[offset + i] = next++;
            }
            return result;
        }
    }

    private static List<byte[]> runCapture(ScriptedSource source, int readSamples, int[] status) {
        List<byte[]> frames = new ArrayList<>();
        status[0] = NativeMicCapture.run(source, readSamples, source::running, frames::add);
        return frames;
    }

    private static void readSizeIsMinBufferBytesAsSamples() {
        check(NativeMicCapture.readSamples(1280) == 640,
                "1280-byte min buffer is 640 16-bit samples, got " + NativeMicCapture.readSamples(1280));
        check(NativeMicCapture.readSamples(1920) == 960,
                "1920-byte min buffer is 960 16-bit samples, got " + NativeMicCapture.readSamples(1920));
        int readMs = NativeMicCapture.readSamples(1280) * 1000 / SAMPLE_RATE;
        check(readMs == 40, "a 1280-byte min buffer must block for 40 ms per read, not " + readMs + " ms");
    }

    private static void loopRequestsTheSizedRead() {
        ScriptedSource source = new ScriptedSource(640);
        int readSamples = NativeMicCapture.readSamples(1280);
        runCapture(source, readSamples, new int[1]);
        for (int length : source.requested) {
            check(length == 640, "every read must request the sized sample count 640, got " + length);
        }
    }

    private static void framesAreTwentyMsLittleEndianAndContiguous() {
        ScriptedSource source = new ScriptedSource(640, 500, 100);
        int[] status = new int[1];
        List<byte[]> frames = runCapture(source, 640, status);
        check(status[0] == 0, "clean stop returns 0, got " + status[0]);
        check(frames.size() == 4, "1240 samples are 3 full frames plus 1 partial, got " + frames.size());
        for (int i = 0; i < 3; i++) {
            check(frames.get(i).length == NativeMicCapture.CHUNK_SAMPLES * 2,
                    "full frame " + i + " is 640 bytes, got " + frames.get(i).length);
        }
        check(frames.get(3).length == 280 * 2, "partial frame flushed at stop is 280 samples");
        int expected = 0;
        for (byte[] frame : frames) {
            for (int i = 0; i < frame.length; i += 2) {
                int sample = (frame[i] & 0xff) | (frame[i + 1] << 8);
                check(sample == expected, "sample " + expected + " out of order or not little-endian: " + sample);
                expected++;
            }
        }
    }

    private static void zeroReadContinues() {
        ScriptedSource source = new ScriptedSource(0, 0, 320);
        int[] status = new int[1];
        List<byte[]> frames = runCapture(source, 640, status);
        check(status[0] == 0, "zero reads are not errors, got " + status[0]);
        check(frames.size() == 1 && frames.get(0).length == 640, "data after zero reads is framed");
    }

    private static void negativeReadEndsCaptureWithoutSpinning(int error) {
        ScriptedSource source = new ScriptedSource(100, error, 640, 640);
        int[] status = new int[1];
        List<byte[]> frames = runCapture(source, 640, status);
        check(source.reads == 2, "read error " + error + " must end the loop after 2 reads, saw " + source.reads);
        check(status[0] == error, "read error " + error + " is returned to the caller, got " + status[0]);
        check(frames.size() == 1 && frames.get(0).length == 200,
                "samples read before error " + error + " are flushed as one partial frame");
    }

    private static void run(String name, Runnable test) {
        try {
            test.run();
            System.out.println("ok " + name);
        } catch (AssertionError e) {
            failures.add(name + ": " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        run("readSizeIsMinBufferBytesAsSamples", NativeMicCaptureTest::readSizeIsMinBufferBytesAsSamples);
        run("loopRequestsTheSizedRead", NativeMicCaptureTest::loopRequestsTheSizedRead);
        run("framesAreTwentyMsLittleEndianAndContiguous", NativeMicCaptureTest::framesAreTwentyMsLittleEndianAndContiguous);
        run("zeroReadContinues", NativeMicCaptureTest::zeroReadContinues);
        for (int error : new int[] { ERROR, ERROR_BAD_VALUE, ERROR_INVALID_OPERATION, ERROR_DEAD_OBJECT }) {
            run("negativeReadEndsCaptureWithoutSpinning(" + error + ")",
                    () -> negativeReadEndsCaptureWithoutSpinning(error));
        }
        if (!failures.isEmpty()) {
            for (String failure : failures) {
                System.err.println("FAIL " + failure);
            }
            System.exit(1);
        }
    }
}
