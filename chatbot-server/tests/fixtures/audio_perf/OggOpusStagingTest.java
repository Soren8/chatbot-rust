package com.chatbot.app.audio;

import io.github.jaredmdobson.concentus.OpusDecoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * OggOpusStreamDecoder must produce identical PCM for any chunking and must
 * not retain (or re-copy) the whole stream: parsed pages are consumed.
 */
public final class OggOpusStagingTest {
    private static final int PRESKIP = 312;

    public static void main(String[] args) throws Exception {
        List<byte[]> small = packets(120);
        byte[] smallStream = stream(small, 48000);
        byte[] expected48 = pcmBytes(reference48(small));
        check("48k whole", expected48, decode(smallStream, smallStream.length, 48000));
        check("48k 2KB", expected48, decode(smallStream, 2048, 48000));
        check("48k 1B", expected48, decode(smallStream, 1, 48000));

        byte[] smallStream24 = stream(small, 24000);
        byte[] expected24 = pcmBytes(decimate(reference48(small), 2));
        check("24k whole", expected24, decode(smallStream24, smallStream24.length, 24000));
        check("24k 2KB", expected24, decode(smallStream24, 2048, 24000));
        check("24k 7B", expected24, decode(smallStream24, 7, 24000));

        OggOpusStreamDecoder truncated = new OggOpusStreamDecoder();
        truncated.feed(smallStream24, smallStream24.length - 10);
        truncated.finish();
        if (!truncated.hasIncompleteData()) throw new AssertionError("truncated stream must be flagged");

        OggOpusStreamDecoder garbage = new OggOpusStreamDecoder();
        try {
            garbage.feed(new byte[64], 64);
            throw new AssertionError("non-Ogg input must be rejected");
        } catch (IOException expectedFailure) {
            if (!expectedFailure.getMessage().contains("not an Ogg stream")) throw expectedFailure;
        }

        byte[] large = stream(packets(16000), 24000);
        OggOpusStreamDecoder decoder = new OggOpusStreamDecoder();
        long pcmTotal = 0;
        long maxRetained = 0;
        for (int off = 0; off < large.length; off += 2048) {
            int n = Math.min(2048, large.length - off);
            decoder.feed(Arrays.copyOfRange(large, off, off + n), n);
            pcmTotal += decoder.takePcm().length;
            maxRetained = Math.max(maxRetained, retainedBytes(decoder));
        }
        decoder.finish();
        if (decoder.hasIncompleteData()) throw new AssertionError("complete stream flagged incomplete");
        if (pcmTotal == 0) throw new AssertionError("large stream produced no PCM");
        if (maxRetained > 128 * 1024) {
            throw new AssertionError("decoder retained " + maxRetained + " bytes for a "
                    + large.length + "-byte stream; parsed pages must be consumed");
        }
        System.out.println("ogg staging bounded: stream=" + large.length + " maxRetained=" + maxRetained);
    }

    private static void check(String label, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(label + ": PCM mismatch (expected " + expected.length
                    + " bytes, got " + actual.length + ")");
        }
    }

    private static byte[] decode(byte[] stream, int chunk, int rate) throws IOException {
        OggOpusStreamDecoder decoder = new OggOpusStreamDecoder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int off = 0; off < stream.length; off += chunk) {
            int n = Math.min(chunk, stream.length - off);
            byte[] buf = new byte[chunk + 3];
            System.arraycopy(stream, off, buf, 0, n);
            decoder.feed(buf, n);
            out.write(decoder.takePcm());
        }
        decoder.finish();
        out.write(decoder.takePcm());
        if (decoder.sampleRate() != rate || !decoder.sawOpusHead() || !decoder.sawEndOfStream()
                || decoder.hasIncompleteData()) {
            throw new AssertionError("decoder state wrong after complete " + rate + " stream");
        }
        return out.toByteArray();
    }

    /** Sum of byte buffers the decoder keeps alive between feeds. */
    private static long retainedBytes(OggOpusStreamDecoder decoder) throws Exception {
        long total = 0;
        for (Field field : OggOpusStreamDecoder.class.getDeclaredFields()) {
            field.setAccessible(true);
            Object value = field.get(decoder);
            if (value instanceof byte[]) {
                total += ((byte[]) value).length;
            } else if (value instanceof ByteArrayOutputStream) {
                Field buf = ByteArrayOutputStream.class.getDeclaredField("buf");
                buf.setAccessible(true);
                total += ((byte[]) buf.get(value)).length;
            }
        }
        return total;
    }

    private static List<byte[]> packets(int count) {
        List<byte[]> out = new ArrayList<>();
        for (int p = 0; p < count; p++) {
            byte[] packet = new byte[60 + (p * 37) % 190];
            for (int i = 0; i < packet.length; i++) packet[i] = (byte) (p * 31 + i * 7);
            out.add(packet);
        }
        return out;
    }

    private static short[] reference48(List<byte[]> packets) {
        short[] all = new short[packets.size() * OpusDecoder.FRAME_SAMPLES];
        int pos = 0;
        for (byte[] packet : packets) {
            for (int i = 0; i < OpusDecoder.FRAME_SAMPLES; i++) {
                all[pos++] = OpusDecoder.sample(packet, 0, packet.length, i);
            }
        }
        return Arrays.copyOfRange(all, PRESKIP, all.length);
    }

    /** Non-streaming Blackman-sinc decimator: y[j] = sum coef[k] * x[delay + j*factor - k]. */
    private static short[] decimate(short[] x, int factor) {
        int taps = 64 * factor + 1;
        int delay = (taps - 1) / 2;
        double fc = 0.5 / factor;
        double[] h = new double[taps];
        double sum = 0.0;
        for (int n = 0; n < taps; n++) {
            int d = n - delay;
            double v = d == 0 ? 2.0 * fc : Math.sin(2.0 * Math.PI * fc * d) / (Math.PI * d);
            double w = 0.42 - 0.5 * Math.cos(2.0 * Math.PI * n / (taps - 1))
                    + 0.08 * Math.cos(4.0 * Math.PI * n / (taps - 1));
            h[n] = v * w;
            sum += h[n];
        }
        int[] coef = new int[taps];
        for (int n = 0; n < taps; n++) coef[n] = (int) Math.round(h[n] / sum * 32768.0);
        List<Short> out = new ArrayList<>();
        for (long c = delay; c < x.length; c += factor) {
            long acc = 0;
            for (int k = 0; k < taps; k++) {
                long idx = c - k;
                if (idx >= 0) acc += (long) coef[k] * x[(int) idx];
            }
            int y = (int) (acc >> 15);
            y = Math.max(-32768, Math.min(32767, y));
            out.add((short) y);
        }
        short[] result = new short[out.size()];
        for (int i = 0; i < result.length; i++) result[i] = out.get(i);
        return result;
    }

    private static byte[] pcmBytes(short[] samples) {
        byte[] out = new byte[samples.length * 2];
        for (int i = 0; i < samples.length; i++) {
            out[2 * i] = (byte) (samples[i] & 0xFF);
            out[2 * i + 1] = (byte) ((samples[i] >> 8) & 0xFF);
        }
        return out;
    }

    private static byte[] stream(List<byte[]> audio, int rate) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = new byte[19];
        System.arraycopy("OpusHead".getBytes(), 0, head, 0, 8);
        head[8] = 1;
        head[9] = 1;
        head[10] = (byte) (PRESKIP & 0xFF);
        head[11] = (byte) (PRESKIP >> 8);
        head[12] = (byte) rate;
        head[13] = (byte) (rate >> 8);
        head[14] = (byte) (rate >> 16);
        head[15] = (byte) (rate >> 24);
        int seq = 0;
        page(out, 0x02, seq++, List.of(head));
        page(out, 0x00, seq++, List.of("OpusTags\0\0\0\0\0\0\0\0".getBytes()));
        List<byte[]> pending = new ArrayList<>();
        int bytes = 0;
        for (int i = 0; i < audio.size(); i++) {
            pending.add(audio.get(i));
            bytes += audio.get(i).length;
            boolean last = i == audio.size() - 1;
            if (bytes >= 4000 || pending.size() == 200 || last) {
                page(out, last ? 0x04 : 0x00, seq++, pending);
                pending = new ArrayList<>();
                bytes = 0;
            }
        }
        return out.toByteArray();
    }

    private static void page(ByteArrayOutputStream out, int headerType, int seq, List<byte[]> packets) {
        byte[] header = new byte[27 + packets.size()];
        System.arraycopy("OggS".getBytes(), 0, header, 0, 4);
        header[5] = (byte) headerType;
        header[14] = 0x2A;
        header[15] = 0x13;
        header[18] = (byte) seq;
        header[19] = (byte) (seq >> 8);
        header[26] = (byte) packets.size();
        for (int i = 0; i < packets.size(); i++) {
            if (packets.get(i).length >= 255) throw new IllegalStateException("fixture packets stay single-segment");
            header[27 + i] = (byte) packets.get(i).length;
        }
        out.write(header, 0, header.length);
        for (byte[] packet : packets) out.write(packet, 0, packet.length);
    }
}
