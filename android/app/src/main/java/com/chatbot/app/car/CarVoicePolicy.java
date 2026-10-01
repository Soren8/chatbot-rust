package com.chatbot.app.car;

/** Pure capture, turn-queue and playback-drain decisions for the car voice screen. */
public final class CarVoicePolicy {
    private CarVoicePolicy() {}

    /** Classifies AudioRecord.read results: errors end capture, empty reads back off. */
    public static final class CaptureReads {
        public static final int PROCESS = 0;
        public static final int BACK_OFF = 1;
        public static final int STOP = 2;
        private static final long IDLE_LOG_EVERY = 250;
        private long idleReads;

        public int onRead(int read) {
            if (read < 0) return STOP;
            if (read == 0) { idleReads++; return BACK_OFF; }
            idleReads = 0;
            return PROCESS;
        }

        /** Logs the first empty read of a run, then once per IDLE_LOG_EVERY. */
        public boolean logIdle() {
            return idleReads == 1 || (idleReads > 0 && idleReads % IDLE_LOG_EVERY == 0);
        }
    }

    /** One turn in flight plus at most one pending utterance; newer speech replaces the pending one. */
    public static final class TurnSlot<T> {
        private boolean busy;
        private T pending;

        /** Returns the item to start now, or null when it was held as the pending turn. */
        public synchronized T offer(T item) {
            if (!busy) { busy = true; return item; }
            pending = item;
            return null;
        }

        /** Ends the current turn and returns the pending item to run next, if any. */
        public synchronized T finish() {
            T next = pending;
            pending = null;
            busy = next != null;
            return next;
        }
    }

    /** Blocking writes have already played everything beyond the track buffer. */
    public static long drainMs(long bytesWritten, int bufferBytes, int sampleRate) {
        long buffered = Math.min(bytesWritten, bufferBytes);
        return (buffered / 2 * 1000L) / sampleRate; // 16-bit mono
    }
}
