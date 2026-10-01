import android.content.Context;
import com.chatbot.app.util.FileLogger;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.regex.Pattern;

/** The on-disk log must stay bounded and every line must keep its timestamp under concurrency. */
public final class FileLoggerCapTest {
    private static final Pattern LINE = Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3} \\[[^\\]]+\\] .*");

    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("file_logger_cap").toFile();
        FileLogger.init(new Context(root));
        File logs = new File(root, "logs");
        File active = new File(logs, "chatbot_auto.log");
        if (!active.isFile()) throw new AssertionError("init must create the log under the internal-storage fallback");

        String payload = "x".repeat(200);
        int threads = 4;
        int perThread = 8000;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            int id = t;
            workers[t] = new Thread(() -> {
                for (int i = 0; i < perThread; i++) FileLogger.log("T" + id, i + " " + payload);
            });
            workers[t].start();
        }
        for (Thread worker : workers) worker.join();
        FileLogger.log("Final", "last line");

        long written = (long) threads * perThread * 230;
        long onDisk = 0;
        File[] files = logs.listFiles();
        for (File f : files) onDisk += f.length();
        if (onDisk > 4L * 1024 * 1024 || onDisk >= written / 2) {
            throw new AssertionError("log directory grew unbounded: " + onDisk + " bytes on disk for ~"
                    + written + " bytes logged across " + files.length + " files");
        }

        List<String> lines = Files.readAllLines(active.toPath(), StandardCharsets.UTF_8);
        if (lines.isEmpty() || !lines.get(lines.size() - 1).endsWith("[Final] last line")) {
            throw new AssertionError("the newest line must be in the active log file");
        }
        for (File f : files) {
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                if (!LINE.matcher(line).matches()) throw new AssertionError("malformed line in " + f.getName() + ": " + line);
            }
        }
        List<String> ring = FileLogger.snapshotLines();
        if (ring.size() != 150 || !ring.get(ring.size() - 1).endsWith("[Final] last line")) {
            throw new AssertionError("ring history must keep the most recent 150 lines");
        }
        System.out.println("file log bounded: " + onDisk + " bytes in " + files.length + " files");
    }
}
