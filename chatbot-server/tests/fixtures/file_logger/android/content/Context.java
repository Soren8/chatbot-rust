package android.content;

import java.io.File;

/** Minimal stub of android.content.Context for the FileLogger harness. */
public class Context {
    private final File filesDir;

    public Context(File filesDir) {
        this.filesDir = filesDir;
    }

    public File getExternalFilesDir(String type) {
        return null;
    }

    public File getFilesDir() {
        return filesDir;
    }
}
