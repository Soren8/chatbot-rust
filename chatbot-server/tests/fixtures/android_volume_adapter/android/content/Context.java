package android.content;

/**
 * Fake android.content.Context leaf for the real volume-adapter harness.
 */
public class Context {
    public Context getApplicationContext() {
        return this;
    }
}
