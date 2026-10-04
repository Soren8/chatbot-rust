import android.media.AudioAttributes;
import android.media.AudioManager;
import android.os.Build;
import com.chatbot.app.audio.AudioFocusCompat;

public final class NativeAudioFocusCompatTest {
    public static void main(String[] args) {
        AudioManager manager = new AudioManager();
        AudioManager.OnAudioFocusChangeListener listener = change -> {};
        AudioAttributes attrs = new AudioAttributes.Builder().build();

        Build.VERSION.SDK_INT = 25;
        AudioFocusCompat.Focus legacy = AudioFocusCompat.request(manager, listener, attrs,
                AudioManager.STREAM_MUSIC);
        if (!legacy.granted || manager.legacyRequests != 1 || manager.modernRequests != 0) {
            throw new AssertionError("API 25 must use and accept legacy focus");
        }
        AudioFocusCompat.abandon(manager, legacy);
        if (manager.legacyAbandons != 1 || manager.modernAbandons != 0) {
            throw new AssertionError("API 25 must abandon through the legacy API");
        }

        Build.VERSION.SDK_INT = 26;
        AudioFocusCompat.Focus modern = AudioFocusCompat.request(manager, listener, attrs,
                AudioManager.STREAM_MUSIC);
        if (!modern.granted || manager.modernRequests != 1) {
            throw new AssertionError("API 26 must use the attributes-based request");
        }
        AudioFocusCompat.abandon(manager, modern);
        if (manager.modernAbandons != 1) {
            throw new AssertionError("API 26 must abandon its matching request");
        }
        System.out.println("API 25 legacy and API 26 attributes-based focus paths passed");
    }
}
