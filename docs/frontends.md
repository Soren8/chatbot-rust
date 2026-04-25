# Frontend Diversification Plan

## Problem Statement

The web frontend is the only interface. This creates three issues:

1. **Mobile browsers on Android**: Firefox Focus and Brave Mobile block `getUserMedia`, `MediaRecorder`, and WebAudio APIs, breaking voice mode entirely.
2. **Background tabs on desktop**: Browsers suspend `AudioContext` and revoke microphone permissions when tabs are backgrounded, breaking voice mode.
3. **Android Auto integration**: Browser-based apps cannot integrate with Android Auto head unit projection.

## Constraints

- Voice mode uses VAD barge-in (already in `chat.js` with Silero VAD + MediaRecorder).
- Android Auto requires a native `CarAppService` — no framework bypasses this.
- iOS support is low priority but desired as a side effect.
- Existing web UI (`static/chat.js`, ~2000 lines Bootstrap/jQuery) must be reused with minimal changes.
- VAD stays as Silero in Capacitor WebView; native VAD is post-baseline optimization only.
- **Server-pull model**: The app loads web content from the running `chatbot-server` instead of bundling static assets. Any web UI updates are reflected instantly without rebuilding the APK.

## Recommendation: Capacitor Android + Native Android Auto Module

Capacitor wraps the existing web UI in a native Android shell. The WebView loads from the server (not bundled), so the app always shows the latest web UI. Voice mode uses a native Kotlin plugin that captures audio and streams to `/stt`, bypassing browser restrictions. Android Auto is a separate native `CarAppService` implementing a voice-only interface (listen → transcribe → chat → TTS → speak, with an exit button).

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Android Device                         │
│  ┌─────────────────────────────┐    ┌──────────────────────┐  │
│  │     Capacitor WebView       │    │    Android Auto      │  │
│  │  ┌───────────────────────┐  │    │    (Native Java)     │  │
│  │  │  chat.js              │  │    │                      │  │
│  │  │  - Silero VAD         │  │    │  ChatbotCarAppService│  │
│  │  │  - TTS playback       │  │    │  - Voice input       │  │
│  │  │  - Chat UI            │  │    │  - REST calls        │  │
│  │  └───────────┬───────────┘  │    │  - TTS output        │  │
│  │              │              │    │  - Exit button        │  │
│  │              ▼              │    └──────────────────────┘  │
│  │  ┌───────────────────────┐  │                             │
│  │  │  NativeMicPlugin.java │  │                             │
│  │  │  - 16kHz mono PCM    │  │                             │
│  │  │  - base64 to JS bridge│  │                             │
│  │  └───────────────────────┘  │                             │
│  │              │              │                             │
│  │              ▼              │                             │
│  │  ┌───────────────────────┐  │                             │
│  │  │  NativeMicVADBridge   │  │                             │
│  │  │  - ScriptProcessor    │  │                             │
│  │  │  - MediaStreamDest    │  │                             │
│  │  │  - Feeds Silero VAD   │  │                             │
│  │  └───────────────────────┘  │                             │
│  └─────────────────────────────┘                             │
└──────────────────────────────┼────────────────────────────────┘
                               │   REST API
                               ▼
                    ┌──────────────────────┐
                    │   chatbot-server     │
                    │  /stt  /chat  /tts   │
                    └──────────────────────┘
```

### Why not other frameworks?

- **React Native**: Partial web reuse — jQuery/Bootstrap must be ported (~2-4 week rewrite).
- **Flutter**: Zero web reuse — full Dart rewrite (~2-3 months). Platform channel overhead for real-time audio is a concern.
- **All frameworks**: Android Auto always requires a separate native Java module regardless of framework choice.

Capacitor is the only option that preserves the existing web UI unchanged.

## Implementation Phases

### Phase 1: Capacitor Android Shell ✅
**Goal**: Existing web UI runs in native Android app, loaded from server (not bundled).

1. Add Capacitor:
   ```bash
   npm install @capacitor/core @capacitor/cli
   npx cap init "Chatbot" "com.chatbot.app" --web-dir=./static
   npm install @capacitor/android
   npx cap add android
   ```

2. Modify `MainActivity.java` to load from server URL instead of bundled assets:
   - WebView loads `http://<server>:80` on launch
   - Server URL configurable via `server_url` string resource
   - WebView caching disabled for development

3. Configure `AndroidManifest.xml`:
   - `RECORD_AUDIO`, `INTERNET`, `WAKE_LOCK`, `FOREGROUND_SERVICE` permissions
   - `android:exported="true"` for intent filters

4. Build and verify shell app loads and connects to running server.

**Effort**: ~1-2 days.

---

### Phase 2: Native Microphone Plugin (Android) ✅
**Goal**: Voice mode works reliably without browser restrictions.

1. Write `NativeMicPlugin.java`:
   - Uses `AudioRecord` for 16kHz mono PCM capture
   - Sends audio data to JS via Capacitor events (`nativeMicData`)
   - Handles audio focus and wake locks
   - Exposes `window.NativeMic.start()` / `stop()` / `isRecording()` to web layer

2. `NativeMicVADBridge` class in `chat.js`:
   - Creates AudioContext + ScriptProcessorNode + MediaStreamDestination
   - Feeds native mic chunks (base64 → Float32) through queue to ScriptProcessorNode
   - ScriptProcessorNode outputs to MediaStreamDestination's stream
   - Silero VAD's `createVAD()` receives the stream with custom `getStream` override
   - Handles onSpeechStart, onSpeechEnd callbacks

**Key Bug Fixed**: Silero VAD's `start()` internally calls `navigator.mediaDevices.getUserMedia()` even when a stream is passed, so the `getStream` override was required. Also, after speech detection, calling `pause()`/`start()` or `destroy()`/`createVAD()` on the VAD broke subsequent detection — the VAD must be left running continuously without interruption.

**Effort**: ~1 week.

---

### Phase 3: Android Auto Module ✅
**Goal**: App appears on AA head unit as a voice-only interface.

1. Implement `CarAppService` in Java:
   - `ChatbotCarAppService` with `onCreateSession()` returning `VoiceSession`
   - `VoiceScreen` with listening indicator and Exit button
   - Voice input via Android `SpeechRecognizer`
   - REST calls: `/chat` → response, `/tts` → `/tts_stream` → audio playback
   - Exit button terminates session and closes AA UI

2. Manifest declarations:
   - `android:autoContents="true"`
   - `androidx.car.app.category.POINT_OF_INTEREST`
   - `android:exported="true"` on CarAppService
   - `car_app_supported_types` array with `GenericDeprecated`

**Effort**: ~1 week.

---

### Phase 4: iOS Support (Low Priority)
**Goal**: Same codebase builds for iOS.

1. `npx cap add ios`
2. Write Swift `NativeMicPlugin` (same pattern as Android)
3. Configure `audio` background mode in `Info.plist`
4. `npx cap build ios`

**Effort**: ~1 day (after Android is done).

---

## Server-Pull Model

The app does NOT bundle `static/` files. Instead, the WebView loads directly from the running `chatbot-server`. This means:

- Web UI updates (chat.js, CSS, templates) appear instantly without rebuilding the APK
- The device must have network access to the server (same WiFi or port-forwarded)
- For car use, the server URL should point to the machine running `chatbot-server`
- Default URL is `http://10.0.2.2:80` (Android emulator's host loopback)

**Note**: WebView caching is disabled in `MainActivity.onStart()` via `setCacheMode(LOAD_NO_CACHE)` to ensure fresh loads during development.

---

## VAD Implementation Notes

### Silero VAD in Capacitor WebView

Silero VAD runs in the Capacitor WebView with a native mic bridge. Key implementation details:

1. **NativeMicPlugin.java** captures 16kHz mono PCM via `AudioRecord` and sends base64-encoded chunks to JS via `notifyListeners('nativeMicData', ...)`

2. **NativeMicVADBridge** (chat.js):
   - Creates an `AudioContext` with `ScriptProcessorNode` (4096 samples = 256ms at 16kHz)
   - Creates `MediaStreamDestination` and connects the ScriptProcessor to it
   - On receiving native audio chunks, converts Int16 → Float32 and pushes to a queue
   - The ScriptProcessor drains the queue into its output buffer (silence when queue is empty)
   - The resulting stream is passed to Silero VAD via `createVAD(stream)` with `getStream` override

3. **Critical VAD behavior**: After `onSpeechEnd` fires, the VAD must be left running. Calling `pause()`/`start()` causes Silero to internally call `getUserMedia` (fails in Android WebView). Calling `destroy()` and recreating the VAD also breaks subsequent detection. Simply letting the VAD run continuously works correctly — it naturally detects the next speech onset.

### VAD Evaluation

Car environments are noisy. After Phase 2 delivery, test VAD accuracy. If it misses too often:
- Adjust Silero thresholds (`positiveSpeechThreshold`, `minSpeechFrames`)
- Or implement native Kotlin VAD plugin using ONNX Runtime Mobile

Native VAD is **not in scope** for initial delivery.

---

## Build Instructions

Prerequisites: Java 21+, Android SDK (command-line tools or Android Studio)

```bash
# Build Android APK
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/home/malakar/Android/Sdk
cd android && ./gradlew assembleDebug

# APK location
android/app/build/outputs/apk/debug/app-debug.apk

# Install via adb
/home/malakar/Android/Sdk/platform-tools/adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

For production builds, configure the server URL in `res/values/strings.xml` before building.

---

## Files Created/Modified

| File | Action |
|------|--------|
| `docs/frontends.md` | Create — this document |
| `docs/design.md` | Modify — add frontends reference |
| `capacitor.config.json` | Create |
| `package.json` | Create |
| `android/` | Create — Capacitor Android project |
| `android/.../MainActivity.java` | Modify — server-pull WebView, disable cache |
| `android/.../AndroidManifest.xml` | Modify — audio permissions, CarAppService |
| `android/.../NativeMic/NativeMicPlugin.java` | Create — native mic capture |
| `android/.../car/ChatbotCarAppService.java` | Create — Android Auto entry |
| `android/.../car/VoiceSession.java` | Create — Android Auto session |
| `android/.../car/VoiceScreen.java` | Create — Android Auto UI |
| `android/.../Logger/LoggerPlugin.java` | Create — native logging to adb |
| `res/values/strings.xml` | Modify — server_url |
| `res/values/arrays.xml` | Create — car_app_supported_types |
| `static/chat.js` | Modify — NativeMicVADBridge, voice mode |
| `.gitignore` | Modify — exclude Capacitor build artifacts |

---

## Summary

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Capacitor Android shell (server-pull) | ✅ Complete |
| 2 | Native mic plugin + NativeMicVADBridge | ✅ Complete |
| 3 | Android Auto voice module | ✅ Complete |
| 4 | iOS build (same codebase) | Pending |

**Total**: ~2-3 weeks for full Android delivery. iOS nearly free after.
