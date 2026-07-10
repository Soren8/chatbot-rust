# Frontend Diversification Plan

## Problem Statement

The web frontend is the only interface. This creates three issues:

1. **Mobile browsers on Android**: Firefox Focus and Brave Mobile block `getUserMedia`, `MediaRecorder`, and WebAudio APIs, breaking voice mode entirely.
2. **Background tabs on desktop**: Browsers suspend `AudioContext` and revoke microphone permissions when tabs are backgrounded, breaking voice mode.
3. **Android Auto integration**: Browser-based apps cannot integrate with Android Auto head unit projection.

## Constraints

- Voice mode uses VAD barge-in: Silero on desktop/browser; RMS (`NativeMicUtteranceVAD`) on Capacitor + Android Auto.
- Android Auto requires a native `CarAppService` — no framework bypasses this.
- iOS support is low priority but desired as a side effect.
- Existing web UI (`static/chat.js`, Bootstrap/jQuery) must be reused with minimal changes.
- **Server-pull model**: The app loads web content from the running `chatbot-server` instead of bundling static assets. Web UI updates do not require rebuilding the APK, but they **do** require rebuilding the `webserver` Docker image (`docker compose up --build -d webserver`) because `static/` is baked into the image.

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
│  │  │  - NativeMicUtterance │  │    │  ChatbotCarAppService│  │
│  │  │    VAD (RMS)          │  │    │  - Voice input (RMS) │  │
│  │  │  - NativeVoiceTts     │  │    │  - REST / TTS        │  │
│  │  │  - Chat UI            │  │    │  - Exit button        │  │
│  │  └───────────┬───────────┘  │    └──────────────────────┘  │
│  │              │              │                             │
│  │              ▼              │                             │
│  │  ┌───────────────────────┐  │                             │
│  │  │  NativeMicPlugin.java │  │                             │
│  │  │  - 16kHz mono PCM     │  │                             │
│  │  │  - VOICE_COMMUNICATION│  │                             │
│  │  └───────────────────────┘  │                             │
│  │  Desktop browser: Silero VAD (not shown)                  │
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
   - Uses `AudioRecord` for 16kHz mono PCM capture (`VOICE_COMMUNICATION` for hardware AEC/NS/AGC)
   - Sends fixed 20 ms frames to JS via Capacitor events (`nativeMicData`)
   - Handles audio focus and wake locks
   - Exposes `window.NativeMic.start()` / `stop()` / `isRecording()` to web layer

2. `NativeMicUtteranceVAD` in `chat.js` (shipped path — **RMS-only**, not Silero):
   - Operates on native PCM chunks; no WebView `AudioContext` / Silero on the native path
   - 600 ms PCM pre-roll; skips utterance detection during TTS; RMS barge-in while TTS plays
   - 400 ms cooldown after TTS before listening resumes
   - `NativeVoiceTtsPlugin` plays `/tts_stream/{token}` via `AudioTrack` + `USAGE_VOICE_COMMUNICATION` so AEC tracks TTS

3. Desktop/browser still uses Silero VAD (`static/deps/vad/`) with `getUserMedia` when not on Capacitor.

**Key Bugs Fixed**:
1. Early experiments feeding Silero via ScriptProcessor/`NativeMicVADBridge` were abandoned on native: Silero + WebView audio breaks during TTS; RMS matches Android Auto `VoiceScreen`.
2. After speech detection, restarting Silero (`pause`/`start` or recreate) broke subsequent detection on WebView — native path avoids Silero entirely.
3. `AudioSource.MIC` captured speaker output causing TTS self-loop. Solution: `AudioSource.VOICE_COMMUNICATION` + voice-communication TTS usage.

**Effort**: ~1 week.

---

### Phase 3: Android Auto Module ✅
**Goal**: App appears on AA head unit as a voice-only interface.

1. Implement `CarAppService` in Java:
   - `ChatbotCarAppService` with `onCreateSession()` returning `VoiceSession`
   - `VoiceScreen` with listening indicator and Exit button
   - Voice input via native `AudioRecord` + RMS VAD (not `SpeechRecognizer`)
   - REST calls: `/chat` → response, `/tts` → `/tts_stream` → audio playback
   - Exit button terminates session and closes AA UI

2. Manifest declarations (per [Car App Library setup](https://developer.android.com/training/cars/apps/library/set-up-project)):
   - `com.google.android.gms.car.application` meta-data → `@xml/automotive_app_desc`
   - `automotive_app_desc.xml` must declare `<uses name="template"/>` (not `audio`)
   - `CarAppService` intent-filter with `androidx.car.app.category.POI`
   - `androidx.car.app.minCarApiLevel` meta-data on the service
   - `android:exported="true"` on CarAppService
   - Dependencies: `androidx.car.app:app` + `androidx.car.app:app-projected`

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

- Web UI updates (chat.js, CSS, templates) do not require rebuilding the APK; rebuild `webserver` to pick up static changes in the running server.
- The device must have network access to the server (same WiFi or port-forwarded)
- For car use, the server URL should point to the machine running `chatbot-server`
- Default URL is `http://10.0.2.2:80` (Android emulator's host loopback) for emulator flavor, `http://desktop-1.tailfc0df0.ts.net:80` for production flavor. These http URLs are for the native app (which derives/stores keys via the OS plugin and does not rely on browser secure context). For any browser-based testing, use http://localhost or a https URL.
- Server URL is read from the `server_url` string resource (flavor-specific) and passed to `VoiceScreen` via `CarContext.getString(R.string.server_url)`

**Note**: WebView caching is disabled in `MainActivity.onStart()` via `setCacheMode(LOAD_NO_CACHE)` to ensure fresh loads during development.

---

## VAD Implementation Notes

### Native (Capacitor) vs desktop VAD

1. **NativeMicPlugin.java** — 16kHz mono PCM via `AudioRecord` (`VOICE_COMMUNICATION`, AEC/NS/**AGC**), 20 ms frames → `nativeMicData`.

2. **`static/native-audio.js`** — PCM16 WAV helpers for STT upload and related buffering.

3. **`NativeMicUtteranceVAD`** (chat.js) — RMS-only on native PCM (same approach as `VoiceScreen.java`):
   - No Silero / WebView `AudioContext` on the native path
   - **600 ms PCM pre-roll**; skip utterance start during TTS; RMS barge-in; **400 ms** post-TTS cooldown

4. **`NativeVoiceTtsPlugin.java`** — `/tts_stream/{token}` via `AudioTrack` + `USAGE_VOICE_COMMUNICATION` so hardware AEC cancels TTS (HTML `<audio>` uses the media route and breaks AEC).

5. **Desktop/browser**: Silero VAD remains. After `onSpeechEnd`, leave Silero running or reinitialize carefully; `pause()`/`start()` is OK on desktop. Do not rely on Silero restart behavior inside Android WebView.

### VAD Evaluation

Car environments are noisy. If RMS misses too often:
- Tune RMS thresholds / hangover in `NativeMicUtteranceVAD` / `VoiceScreen`
- Or implement a native Kotlin VAD (ONNX Runtime Mobile) — still optional, not baseline

---

## Android Auto: testing and distribution

This app uses the **Android for Cars App Library** (`CarAppService`, `PaneTemplate`). That choice has strict distribution rules that affect day-to-day development.

### Sideload does not work on real Android Auto (even parked)

Per [Test Android apps for cars](https://developer.android.com/training/cars/testing):

- On a **real** Android Auto session (phone AA UI or car projection), the app must be installed from a **trusted source** (Google Play or Play-internal distribution).
- AA developer setting **Unknown sources** applies only to **media**, **messaging notifications**, and **parked** apps — **not** to Car App Library apps.
- Enabling Unknown sources while parked does **not** make a sideloaded (`adb install`) build appear in the AA launcher. This is Google platform policy, not a project manifest bug.

**Observed:** Wired AA works for other apps; a debug APK installed via `adb` never appears in AA customize/launcher, with or without Unknown sources.

**Workaround for phone/car testing:** [Internal App Sharing](https://play.google.com/console/about/internalappsharing/) or an [internal testing track](https://play.google.com/console/about/internal-testing/) — Play-signed install without a public store listing or full review per iteration.

**Fast local iteration:** Desktop Head Unit (DHU) or AVD-based flows below (sideload is fine there).

### Three testing setups (do not mix install instructions)

| Setup | Where DHU runs | Where Android Auto + your APK run | APK flavor | Connection |
|-------|----------------|-----------------------------------|------------|------------|
| **A. AVD + DHU** (recommended dev loop) | Dev PC | Same Android emulator | `emulator` (`10.0.2.2`) | `adb forward tcp:5277 tcp:5277` (no USB to phone) |
| **B. Physical phone + DHU** | Dev PC | Physical phone | `production` (or dev server URL) | Wireless `adb connect` + `adb forward` — USB not required; avoid DHU `--usb` (libusb) |
| **C. Real car / phone AA UI** | N/A (real head unit or AA on phone) | Physical phone | Any | Wired AA; install via **Play internal**, not `adb install` |

**DHU architecture (clarification):** DHU emulates the **head unit on the PC**. Android Auto still runs on the **phone or AVD** (head-unit server on port 5277). Your **Chatbot APK must be installed on that device** — you are not installing DHU on the phone. Default connection is **ADB tunneling** (`adb forward`), not USB accessory mode.

### A. Emulator + DHU (all on dev PC)

Community-documented path when USB or GrapheneOS complicates phone testing ([reference](https://stackoverflow.com/questions/76482834/can-we-test-android-auto-purely-in-emulators-2023)):

1. SDK Manager → install **Android Auto Desktop Head Unit Emulator** (`extras/google/auto`).
2. Create AVD with Google APIs / Play image (x86_64; API 33+ reported working).
3. Sideload **Android Auto** (`com.google.android.projection.gearhead`) onto the AVD if not present (Play image or x86_64 APK).
4. Enable emulator developer options and **Android Auto developer mode** (tap AA version ~10× in AA settings).
5. AA settings → **Start head unit server** (developer menu).
6. `adb install` Chatbot APK (`assembleEmulatorDebug`).
7. `adb forward tcp:5277 tcp:5277`
8. Run `$ANDROID_HOME/extras/google/auto/desktop-head-unit` on the PC (Linux/Wayland may need `SDL_VIDEODRIVER=x11`).

Open Chatbot from the **DHU launcher window on the PC**, not the phone launcher.

### B. Physical phone + DHU

1. Install/update **Android Auto** on the phone (on GrapheneOS: **Sandboxed Google Play**).
2. Enable AA developer mode; optionally **Start head unit server** for ADB tunneling.
3. `adb connect <phone-ip>:5555` (wireless ADB is sufficient — no working USB cable needed).
4. `adb install` production/debug APK.
5. `adb forward tcp:5277 tcp:5277`
6. Run `desktop-head-unit` on the PC (default `--adb`, not `--usb`).

Sideload may work for DHU even when the app never appears in real AA (setup C).

### C. Real vehicle or phone Android Auto UI

- Requires Play-trusted install (internal sharing/track).
- **GrapheneOS:** Wired AA often works well for Play-distributed apps; grant Sandboxed Play / AA permissions as needed. Sideloaded Car App builds still will not list in AA (same CAL policy as stock Android). Extra friction for non-Play apps (installer checks) is documented in [GrapheneOS#3257](https://github.com/GrapheneOS/os-issue-tracker/issues/3257); CAL sideload exemption does not exist on stock either.
- Wireless AA on GrapheneOS is commonly less stable than wired ([issue tracker](https://github.com/GrapheneOS/os-issue-tracker/issues?q=android+auto)).

### Manifest checklist (real AA / DHU discovery)

Already configured in this repo; if the app is missing everywhere, verify:

- `automotive_app_desc.xml`: `<uses name="template"/>` (not `audio` alone)
- `CarAppService` intent-filter: `androidx.car.app.category.POI`
- `com.google.android.gms.car.application` meta-data
- `androidx.car.app.minCarApiLevel` on the service
- Dependencies: `androidx.car.app:app` and `androidx.car.app:app-projected`

`HostValidator.ALLOW_ALL_HOSTS_VALIDATOR` is for local/DHU only; use a production `HostValidator` before Play release.

**Play Store note:** POI apps must meet [car app quality guidelines](https://developer.android.com/docs/quality-guidelines/car-app-quality). A voice chatbot is a stretch for the POI category; internal Play distribution is still required for real AA even when not publishing publicly.

## Build Instructions

Prerequisites: **JDK 21** (not 25+), Android SDK (command-line tools or Android Studio)

Pinned versions (do not bump casually — library compatibility breaks on newer JDKs/AGP):
- Gradle **8.14.3** (`gradle/wrapper/gradle-wrapper.properties`)
- Android Gradle Plugin **8.13.0** (`build.gradle`)
- Java bytecode **21** (Capacitor-generated `capacitor.build.gradle`)

```bash
# Recommended: wrapper script picks JDK 21 automatically
cd android && ./build-apk.sh production

# Or explicit JDK + Gradle
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/home/malakar/Android/Sdk
cd android && ./gradlew assembleProductionDebug

# Build Android APK (emulator flavor)
cd android && ./build-apk.sh emulator

# APK locations
android/app/build/outputs/apk/production/debug/app-production-debug.apk
android/app/build/outputs/apk/emulator/debug/app-emulator-debug.apk

# Install via adb
/home/malakar/Android/Sdk/platform-tools/adb install -r android/app/build/outputs/apk/production/debug/app-production-debug.apk
```

Product flavors configure `server_url` string resource:
- **emulator**: `http://10.0.2.2:80` (Android emulator's host loopback)
- **production**: `http://desktop-1.tailfc0df0.ts.net:80`

`network_security_config.xml` allows cleartext HTTP for emulator IP and tailscale domains (required for native; the app does not use Web Crypto secure context paths on mobile). For browser dev against the server, prefer localhost or https (e.g. Tailscale Serve).

---

## Files Created/Modified

| File | Action |
|------|--------|
| `docs/mobile-apps.md` | Create — this document |
| `docs/design.md` | Modify — add mobile-apps reference |
| `capacitor.config.json` | Create — root config, synced to `android/app/src/main/assets/` after changes |
| `package.json` | Create |
| `android/` | Create — Capacitor Android project |
| `android/.../MainActivity.java` | Modify — server-pull WebView, disable cache, register plugins |
| `android/.../AndroidManifest.xml` | Modify — audio permissions, CarAppService |
| `android/.../NativeMic/NativeMicPlugin.java` | Create — native mic capture with `VOICE_COMMUNICATION` source |
| `android/.../car/ChatbotCarAppService.java` | Create — Android Auto entry |
| `android/.../car/VoiceSession.java` | Create — Android Auto session |
| `android/.../car/VoiceScreen.java` | Create — Android Auto UI, reads server URL from flavor string |
| `android/.../Logger/LoggerPlugin.java` | Create — native logging to adb logcat |
| `android/.../build.gradle` | Modify — product flavors (emulator/production) |
| `android/.../res/xml/network_security_config.xml` | Create — allow cleartext for emulator + tailscale |
| `android/.../res/values/arrays.xml` | Create — `car_app_supported_types` |
| `android/.../res/values/strings.xml` | Modify — `server_url` per flavor |
| `static/chat.js` | Modify — `NativeMicUtteranceVAD` (RMS), voice-mode TTS, native bridge |
| `static/deps/vad/` | Create — Silero VAD WASM assets |
| `.gitignore` | Modify — exclude Capacitor build artifacts |

---

## Summary

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Capacitor Android shell (server-pull) | ✅ Complete |
| 2 | Native mic plugin + NativeMicUtteranceVAD (RMS) | ✅ Complete |
| 3 | Android Auto voice module | ✅ Complete |
| 4 | iOS build (same codebase) | Pending |

**Total**: ~2-3 weeks for full Android delivery. iOS nearly free after.
