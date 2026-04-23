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

## Recommendation: Capacitor Android + Native Android Auto Module

Capacitor wraps the existing web UI in a native Android shell. Voice mode uses a native Kotlin plugin that captures audio and streams to `/stt`, bypassing browser restrictions. Android Auto is a separate native `CarAppService` implementing a voice-only interface (listen → transcribe → chat → TTS → speak, with an exit button).

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Android Device                         │
│  ┌─────────────────────────────┐    ┌──────────────────────┐  │
│  │     Capacitor WebView       │    │    Android Auto      │  │
│  │  ┌───────────────────────┐  │    │    (Native Kotlin)   │  │
│  │  │  chat.js              │  │    │                      │  │
│  │  │  - Silero VAD         │  │    │  CarAppService       │  │
│  │  │  - TTS playback       │  │    │  - Voice input       │  │
│  │  │  - Chat UI            │  │    │  - REST calls        │  │
│  │  └───────────┬───────────┘  │    │  - TTS output        │  │
│  │              │              │    │  - Exit button        │  │
│  │              ▼              │    └──────────────────────┘  │
│  │  ┌───────────────────────┐  │                             │
│  │  │  NativeMicPlugin.kt   │  │                             │
│  │  │  - 16kHz mono capture │  │                             │
│  │  │  - POSTs to /stt      │  │                             │
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
- **All frameworks**: Android Auto always requires a separate native Kotlin module regardless of framework choice.

Capacitor is the only option that preserves the existing web UI unchanged.

## Implementation Phases

### Phase 1: Capacitor Android Shell
**Goal**: Existing web UI runs in native Android app.

1. Add Capacitor:
   ```bash
   npm install @capacitor/core @capacitor/cli
   npx cap init "Chatbot" "com.chatbot.app" --web-dir=./static
   npm install @capacitor/android
   npx cap add android
   ```

2. Configure `AndroidManifest.xml`:
   - `RECORD_AUDIO`, `INTERNET`, `WAKE_LOCK`, `FOREGROUND_SERVICE` permissions
   - `android:exported="true"` for intent filters

3. Add `@capacitor-community/background-runner` for background execution.

4. Build and verify shell app loads.

**Effort**: ~1-2 days.

---

### Phase 2: Native Microphone Plugin (Android)
**Goal**: Voice mode works reliably without browser restrictions.

1. Write `NativeMicPlugin.kt`:
   - Uses `AudioRecord` for 16kHz mono PCM capture
   - POSTs to existing `/stt` endpoint
   - Handles audio focus and wake locks
   - Exposes `window.NativeMic.start()` / `stop()` / `isRecording()` to web layer

2. Modify `chat.js`:
   - Add `if (window.Capacitor && window.NativeMic) useNativeMicBridge()` conditional
   - When native bridge is present, use it instead of `getUserMedia` + MediaRecorder
   - Keep existing Silero VAD in WebView (not browser tab, so no suspension issue)

**Effort**: ~1 week.

---

### Phase 3: Android Auto Module
**Goal**: App appears on AA head unit as a voice-only interface.

1. Implement `CarAppService` in Kotlin:
   - `onCreateSession()` returns a `VoiceSessionFragment`
   - UI: only a listening indicator and an Exit button
   - Voice input → `/stt` → `/chat` → `/tts` → audio playback
   - Exit button terminates session and closes AA UI

2. Manifest declarations:
   - `android:autoContents="true"`
   - `android.media.apis` capability
   - `android:exported="true"` on CarAppService

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

## VAD Evaluation

Silero VAD runs in the Capacitor WebView, not in a browser tab, so it should not be subject to the same suspension rules. However, car environments are noisy. After Phase 2, test VAD accuracy. If it misses too often:
- Adjust Silero thresholds (`positiveSpeechThreshold`, `minSpeechFrames`)
- Or implement native Kotlin VAD plugin using ONNX Runtime Mobile

Native VAD is **not in scope** for initial delivery.

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `docs/frontends.md` | Create — this document |
| `docs/design.md` | Modify — add frontends reference |
| `capacitor.config.ts` | Create — points to `./static` |
| `android/` | Create — Capacitor Android project |
| `android/app/src/main/java/.../NativeMicPlugin.kt` | Create — mic bridge |
| `android/app/src/main/java/.../VoiceCarAppService.kt` | Create — AA CarAppService |
| `static/chat.js` | Modify — add `Capacitor.isNative` conditional |
| `ios/` | Create — Capacitor iOS project (Phase 4) |
| `src/ios/NativeMicPlugin.swift` | Create — Swift mic plugin (Phase 4) |

---

## Summary

| Phase | Deliverable | Effort |
|-------|-------------|--------|
| 1 | Capacitor Android shell | ~1-2 days |
| 2 | Native mic plugin + chat.js conditional | ~1 week |
| 3 | Android Auto voice module | ~1 week |
| 4 | iOS build (same codebase) | ~1 day |

**Total**: ~2-3 weeks for full Android delivery. iOS nearly free after.
