# Observed boundaries and flow map

This is a partial cross-component map, not certification of every flow. Arrows describe inspected ownership and behavior. See [coverage.md](coverage.md) for review coverage and execution limits.

## Rust composition

The Cargo workspace contains `chatbot-core`, `chatbot-server`, and `chatbot-test-support`. Server depends on core; core has no Axum dependency. Core includes concrete storage, crypto and configuration implementations, not only domain logic.

`chatbot-server/src/main.rs` invokes `run()` in `lib.rs`. Startup initializes logging, resolves static assets, starts purge, builds the router, binds and serves. The purge task calls core session and remember stores; its task handle is discarded, and these files do not show an application-owned shutdown handle.

`build_router()` assembles handlers and a rate-limited subrouter. Middleware owns cross-origin headers, cookie transport classification/sanitization, static cache policy and server-error logging. `http_error.rs` maps typed core errors to Axum JSON; core `ServiceResponse` and HTTP-body construction have been removed. See [findings.md](findings.md) (MOD-001).

## Core state ownership

`config::app_config()` and lazy global compatibility constructors remain available. Production instead composes owned HTTP identity, chat/history, account and policy/service dependencies through `AppServices`; the identity and chat-state types retain distinct responsibilities. Session code still composes chat preparation, key verification, mirror sealing and history commits. See [findings.md](findings.md) (MOD-002).

`TestWorkspace` changes cwd/environment and resets config/rate limiting, but does not own all independently initialized globals. Test callers/process isolation remain relevant to TEST-001, owned by [test-quality.md](test-quality.md).

## Generation and durable data

Browser send/edit → chat/regenerate handler → cookie/CSRF/key and provider selection → core session prepare → history load/capture → prompt packing → provider/search stream → server completion guard → core capture-based commit → private history operations/store/crypto → wire error text/client rendering.

The generation lock is shared by core prepare/finalize and an ID-based server guard. HTTP identity and chat working state use separate stores; authenticated chat identity is username-based. Durable version/capture protects set writes independently of that lock. Default finalizers retain a name-based no-capture fallback for saved-error turns.

Authenticated load/edit/delete/reset/prompt/memory routes use `HistoryService`, then synchronize session mirrors; guest mutation routes use RAM. Private store modules enforce redb ownership/CAS, while service methods enforce naming/content policy. Chunk storage uses stable pair/image IDs; caller snapshots can carry references or materialized images. `chat_images` spans provider packing, UI projection and durable-image normalization.

## Browser and native voice

`chat.html` declares script order; there is no JS module loader. `native-bridge.js` provides plugin facades for login/key operations, while `chat.js` separately wraps microphone/playback through Capacitor. `native-audio.js` provides PCM/VAD/codec helpers and logs through globals installed by `chat.js`.

Browser and handheld clients use `/stt`, `/chat` or `/regenerate`, and `POST /tts` → `GET /tts_stream/{token}`. Native PCM capture feeds JS VAD/STT encoding; browser capture uses MediaRecorder or Silero. Playback policy is split across JS sentence/token scheduling, native ordered downloads/AudioTrack, and browser HTML Audio/blobs. Rust's Kokoro adapter requests full PCM, fades/encodes it and caches complete wire clips; the inspected GPU streaming endpoint is not used there.

Android microphone/playback plugins call static instance helpers. A foreground service invokes native hooks to keep MainActivity's WebView running; phone/notification lifecycle also crosses into JS through events and evaluated calls. Android Auto has its own capture/network/playback loop in `VoiceScreen`, without handheld auth/CSRF plumbing. Its transport repair and supported host-validation contract remain user-deferred.

## Authentication and credential lifecycle

Password login derives a key in web crypto/native plugin or on the server, validates password and verifier, rotates HTTP session, then issues session/remember/key cookies. Cached native login unwraps credentials and injects cookies before `/login/remember`; browser JS maintains account names. Home auto-restore and explicit remember-login compose remember rotation, session creation and key-cookie promotion. The legacy key-export surface has been removed; the remaining SEC-003 security decision is tracked in [security.md](security.md), not as an outstanding key-export API (see [modularity.md](modularity.md)).

## Packaging and test boundaries

The runtime Rust image embeds templates and browser assets. The separately built FastAPI GPU process owns model globals and raw-YAML settings. Native APKs pull web content but use separately specified origin resources for Auto/telemetry; Compose, Helm and native build configuration therefore participate in module boundaries.

Cargo owns core/server tests; server integration tests also run JS/Android source policies and Node/Java behavioral entry points. Shared support owns temporary cwd/env roots. HTTP voice stubs use local listeners and their own worker runtime. Android Gradle owns JUnit/instrumentation tests; the Rust `TtsDownloadQueueTest.java` wrapper is a separate executable path, not the full Gradle/device suite. Off-device Opus comparison uses another executor. Keep these verification scopes distinct.

## Boundaries worth retaining

Keep the acyclic Cargo dependency direction, private redb tables/crypto, typed history operations, shared browser product UI, first-party asset delivery, pre-signed TTS transport, independent GPU process, and small native resource/codec/queue units. Interface/ownership shortcomings do not make extra services or crates the default remedy.

## Current owned flows

- Current owner edges include `AppServices → ConfigSource → request/identity/cookie policy` (with ambient route/config policies remaining: MOD-003); generation dependencies carry explicit provider/fake inputs, while live Rust compatibility remains lazy.
- `chat.js → ChatRenderer / ChatTtsPlayback / ChatVoiceCapture → injected platform callbacks`.
- `capacitor.config.json serverUrls → Gradle flavor resource → ServerUrlResolver → WebView/cookies/logging/Auto`.
- Browser stream decoding/projection is centralized in `stream-decoder.js`; chat adapters retain their rendering/error differences.
- Shared naming and Fernet helpers live in current-domain core modules; legacy storage delegates while preserving compatibility APIs.
- TTS text preparation, backend PCM synthesis and token lifecycle have private module owners; HTTP/access/codec remain in the parent.
- Production uses owned request/config, account, chat/history, rate and TTS service/policy dependencies where recorded in [design.md](../design.md); compatibility constructors remain lazy-global paths.

## Open boundary

TEST-001 remains with [test-quality.md](test-quality.md). Cross-pass correctness, security and documentation items remain in [findings.md](findings.md).
