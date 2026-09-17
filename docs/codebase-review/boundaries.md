# Observed boundaries and flow map

Evidence baseline: `4cda3039d3e5a58932a3c40afccc1e4ce33a19e3`. This map is partial; arrows below describe inspected edges, not certification of the entire flow.

## Rust composition — inspected

The Cargo workspace has three crates. `chatbot-server` depends on `chatbot-core`; shared test support depends on core and is a server dev-dependency. Core has no Axum/server dependency. This is a useful acyclic crate-level boundary. Core also contains concrete storage/crypto/configuration implementations, so the name does not imply a pure domain layer.

`chatbot-server/src/main.rs` calls `run()` in `lib.rs`. `run()` initializes logging, resolves the static root, spawns a purge task, constructs the router, binds a TCP listener, and serves it. The purge task directly calls the core session and remember stores. Its task handle is discarded; there is no application-owned shutdown handle in these files. Whether that warrants a lifecycle change depends on embedding/shutdown requirements, not merely the existence of `tokio::spawn`.

`build_router()` assembles route handlers and a rate-limited subrouter. Inline middleware implements cross-origin headers, cookie transport sanitization, static cache policy, and server-error logging. `http_error.rs` maps typed core errors to Axum JSON responses. A second path adapts core `ServiceResponse` objects containing serialized HTTP bodies and string headers. See MOD-001.

## Core state ownership — partially inspected

`config::app_config()` owns resettable global configuration. `HttpSessionStore` and `SessionStore` are independently initialized process globals inside `session.rs`; each captures configuration at first use. The former owns cookie-indexed identity/CSRF records; the latter owns per-identity chat state and a generation lock. `HistoryService` has a separate process-global entry point for durable state.

Core `session.rs` also selects model access policy, prepares chat contexts, validates data keys, seals session mirrors, and commits history. These are observable responsibilities, not evidence that all should become new crates. See MOD-002.

Shared `TestWorkspace` changes process cwd/environment and resets config/rate limiting. It does not establish ownership of all the independently initialized globals. Test callers and process isolation still need review before judging correctness (TEST-001).

## Partially traced request edges

- **Home:** `/` → `home::handle_home` → optional remember-token restoration → session bootstrap → account key-cookie promotion → user preferences/model-list projection → Minijinja render → response/security headers. The handler was read; remember-store/key-promotion internals and browser consumption have not yet been traced.
- **Chat preparation:** `/chat` → payload/CSRF/session handling → provider lookup → `session::chat_prepare` → chat lock, key check, durable snapshot or guest state, model-tier check → context returned to server provider construction. Streaming, cancellation, regeneration parity, and guard cleanup remain unread.
- **Chat persistence:** `session::chat_finalize_with_capture` → key verification → durable history append with capture (or snapshot fallback) for authenticated users; guest history append otherwise → session mirror update → unlock. History transaction implementation and server finalizer call sites remain unreviewed.

## Flows still to trace end to end

Password signup/login, remembered login and account switching; authenticated and guest chat including provider errors/cancellation; history load/edit/delete/fork and conflict recovery; browser/native STT and TTS including barge-in/background lifecycle; Android Auto; cleanup and resource limits; configuration/build/deployment; test execution and fixture isolation.

The source inventory also includes browser JavaScript, native Java, the Python GPU voice service, deployment/CI, and vendored runtime artifacts. Their architectural relationships are currently documented intent or inventory observations until their implementation is read.

## Session 002 — expanded implementation map

The earlier partial map above is retained as the session-001 record. Production paths described below have now been read through their implementations at `7dc8a23`; individual test assertions and live platform behavior are not thereby certified.

### Generation and durable data

Browser send/edit → HTTP chat/regenerate handler → cookie/CSRF/key and provider selection → core session prepare → history load and immutable capture → pure prompt packing → concrete provider/search stream → server completion guard → core capture-based commit → private history ops/store/crypto → wire error text and client rendering.

The generation lock is shared by core prepare/finalize and an ID-based server guard. HTTP-session identity and chat working state have different stores; authenticated chat identity is username-based rather than one record per browser cookie. Durable version/capture protects set writes independently of that lock. The default finalizers also retain a name-based, no-capture fallback used by saved-error-turn handling. Refactoring must preserve or explicitly correct each of those paths, not assume the happy-path capture applies everywhere.

Authenticated load/edit/delete/reset/prompt/memory routes use `HistoryService`, then separately synchronize session mirrors. Guest mutation routes use RAM. Private store modules enforce redb ownership/CAS; service methods enforce additional naming/content policy. Chunk storage uses stable pair/image IDs, but caller-facing snapshots can carry either references or materialized images. `chat_images` currently spans provider packing, UI projection and durable-image normalization.

### Browser and native voice

`chat.html` declares script order: Trusted Types/vendor globals, app-data JSON, VAD dependencies, native bridge, account cache, audio helpers, then chat application. No JavaScript module loader is present. `native-bridge.js` provides a plugin facade for login/key operations; `chat.js` separately implements microphone/playback wrappers through direct Capacitor calls. `native-audio.js` is a reusable PCM/VAD-math/codec helper surface, but logs back through globals installed by `chat.js`.

Both browser and handheld native clients use the same `/stt`, `/chat` or `/regenerate`, and POST `/tts` → GET `/tts_stream/{token}` API. Native PCM capture feeds a JS VAD and STT encoding path; browser capture uses MediaRecorder or Silero. These different capture mechanisms have documented platform reasons. Playback policy is split between JS sentence discovery/token scheduling, native ordered downloads, and native AudioTrack state; browser playback uses HTML Audio and blobs. The GPU service's streaming endpoint is not used by the inspected Rust Kokoro adapter: Rust requests full PCM, fades/encodes it, and caches complete wire clips for retries.

Android microphone/playback plugins call each other's static instance helpers. A foreground service invokes static native hooks to keep MainActivity's WebView running. Phone-call/notification lifecycle also crosses back into JS via both events and evaluated function calls. Small resource-policy classes and the pure-Java download/decoder helpers are useful existing seams. Android Auto instead contains its own capture/network/playback loop in `VoiceScreen`, without the handheld auth/CSRF plumbing.

### Authentication and credential lifecycle

Password login derives a key in web crypto/native plugin or on the server, validates password and verifier, rotates the HTTP session, then issues session/remember/key cookies. Cached native login unwraps stored credentials and injects cookies before `/login/remember`; browser JS maintains an account-name list. Home auto-restore and explicit remember-login each compose remember rotation, session creation and key-cookie promotion. Legacy key-returning web/native interfaces still coexist with the newer cookie-only request path (MOD-014/SEC-003).

### Packaging and test boundaries

The runtime Rust image copies browser assets and embeds templates. The GPU voice process is a separately built FastAPI app with model globals and raw-YAML settings. Native APKs pull web content but use separately specified origin resources for Auto/telemetry. Compose, Helm and native build configuration therefore participate in the application's module boundaries; they are not interchangeable launch wrappers.

Cargo owns core/server tests; the server integration tree additionally contains JS/Android source-policy checks and Node/Java behavioral entry points. Shared test support owns temporary cwd/env roots. HTTP voice stubs use local listeners and their own worker runtime. Android Gradle owns JUnit/instrumentation tests; the Rust wrapper for `TtsDownloadQueueTest.java` is a separate executable test path, not execution of the full Gradle or device suite. The documented off-device Opus comparison is another external executor operation. These scopes must stay distinct when reporting verification.

### Boundaries worth retaining

Keep the existing acyclic Cargo dependency direction, private redb tables/crypto, typed history operations, shared browser product UI, first-party asset delivery, pre-signed TTS transport, independent GPU process, and small native resource/codec/queue units. Their shortcomings are at interfaces and ownership points; another service layer or additional crates are not default remedies.

## Session 003 — remediated helper boundaries

Username validation (`user_store`) and set-name validation (`history` facade → HTTP/session callers) now delegate to `chatbot-core::names`. The legacy store also delegates to that domain module, mapping failures to its existing migration errors. Session mirror sealing and history Fernet payload decoding call private `fernet_crypto` directly; legacy store Fernet wrappers call the same crypto module. Only real history migration and compatibility surfaces retain the legacy-storage dependency.

POST `/tts` calls private `tts::text::sanitize_text` before token insertion. That module owns markup/reasoning/URL/citation removal and currency/abbreviation/number normalization; it has no config, token, network or HTTP dependency. Private `tts::backend` owns provider synthesis (legacy/fish/kokoro request shapes, provider HTTP client, WAV parsing, per-provider fade, silence fallback, backend error mapping) and returns owned PCM plus sample rate, never an HTTP response. Private `tts::store` owns the token-session lifecycle (admission with TTL/cap eviction, cached-or-generation/busy/missing arbitration, cancel, generation lease for success/drop retry cleanup) behind one global parent store; the parent keeps token minting, access policy, codec conversion, the encoded-size cache cap with retry reset, and response construction, and `tts_opus` retains codec ownership. Browser sentence normalization remains an earlier client stage. The text-boundary change has baseline and post-refactor full-suite evidence in the session-003 checkpoint; the backend boundary has its own baseline/final evidence in the session-005 checkpoint; the store boundary has its own baseline/final evidence in the session-006 checkpoint.

## Session 004 — remediated stream-decoder boundary

`static/stream-decoder.js` owns the `<think>` / `[BEGIN FINAL RESPONSE]` / `[ConsoleError]` buffer/state transitions, partial-tag holds and whole-text projection with no DOM, network or config dependency. `static/chat.js` history/regenerate/chat adapters own status labels, `data-original` accumulation and markdown rendering, with explicit preserved divergences (chat strips console detail and flushes at EOF/interrupt; regenerate keeps markers visible and drops the residual). The chat template loads the decoder before the application script. Rust think-stripping, server TTS normalization and TTS text selection stay separate callers. Baseline and wired full-suite evidence is in the session-004 checkpoint.

## Session 005 — remediated TTS backend-result boundary

`chatbot-server/src/tts/backend.rs` owns provider synthesis and returns owned PCM plus rate; the `tts.rs` parent owns the token session, access policy, wire encoding, the encoded-size rejection with retry reset, and HTTP rendering. Provider request shapes, default rates, fade differences, error statuses/messages and log contexts are preserved verbatim. Baseline and final full-suite evidence is in the session-005 checkpoint.

## Session 006 — remediated TTS token-store boundary

`chatbot-server/src/tts/store.rs` owns the token-session map (`PendingTtsStore` over an `RwLock` map) with admission, cached-or-generation/busy/missing/exhausted arbitration, cancel, and a generation lease (`complete`/`fail`/drop reset). The `tts.rs` parent keeps one global `Lazy` store plus token minting, access policy, wire encoding, the encoded-size rejection with retry reset, and HTTP rendering; handlers hold no map accesses and no lock across synthesis. TTL, cap, eviction order, replay budget, statuses/messages/headers, the 8 MiB cap, missing-cancel 204, and token-collision overwrite are preserved verbatim. The single process-global store remains a MOD-003 composition lead. Baseline and final full-suite evidence is in the session-006 checkpoint.

## Session 007 — remediated generation-dispatch boundary

`chatbot-server/src/providers/generation.rs` owns shared generation dispatch (closed `GenerationProvider`, `build_provider`, `map_core_messages`, search-gated `dispatch_stream`); `chat.rs`/`regenerate.rs` keep validation with the unsupported guard earlier, construction timing, saved-turn rendering with append-versus-replace, capture-derived versus payload user text, stream guards/finalizers and response building. The existing OpenAI-owned message DTO remains the shared shape. Baseline and final full-suite evidence is in the session-007 checkpoint.
