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
