# Architecture & Roadmap

This document captures the current architecture of the project and the potential future roadmap.

## Current Architecture

Android foreground stops propagate stopped/already-stopped/failure outcomes through the platform adapter. Failed stops retain session ownership; successful outcomes reconcile only the initiating generation. Platform start/stop calls are serialized separately from the session monitor so an older stop cannot follow a replacement start.

The voice service tracks non-streaming Kokoro/STT jobs alongside streaming producers. A cancelled waiter does not interrupt inference or release its STT staging file; the worker cleans up before delivering its result. Lifespan shutdown rejects new jobs and joins all worker types off-loop under one shared bounded deadline, retaining work that has not exited.

Desktop playback cancellation settles active clip promises and disposes queue-owned subscriptions, observers and timers. The voice lifecycle registers both clip and queue disposers so direct lifecycle stops and UI stop/replacement paths share cleanup; cancellation does not emit normal completion notifications.

Browser requests capture the initiating conversation identity and history generation as well as the request sequence. Switching sets cancels the outgoing generation and settles its playback source; stale stream callbacks cannot render or update the newly selected set. Memory and system-prompt retries retain the original target and fence their response UI. History-pair pre-reads and older-page settlement also respect the captured generation.

Request policy is injectable through `ConfigSource` in `AppServices` and `RequestIdentity`: CSRF, cookie timeout, default prompt and voice-service base URL. Owned handles use explicit values; global handles retain call-time lookup. Home rendering captures one coherent live configuration when needed. Generation dependencies additionally own fake chunks, tool queries, Brave results, chunk delay and XAI fallback keys; explicit provider constructors do not consult ambient fake inputs.

Browser rendering, playback queues and capture coordination live in `chat-renderer.js`, `tts-playback.js` and `voice-capture.js`. They receive DOM/markdown, transport, lifecycle, clock and platform dependencies from `chat.js`; desktop and native retain their shared session/protocol owners and established retry/barge-in behavior.

Android build flavor is authoritative for the server origin. Root `capacitor.config.json` defines both emulator and physical endpoints under `serverUrls`; Gradle projects the selected endpoint into `R.string.server_url`. The WebView, credential cookies, client logging and Android Auto use that resource through `ServerUrlResolver`.

`RatePolicy` and `TtsPolicy` own per-router rate budgets and TTS access/codec/synthesis policy behind separate optional-`Arc` handles. `AppServices` carries both with `with_rate_policy`/`with_tts_policy`; TTS endpoints resolve access, wire codec, coherent provider/voice/endpoint inputs and legacy/fish bases through the router policy, while the rate middleware takes budgets from the router policy and keeps counters in the limiter dimension. Global handles construct config-free and delegate per operation at the original config sites; production keeps the live path with no snapshot or schema change. Other route/config policies remain ambient.

`DataRequestContext` owns data-route session/key resolution without eager key validation. Direct data routes obtain a privately constructed, borrowed `VerifiedDataContext` after validation through their chat service. Chat/regenerate consume explicitly unverified parts so model/provider error ordering stays intact. CSRF remains at existing route boundaries; history images retain their named cookie fallback. Preferences retain their distinct session-first, key-only-for-authenticated flow.

Core session operations now return `SessionOperationError`, including encryption-key, account-store, cache and bootstrap failures. `PrepareError::Session` carries these typed failures; `ServiceResponse` and core HTTP-body construction have been removed. Server error mapping owns JSON/status/counters, including raw-400 body logging and single-count 500 responses. Saved-error-turn handling keeps its prepare-specific policy.

Canonical chat/regenerate finalization returns `FinalizeOutcome`; typed lease completion follows the same commit/mirror/unlock path. The server renders stream-error chunks. Guest updates, durable commits and absent sessions render no extras; key-validation failures retain the shared missing-key text, while conflict/input/store errors retain their existing messages. Legacy `Vec<String>` APIs remain compatibility adapters. Successful durable writes still count as committed when mirror sealing fails; expiry/recreation behavior is unchanged.

Production shares one `AccountService` between chat key/tier checks, account HTTP handlers, TTS access checks and remember-token purge. It opens user/remember stores per operation at an explicit root; configured user handles use the service's HMAC secret for ordinary verifier methods. Password signup/login, salts, remember restore/rotation/forget, preferences and key-cookie promotion use injected accounts. Existing router constructors keep global account compatibility unless explicitly configured. Provider selection, CSRF and cookie/TTS/rate policies still resolve live global configuration.

Production now installs its owned `ChatService` in `AppServices`. Chat/regenerate (including saved-error turns), set/history routes, memory/reset and deep health use that same service. Background purge uses the matching HTTP/chat owners. `ChatService::with_storage` opens history on first use and retries failed opens, preserving request-level database failures rather than failing startup. Compatibility routers retain lazy global chat/history. Account HTTP handlers, provider selection and live configuration remain ambient dependencies.

`ChatService` composes chat state, history and account validation with concrete owned dependencies. Its leases bind both service and prepare-time session, so prepare, durable completion, mirror updates and release use the same owner. The session store supplies the default prompt; service clones share one dependency bundle. `ChatService::global()` and existing free functions preserve lazy process-global compatibility. Owned services use explicit account roots/HMAC secrets and provider inputs; the test-chunk environment override remains shared. Router chat/history wiring still uses compatibility functions until service injection is completed.

`GenerationDeps` owns per-router generation inputs behind one optional-`Arc` handle: provider map/default, thought defaults and Brave key. `AppServices` carries the handle with `with_generation_deps`; chat/regenerate resolve provider lookup, thought defaults and dispatch Brave lookup through it. The global handle constructs config-free and delegates per operation at the original config/env sites; owned handles use only explicit inputs. Compatibility constructors keep the global-live handle, so production is unchanged with no config-schema change. Other route/config policies, provider env chunks and test fakes remain ambient.

`ChatSessionStore::new(timeout_secs, default_prompt)` owns independent guest history, memory, prompt, generation locks and expiry. Its timeout is raw seconds, including zero; only HTTP identity applies a 60-second floor. State free functions delegate to the same lazy global store. Authenticated preparation/finalization, mirror mutations and generation leases still use global chat/history/account dependencies; state construction alone does not isolate those workflows.

`UserStore::open(root)` and `RememberStore::open(root)` support explicit storage roots; their `new()` compatibility APIs still resolve `HOST_DATA_DIR` per call. User-store verifier enrollment and checking also accept an explicit HMAC secret through `_with_secret` methods. Compatibility verification preserves one record read and only resolves configuration when a verifier exists. These constructors enable independent services; production account handlers still use the compatibility APIs.

Chat/regenerate routes use leased prepare APIs. A non-cloneable `GenerationLease` binds the prepared session and owns completion or release; the stream guard owns its persistence closure. An unpolled body releases without saving, post-poll cancellation saves partial text (including empty text), and provider errors release without saving. Settlement still resolves the current entry by session ID; expiry/recreation semantics are a separate unresolved issue. Direct prepare/finalize compatibility APIs retain their existing behavior.

History caches private store-produced `LogicalSnapshot` values. Chunked commits return normalized image-reference text for cache insertion; public `SetSnapshot` remains a compatibility DTO. `load` expands images into an owned copy, while `load_logical` preserves references consistently across warm/cold reads. Whole-blob migration and literal undecodable image markers keep their supported representations.

Pure browser/native voice-text operations live in `static/voice-text.js`: sentence splitting/completion, speech normalization, utterance joining, amend eligibility and caret-to-sentence lookup. `chat.js` delegates with an explicit amend window and retains playback/recording coordination. The template loads the shared unit before `chat.js`; server speech normalization remains a separate later stage.

Browser conversation/request/history-window state lives in `static/conversation-state.js`: set-version transitions (reads advance only, mutations/409 authoritative), exact set-identity payloads, retry-once decisions, request-sequence plus set-generation fencing, ghost-turn routing, history-window offsets/pagination and the three abort behaviors (quiet replace, user stop, voice interrupt). `chat.js` holds one history window plus one request tracker and keeps DOM rendering, option syncing and voice routing callbacks. The template loads the shared unit before `chat.js`; TTS queue fixtures drive generating state through the real tracker.

Browser HTTP/session ownership lives in `static/session-client.js`: one shared bootstrap attempt, one 401-interceptor allowlist, generate/CSRF/voice HTTP helpers and retry eligibility. `chat.js` supplies explicit DOM callbacks (logged-in state, CSRF meta, home redirect) and keeps rendering; the unit touches no `window`/`document`. The template loads the unit before `chat.js`.

Browser voice lifecycle lives in `static/voice-lifecycle.js`: the single TTS flags/cooldown/barge/session/audio owner (currentAudio/Button, desktop session/audio/abort/preloads/blob, sessionActive/playing, barge frames, listen cooldown, native generation). `chat.js` keeps queue/VAD orchestration with explicit callbacks and exact error/order flags; the unit touches no `window`/`document`. The template loads the unit before `chat.js`.

Browser credential metadata and crypto live in `static/credential-metadata.js` (per-account slot naming/visibility/recency) and `static/credential-crypto.js` (PBKDF2/AES-GCM/PRF/base64 with explicit env, no ambient store/DOM/key-flow reach). `enc-key.js` keeps store lifecycle plus the `EncKey` surface, requires both UMD units before it, and passes browser capabilities per call. Handheld voice-mode session composition lives in `audio/VoiceModeSessionCoordinator` (route/keep-awake/FGS/phone/notification with mic plugin hooks, no new locks; TTS plugin unchanged; dual-event and FGS semantics unchanged). Sealed cached credentials split into `CredentialCookies` (names/parsing/builders) and `SealedCredentialPayload` (`org.json` codec), preserving keystore/biometric and the legacy export surface with no security-behavior change.

Durable mutations with session mirrors are owned `ChatService` operations returning `AppliedMutation{set_id, version}` or `MutationMirrorError{Key, InvalidSetId, SetNotFound, Conflict, History, Mirror}`: key validation, set-address resolution, durable CAS write, then mirror with no rollback. Memory/prompt mirrors swallow the post-durable seal error on active-set mismatch (the other set stays intact) and propagate matching-set failures; guest load keeps the exact 401.

Voice-service settings resolve once per process in `chatbot-cuda/src/settings.py` (raw YAML with no `${VAR}` substitution; lowercased `tts_provider` default `kokoro`; `STT_MODEL_ID` env default Parakeet ID; device `cuda:{CUDA_VISIBLE_DEVICES}` verbatim, else `cuda:0`/`cpu`). `service.py` owns one lifespan-built `InferenceService` shared via `app.state` (Kokoro loads only for the kokoro provider, STT always; load failures propagate except Kokoro warmup/`torch.compile` warnings; explicit readiness). `main.py` builds apps through `create_app` with routes on a router; every route resolves the same lifespan-owned service. Streaming keeps the daemon-thread→unbounded-queue bridge with no backpressure, disconnect cancellation or shutdown join. GPU/device behavior is unmeasured.

HTTP identity lifecycle lives in `chatbot-core/src/session_identity.rs`: cookie/CSRF state, guest/user identity, login/logout rotation and identity expiry. `session.rs` re-exports its public API and composes HTTP/chat expiry counts; chat state, generation locks and orchestration remain in `session.rs`.

`HttpSessionStore` can be constructed with an explicit timeout and receives CSRF policy per operation. The compatibility free functions use one lazy process-global instance, preserving first-use timeout capture and live CSRF configuration. Independently constructed stores share no identity state; router-level service composition remains separate work.

Production startup constructs one owned HTTP identity store and shares it between `build_router_with_identity` and background purge. `RequestIdentity` is installed in request extensions and used by every identity-dependent handler, rate-limit identity lookup and account-key-cookie selection. `build_router` remains a lazy-global compatibility constructor. Chat/history, rate counters, account stores and configuration are not isolated by this identity-only composition.

Resource composition extends this in `services::AppServices`: production now uses `build_router_with_services` with owned HTTP identity, TTS pending tokens and rate counters. All three TTS endpoints resolve the same store, and background purge shares the identity. `build_router` retains lazy globals; `build_router_with_identity` retains global tokens/counters. Rate/TTS configuration, account stores and chat/history remain shared. Separate owned contexts isolate token admission, replay/cancellation and both rate-limit dimensions.

Raw request Cookie/CSRF header parsing and client-IP selection live in `chatbot-server/src/request_context.rs`. Route handlers retain identity lookup and CSRF/authorization decisions; rate limiting uses the borrowed cookie accessor. `chat_utils::get_ip` is a compatibility re-export.

Prompt packing in `chatbot-core::chat::prepare_prompt_messages` uses borrowed `PromptInput` (system prompt, memory, history, context size and thoughts flag). `prepare_chat_messages` adapts the session-owned `ChatContext` and resolves the provider's default context size for existing consumers.

Chat/regenerate preparation exposes typed `PrepareValidationError` values through `PrepareError::Validation`; other failures use a transitional `Service(ServiceResponse)` carrier. HTTP handlers retain the nonempty-message saved error-turn path and map raw validation failures in `http_error.rs`.

Generation contention and premium-model rejection use `PrepareError::Policy(PreparePolicyError)`. The server maps these to direct 429/403 JSON responses without saving an error turn or adding error instrumentation.

Prepare-time history failures use `PrepareError::History(PrepareHistoryError)`. The server owns status/JSON mapping; missing sets retain the prepare-specific 400 classification and nonempty-message saved-error-turn handling. Other history routes keep their own 404 mapping. Core records the history cause; the server records response error counters.

Core encryption-key validation returns `EncryptionKeyValidationError` (`Missing`, `Invalid`, `StoreUnavailable`). Direct HTTP consumers map it in `chatbot-server/src/http_error.rs`; session orchestration retains a `ServiceResponse` adapter in `require_encryption_key`.

Encryption-key HTTP transport helpers live in `chatbot-server/src/enc_key_cookies.rs`: header/account/generic cookie selection, cookie construction and verified account-cookie promotion. `chat_utils` retains compatibility re-exports for current callers.

- **Shared naming and Fernet helpers** – `chatbot-core::names` owns username and set display-name validation. The history facade exports set-name operations with typed domain errors; HTTP handlers map them to responses. Private `fernet_crypto` provides session-mirror sealing and legacy history payload compatibility. The migration store delegates to these modules while preserving its compatibility APIs and error variants.
- **Speech-text boundary** – Private `chatbot-server/src/tts/text.rs` transforms submitted text before TTS token insertion: reasoning/markup/URLs/emoji/citations are removed, then currencies, abbreviations/symbols and numeric forms are expanded before whitespace cleanup. Browser sentence preparation runs earlier; the server stage applies to every `/tts` submission. Token-session lifecycle (admission, cached/replay/busy/missing arbitration, cancel, generation lease) lives in private `tts/store.rs` behind one global parent store; token minting, access policy, codec conversion and HTTP rendering remain in `tts.rs`; provider synthesis lives in private `tts/backend.rs`, which returns owned PCM plus sample rate (never an HTTP response). Opus conversion stays in `tts_opus.rs`.

- **Workspace layout** – The Cargo workspace lives at the repository root. It contains three crates: `chatbot-core` (business logic, config, history, persistence, sessions), `chatbot-server` (Axum HTTP server, route handlers, and LLM/TTS provider adapters under `chatbot-server/src/providers/`), and `chatbot-test-support` (shared fixtures for integration tests). Shared resources such as templates and static assets reside in `static/`, while persisted runtime data is stored under `data/`.
- **HTTP stack** – `chatbot-server` exposes all routes via Axum, including `GET /health` for liveness. Templates are rendered with Minijinja, CSP headers are enforced by middleware (`script-src 'self'`; jquery/bootstrap/marked/highlight.js are vendored under `static/deps/`; `require-trusted-types-for 'script'` with policies `chatbot` and `default`), and state-changing endpoints require per-session CSRF tokens managed by the Rust session store. CSRF protection is configurable via `.config.yml` (and the `CSRF` environment variable); disabling it also removes the `Secure` flag from session cookies to support non-HTTPS development environments.
- **Providers & chat flow** – The chat pipeline is orchestrated in Rust and configured through `.config.yml`. Provider implementations (OpenAI-compatible, XAI) live in `chatbot-server` and use concrete enum dispatch (`GenerationProvider` in `providers/generation.rs`) with streaming support, exercised by cargo integration tests. Shared generation dispatch lives in `chatbot-server/src/providers/generation.rs` (closed provider enum, core-to-DTO mapping, search-gated streaming); `/chat` and `/regenerate` keep validation, saved-turn rendering with append-versus-replace, guards and finalizers, and the shared message DTO in `providers/messages.rs` (OpenAI-compatible serialization) remains the shared shape. XAI providers support optional `xai_zdr: true`, which sends `store: false` on the Responses API (no server-side conversation retention) and logs a warning if the response `x-zero-data-retention` header is not `true`. Full team-level Zero Data Retention is enabled in the [xAI Console](https://console.x.ai/) and is independent of this flag. OpenAI-compatible providers retry upstream `429 Too Many Requests` before the stream starts: per-provider `rate_limit_retries` (default 5, 0 disables) extra attempts with exponential backoff (1s, 2s, 4s, 8s, 16s) whose wait honors the upstream `Retry-After` hint capped by `rate_limit_max_wait_secs` (default 30s); retries never happen mid-stream, an impatient user can hit Stop to cancel the wait at any time, and exhausted retries surface the provider error body exactly as before. Each retry wait streams a `<think>`-wrapped status line ("Upstream rate limited — retrying (attempt n/m) in Xs.") so the client can label the thinking toggle "Rate limited — retrying..." (same mechanism as "Searching the web..."); the notice persists in the thinking log, never in the answer text.
- **Brave Search integration** – Non-XAI providers (OpenAI-compatible API) support web search via the Brave Search REST API. When `web_search=true` is requested, the server starts a streaming call with an OpenAI function-calling tool definition. Direct model content is forwarded immediately; if streamed tool-call deltas request `brave_web_search`, the query is executed against the Brave Search API via `reqwest`, and the results are injected before a final streaming response. Search responses therefore use two LLM calls, while direct answers use one. XAI models retain their native search capability unchanged. Configured via the `BRAVE_API_KEY` environment variable.
- **Sessions & storage** – Session state lives in a Rust-managed in-memory store (guest RAM mirror only). **Remember tokens** ("Remember this computer for 30 days", checked by default) survive server restarts: `GET /` silently restores a remembered session and rotates both the last-used `remember` cookie and that account's `remember-{username}` cookie. The login page lists cached accounts; picking one hides the password and signs in via `POST /login/remember` when that account's cookie matches. A typed password still `POST`s `/login`. Switching remembered accounts does not revoke the other account's family. A ✕ control forgets them (`POST /login/forget` revokes only that account's family). The remember token restores the session only and never bypasses the enc-key; the server stores only a hash, every restore rotates it, re-login refreshes the same family, unchecking the box or ✕ revokes it, and Switch account (`GET /logout`) does not. Log out of this computer forgets this account on this device (`POST /login/forget`) then logs out. There is no `/login/keyauth` — the Fernet key cannot mint a session. The data key is an HttpOnly `enc_key` cookie plus a per-account `enc_key-{username}` cookie (same lifetime as remember); page JS never reads or sends it. Switch account clears last-used `enc_key` only; remember restore copies `enc_key-{username}` back. The data-key HMAC verifier is permanent (password login only; not enrolled from data requests). Chat history for authenticated users is stored in an embedded **redb** database of AEAD ciphertext via `HistoryService`: a sealed header + manifest, per-pair text chunks, and extracted image/thumbnail blobs (see [design-history-store.md](design-history-store.md) and [design-history-chunks.md](design-history-chunks.md)). Pre-redb `user_sets/{user}/sets.json` is **migration-only** and lives permanently in `chatbot-core::legacy_sets_json` (lazy import into redb, then `sets.json.migrated.bak`). Whole-set `SETS_BLOB` rows migrate lazily to chunks on the first payload op. Anonymous flows remain ephemeral/RAM-only.
- **Tooling & operations** – Development and CI rely on Docker. The compose `tests` service runs `cargo test` for the workspace (including `js_syntax`, which parses first-party `static/*.js` with `oxc_parser`); `docker compose run --rm tests`. The runtime image builds the Axum binary; its `rust-build` stage advances workspace source mtimes before `cargo build` because the cache-mounted target dir persists compiled artifacts and `COPY` preserves source mtimes, so cargo's mtime freshness check could otherwise reuse a stale rlib (rust-lang/cargo#9312). `chatbot-server/tests/docker_build.rs` guards that recipe. Build caches, Cargo registries, and generated logs are mounted under `temp/` per `AGENTS.md`.

## Roadmap

### Top Priority Improvements

- [x] **Rust Refactor:** All Flask routes, bridge helpers, and provider integrations have been ported to Rust.

- **UI/UX Improvements**
  - [x] Lower friction for new chats by assigning a temporary title (e.g., "New Chat") that is automatically replaced with a contextual name based on chat content.
  - [x] Branch a conversation at any saved turn: fork copies history up to that point (inclusive) into a new chat (`POST /fork_set`, auto-named `<source> - branch`) and switches to it; the source is untouched.
  - [x] Ability to delete chats from history (`/delete_message` requires `pair_index` + matching `user_message` at that index; content mismatch → 409. `ai_message` may be sent by the client but is not used for the server-side match). Image payload bytes are ignored in the match so UI thumbnails still delete the stored full-resolution attachment.
  - [x] Ability to edit old chat entries.
  - [x] Lazy-load long chats: `/load_set` accepts `limit`/`before` and returns the most recent **text** page first (`history_start` / `history_total` / `has_more`). `thumbnails: true` strips image bytes (`[IMAGE:]` markers only); the client then GETs `/history_image/...?size=thumb` newest-first after paint. Expand uses `GET /history_image/...` (full res, browser HTTP cache); `POST /history_pair` returns the full pair for edit/regenerate. Durable storage is **chunked**; see [design-history-chunks.md](design-history-chunks.md).

- **Authentication & Security**
  - [ ] Outsource authentication to Keycloak or Authentik (or other OIDC-compliant systems).
  - [ ] Add proper email verification and CAPTCHA workflows to prepare for production.
  - An additional encryption password may be required for privacy requirements.
  - [x] Remember-this-computer device tokens (30 days, checked by default) with silent session restore on app entry, a cached-account login dropdown (password-free via per-account remember cookies until ✕; forget control), Switch account vs Log out of this computer in the chat UI, and a true opt-out via the unchecked box, ✕, or Log out of this computer (revokes the device's token). The Fernet key is not a login credential.

- **Security & Session Management**
  - [x] Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - [x] Ensure password hashing uses a strong KDF with per-user salts.
  - [x] Provider metadata hygiene: the UI now receives only a sanitized model list (`provider_name`, `tier`), preventing accidental leakage of `api_key` or `base_url` values.
  - [x] Anonymous model choice: guests see the model picker when more than one free-tier model is configured (the guest list is pre-filtered to free tier); the choice is page-local and sent per request, never persisted.
  - [x] Session isolation: anonymous users are assigned stable random guest IDs instead of the remote IP, eliminating cross-user memory leaks behind shared NAT gateways.
  - [x] Encryption key handling: login derives a Fernet key per user; the server stores only an HMAC key verifier (not the key itself). Browsers receive the key in HttpOnly `enc_key` and `enc_key-{username}` cookies (`SameSite=Strict`); page JS never reads or sends it. Tests may still send `X-Enc-Key`. The server zeroizes the key after each request. See [design-privacy.md](design-privacy.md#per-request-encryption-key-model).
  - [x] CSRF protection – every state-changing route validates a per-session token; the token is exposed to forms and Fetch calls, and the client attaches it automatically.
  - [x] Frontend sanitisation: set names rendered in the chat UI are escaped before insertion, closing stored-XSS vectors through crafted identifiers.
  - [x] CSP refinements: media sources now explicitly allow the `blob:` scheme used for streamed TTS playback; UI JS/CSS (jquery, bootstrap, marked, highlight.js) is first-party under `static/deps/` so `script-src` stays `'self'`.

- **Project Structure & Packaging**
  - [x] Adopt a standardized Cargo workspace layout for packaging, publishing, and dependency management.
  - [x] Include a `.config.yml.example` at the repo root to illustrate required settings.
  - [x] Provide a top-level `README.md` with quickstart instructions and project overview.

- **Dependency Management & CI**
  - [x] Switch to pinned dependencies (direct crate versions aligned to `Cargo.lock`; Dependabot keeps them current).
  - [x] Enable automated dependency updates for security updates (Dependabot weekly PRs — review/merge only).
  - [x] Add a CI workflow to run tests and secret scans on each pull request.
  - [ ] Full CI/CD: on push to `main`, automatically deploy production (today: human runs an Ansible playbook in a sister repo; wire that into GitHub Actions or equivalent after CI is green).

- **Testing**
  - [x] Convert ad-hoc scripts into proper tests or retire them.
  - [ ] Measure test coverage and target critical modules (session manager, providers, chat flow) with explicit coverage goals.
  - [x] Spin up the app in test mode for end-to-end route testing (signup/login, JSON APIs).
  - [x] Establish mocking and external-service stubbing best practices for LLM providers and authentication flows.
  - [ ] Add full Android emulator integration tests for the Capacitor app, including native microphone/TTS, permissions, WebView lifecycle, screen-off/reload recovery, and server-pull voice flows.

### Lower Priority Improvements

- **Configuration & Secrets**
  - [x] Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - [x] Store all API keys and sensitive settings in environment variables only — Compose/`.config.yml` use `${VAR}` substitution; boot refuses plaintext provider `api_key` values and `vars:`-backed key refs.
  - [x] Validate `.config.yml` against a schema to catch missing or invalid fields.
  - [x] Protect `.env` and `.config.yml` from AI agent access via the **agent devcontainer** (Docker isolation + secret bind-mount overlays). Run cloud-connected agents only in that environment — see [`.devcontainer/README.md`](../.devcontainer/README.md). Do not run agents on the host against the live workspace.
  - [x] Dependabot (`.github/dependabot.yml`): weekly PRs for Cargo, GitHub Actions, and Docker base images — **review/merge only**, no automerge. Direct crate deps pinned to current `Cargo.lock` versions.
  - [x] CodeQL security scanning via advanced setup (`.github/workflows/codeql.yml` + `.github/codeql/codeql-config.yml`). Disable GitHub “default setup” for this repo to avoid duplicate scans. Test trees (`**/tests/**`, etc.) are path-ignored so fixture passwords do not trip `rust/hard-coded-cryptographic-value`; production code still runs that query. Bulk-dismiss leftover *test* alerts with `scripts/dismiss-codeql-hardcoded-alerts.sh` if needed.
  - [ ] Implement hybrid chat-history encryption:
        - [x] Derive a per-user data key from a user-supplied passphrase.
        - [x] Encrypt set names and metadata on disk to prevent leakage of conversation identifiers.
        - [x] Per-request key transport: HttpOnly `enc_key` / `enc_key-{username}` cookies (or `X-Enc-Key` for tests); server validates against HMAC verifier. End-to-end encryption is guaranteed for data persisted to disk (redb); plaintext is held in RAM during active requests (required for LLM interaction) and cached snapshots are wiped after an idle TTL. Page JS does not unwrap or send the key.
        - [x] Default client storage is those HttpOnly cookies (IndexedDB holds cached usernames for the login dropdown only; WebAuthn PRF is not on the request path). On mobile, cached credentials are sealed in Android Keystore at rest, requiring biometric unlock before cached login. (iOS still open below.)
        - [ ] WebAuthn PRF as the **default** web wrap — not viable yet; many desktops lack Touch ID / Windows Hello / a security key. Keep Option 3 opt-in. PRF = Pseudo-Random Function (authenticator-side keyed hash).
        - [ ] iOS Keychain plugin mirroring `NativeSecureKey` when the iOS Capacitor target is added.
        - [ ] Allow optional registration of multiple hardware authenticators
     (Touch ID, YubiKey, WebAuthn) for seamless unlock on trusted devices with fallback to the passphrase on new or unregistered devices.

- **Rate Limiting & Concurrency**
  - [x] Add a production-ready rate limiter with per-user + global caps (in-process sliding 60s window; generate-lock unchanged). Config: `rate_limit_*_per_minute` / `RATE_LIMIT_*` (`0` disables).
  - [x] Hook background cleanup jobs to purge expired sessions and chats proactively (`session::purge_expired_sessions` + `SESSION_PURGE_INTERVAL_SECS` background task).
  - [x] Durable chat history on **redb** via `HistoryService` (AEAD+AAD, CAS, PrepareCapture, multi-set `SetCache`, permanent `legacy_sets_json` migration, client `set_id`/`expected_version` + 409 sync-and-retry). See [design-history-store.md](design-history-store.md). Operator: delete `sets.json.migrated.bak` only after a stable redb release.
  - [ ] Enhance test concurrency across integration suites.

- **Error Handling & Logging**
  - [x] Standardize on JSON error responses with proper HTTP status codes rather than plain text (`http_error::HttpError` / `api_error` across `chatbot-server` routes; integration test `http_errors.rs`).
  - [x] Narrow error scopes; only catch expected exceptions and add contextual logging before rethrowing (`http_error` typed mappers: `map_session_err`, `map_user_store_err`, `map_history_err`, etc.).
  - [x] Centralize logging configuration with structured output (`chatbot_core::logging::init_logging`; `LOG_FORMAT=json|plain`, `LOG_ANSI`, `RUST_LOG`/`LOG_LEVEL`).

- **Code Quality & Style**
  - [ ] Enforce consistent formatting and lint rules via pre-commit.
  - [ ] Remove unused imports and dead code to reduce noise.

- **Privacy Modes**
  1. **Recoverable Mode**: Server-managed encryption with full account recovery.
  2. **Private Mode**: Client-derived keys for zero-knowledge storage.
  3. **Ephemeral Mode**: Memory-only sessions with no persistent data.
  See [design-privacy.md](design-privacy.md) for details.

- **Docker & Deployment**
  - [x] Optimize the `Dockerfile` with a multi-stage build so that only artifacts ship in the final image.
  - [x] Health checks for orchestrators — `GET /health` liveness JSON; Compose `healthcheck` on **webserver** (curl, honours `CHATBOT_BIND_ADDR` port); optional deep readiness via `GET /health?deep=true` (redb + voice-service probes, 503 when degraded).
  - [x] Provide sample deployment configurations (e.g., Docker Compose overrides, Kubernetes/Helm charts) for self-hosted and cloud environments (`deploy/compose/`, `deploy/helm/chatbot/`).
  - [ ] Automate production deploys on every push to `main` (Ansible playbook currently lives in a sister repo and is triggered manually).

- **LLM Provider Abstraction**
  - [x] Concrete generation dispatch with streaming (OpenAI-compatible + XAI adapters in `chatbot-server/src/providers/`: closed `GenerationProvider` enum, shared `messages` DTO with OpenAI-compatible serialization).
  - [ ] Document provider-specific fields (e.g., base URLs) and include example configs.
  - [ ] Break out LLM providers into a git submodule so they can be shared and consumed by other projects or front ends.
  - [ ] Establish semantic versioning and backward-compatibility guarantees for the provider interface.

- **Mobile Frontends**
  - [x] Capacitor Android shell — wrap existing web UI in native Android app (server-pull WebView)
  - [x] Native microphone plugin — bypass browser audio restrictions on mobile
  - [x] Screen-off voice — microphone FGS + lock-screen CallStyle Stop (POST_NOTIFICATIONS, no unlock)
  - [ ] Android Auto integration — **partial**: `CarAppService` / `VoiceScreen` implemented and usable on DHU/emulator; still open for production: replace `HostValidator.ALLOW_ALL_HOSTS_VALIDATOR`, Play-trusted install for real head units, production host allowlist. See [mobile-apps.md](mobile-apps.md).
  - [ ] iOS support via Capacitor (same codebase, low priority)
  - See [mobile-apps.md](mobile-apps.md) for full plan and AA distribution constraints.

- **Voice Mode** — Default TTS provider is `kokoro`.
  - [x] Silero VAD voice activity detection on **desktop/browser** (`static/deps/vad/`, `chat.js`).
  - [x] Native mobile VAD — record from speech-like start; barge-in on real speech (`REAL_SPEECH_MS`) in `NativeMicUtteranceVAD` (no Silero in WebView). Dual invariant: cough/"hey" must not stop TTS; sustained speech must, at confirm. See [mobile-apps.md](mobile-apps.md#tts-barge-in-dual-invariant-do-not-oscillate). Android Auto `VoiceScreen` stays RMS.
  - [ ] Whisper Large v3 turbo.
  - [ ] Smart Turn v2 by @trydaily.
  - [x] Kokoro TTS — vertically integrated into `chatbot-cuda` voice-service; select with `tts_provider: "kokoro"` in `.config.yml`. Supports per-sentence streaming (`/v1/tts/kokoro/stream`) using a thread→asyncio-queue bridge for true low-latency first audio. Default voice `af_heart`; configurable via `tts_voice`.
  - [ ] Fish Speech S2 — natively supports low TTFA streaming; evaluate for production use (code path exists; not production default).
  - [x] Parakeet STT — NVIDIA Parakeet TDT 0.6B v2 for speech-to-text, vertically integrated into `chatbot-cuda` voice-service. Supports compressed audio over the wire (hardware-accelerated AAC-LC with ADTS via WebCodecs, or WebM/Opus) and PCM16 WAV. Webserver overrides default body limit up to 50MB for arbitrarily long voice utterances.
  - **Webserver TTS surface (not a public API product):** browsers and native clients use only `POST /tts` (CSRF + deploy-time access policy) then `GET /tts_stream/{token}` for playback. There is no unauthenticated `/api/tts*` on the webserver; the GPU voice-service HTTP API is for the webserver to call as a backend client only. Gate who may use TTS with `tts_access` in `.config.yml` (or `TTS_ACCESS`): `anyone` (default, guests OK — good for LAN/local models), `authenticated` (logged-in only), or `premium` (premium tier only).

- **Documentation**
  - [ ] Host a `/docs` page or integrate with tooling like Redoc to expose interactive docs.
  - [ ] Consider publishing documentation to ReadTheDocs or GitHub Pages for auto-publishing from the repo.
