# Privacy levels and user-owned coding-agent connections

**Status:** planned implementation, revised after code review. This document does not enable features or authorize deployment. Paths in implementation sections are relative to the `chatbot-rust` repository root.

Cross-project direction: [platform design](../../ai-platform-design/design.md). Parallel service work: [OpenCode service plan](../../.devcontainer/CODING_AGENT_SERVICE_PLAN.md). The service plan owns the native OpenCode wire contract and sanitized compatibility fixtures; this plan owns application policy, storage, routes, and UI.

## 1. Deliverables and parallel work

Stage A delivers Private/Non-private selection and enforcement for saved chats, including search and voice. Stage B delivers per-user connection settings and an authenticated, metadata-only connection test. The sandbox team can work independently on its listener and fixtures while the chatbot team implements Stage A and a fake OpenCode server for Stage B.

After implementation and operator rollout, these plans deliver a reachable native OpenCode service plus chatbot connection settings/health checks. The native service has its full authenticated API, but submitting chat content from the chatbot, presenting live tool activity, and reconnecting to agent runs are a subsequent consumer integration milestone. Tests of that future functionality must not be claimed as completed merely because its routes do not yet exist.

The application remains multi-user. Each user owns their connections; the first deployed **destination**, the operator's personal sandbox, is restricted to that operator by deployment policy. Its native API password grants authority over that sandbox's workspace and tool accounts. Supporting multiple independent destinations does not make any one shared sandbox multi-tenant.

### Fixed decisions for this implementation

| Concern | Decision |
| --- | --- |
| Saved chat modes | Three-level target: `private`, `standard`, `non_private`; missing legacy mode and new sets default to `private`. Currently only `private` / `non_private` are implemented. |
| Provider classification | Operator-declared `privacy_level`; omitted means `non_private`. `private` requires local or verified no-retention processing; `standard` covers reputable third parties with limited/anonymized retention, including qualified ZDR LLM endpoints, xAI search on ZDR teams (undocumented upstream retention caveat), and Brave standard 90-day / enterprise-ZDR search; `non_private` covers everything else. Verify the full route. |
| Eligibility | Lattice `private < standard < non_private`: a chat may use a destination at its level or stricter (`private` → private; `standard` → private/standard; `non_private` → all), still subject to account tier and other permissions. |
| History encryption | Current user-key encryption for all saved modes; neither Standard nor Non-private disables it |
| Guest behavior | Current RAM-only app history and free-tier model policy; describe it as temporary in this app, with independent upstream retention |
| Deferred storage modes | Recoverable/server-key storage and selectable Ephemeral chats |
| Connections | User-owned settings: name, service URL and Basic credentials; permitted destinations enforced separately by deployment egress policy |
| Connection privacy | All OpenCode connections remain `non_private`; users cannot promote them by editing a form or API request |
| Connection CRUD/health | Account settings, independent of the selected chat; never send prompts, names of chats, history, or files during a check |
| Future agent execution | Requires an owned connection and an authorized `non_private` set, checked when submitting content; `standard` does not authorize OpenCode |

## 2. Source map and implementation constraints

| Area | Relevant current code |
| --- | --- |
| Provider and config parsing | `chatbot-core/src/config.rs`, `config_source.rs`, `.config.yml.example`, `.config-version` |
| Stored sets and caches | `chatbot-core/src/history/{types,api,cache,ops,crypto}.rs`, `history/store/{mod,chunks,tables}.rs`, `history/migration.rs` |
| Prepare and finalization | `chatbot-core/src/session.rs`: `ChatService`, `PrepareCapture`, `GenerationLease` |
| Router dependencies and identity | `chatbot-server/src/{services,identity,request_context,lib}.rs` |
| Chat dispatch and model summaries | `chatbot-server/src/{chat,regenerate,generation_deps,home}.rs`, `providers/generation.rs`, `search.rs` |
| Voice authorization and delayed synthesis | `chatbot-server/src/{stt,tts,policy}.rs`, `tts/{store,backend}.rs` |
| Shared frontend | `static/{chat,conversation-state,session-client,tts-playback,voice-capture,native-audio}.js`, `static/templates/chat.html` |
| Native direct HTTP path | `android/app/src/main/java/com/chatbot/app/car/VoiceScreen.java` |

Two existing behaviors are particularly important. Generation locks in `ChatSessionStore` are keyed by **login session ID**, not user/set, so they do not coordinate two devices accessing one set. TTS is two-step: `POST /tts` admits text and returns a token; the actual upstream request occurs during `GET /tts_stream/{token}`. Neither today's TTS request nor STT upload carries the set identity.

Use explicitly owned dependencies in `AppServices` for tests. Preserve the existing `HistoryService` database handle and CAS semantics. Keep existing tier, credential-cookie, CSRF, cancellation, and voice barge-in behavior except for the explicit policy additions below. Any changed native request contract needs matching native coverage and an APK handoff, not just a webserver asset rebuild.

## 3. Stage A1: privacy types and destination policy

### Config and policy surface

Introduce a closed `PrivacyLevel` enum serialized as `private` / `non_private`. Use separate default functions for legacy chat mode (`Private`) and destination eligibility (`NonPrivate`); a single default used for both would silently approve new providers. Reject unknown explicit enum values.

Add `privacy_level` to `ProviderConfig`. Preserve the existing free/premium checks and sanitized frontend summaries. A paid API is not automatically private, a local URL is not proof of no logging, and `xai_zdr: true` / `store: false` is not sufficient evidence of full upstream ZDR. Operator classification describes the configured account, endpoint and processing chain. Existing fallback providers default to Non-private as well.

Specify auxiliary destinations explicitly, using these proposed config fields for the first implementation:

| Field | Applies to | Missing value |
| --- | --- | --- |
| `llms[].privacy_level` | Model inference route | `non_private` |
| `llms[].search_privacy_level` | That route's provider-native search, e.g. xAI search | `non_private` |
| `brave_search_privacy_level` | Brave queries from the application's search tool | `non_private` |
| `stt_privacy_level` | Entire configured STT path, including voice-service storage/processing | `non_private` |
| `tts_privacy_level` | Entire selected TTS synthesis path, including any downstream cloud service | `non_private` |

All missing values in this table mean `non_private`. The voice values classify the full resolved path, not only the first local HTTP hop; changing a local service to a cloud proxy requires operator reclassification. Surface these values through owned config/policy handles. Do not assume that an approved model automatically approves its search backend.

The centralized eligibility predicate permits a destination iff the task is Non-private or that destination is classified Private. Apply it independently of account tier, TTS access and STT-enabled settings. For a disallowed selected/default model, return `403 privacy_restricted` before any provider transmission, even if another model would be eligible. Do not secretly change model or privacy mode. Reject an explicitly requested but incompatible search before inference begins rather than silently answering without search. Evaluate any actual fallback destination against the same task policy.

Approve illustrative local example routes only with comments describing operator verification; leave remote examples Non-private by default. Update the example-key validation and deployment config version when introducing this policy. Existing saved chats default to Private, so rollout must tag the operator's existing qualified routes before traffic resumes.

### Acceptance for A1

New tests cover the full mode/eligibility truth table, unknown values, opposite defaults for sets and providers, fallback-provider classification, independent tier restrictions, and native/Brave search distinction. Owned routers must not obtain these values from unrelated global config. Required provider configuration checks use examples and test fixtures, never live secrets.

## 4. Stage A2: one canonical encrypted set-policy record

### Storage decision

Use a small additional encrypted `SETS_POLICY` row keyed by opaque `SetId`, owned by the existing history database, containing `{format_version: 1, privacy_level}`. This is the canonical stored mode for **all existing history formats**. Bind ciphertext to normalized owner, set ID and a distinct policy AAD/domain; use the established AEAD primitives with fresh nonces. `SETS_META` remains structural plaintext only.

Rationale: reusing `SETS_NAME` would make name-only writers responsible for preserving policy; putting the field in both legacy payloads and chunk headers would require a new listing path or duplicate policy projection. A separate small row allows `list_sets` to read names and policy without decrypting history and lets normal history writes leave policy untouched. It adds a table, but no parallel authoritative copy or full history rewrite.

Define store operations for loading policy, creating an initial policy with a set, and changing policy with CAS. Add policy projections to `SetSnapshot`, `SetSummary`, `SetPage`, and `PrepareCapture` as needed. Those are views of the authoritative row, not another place to save it. Generic history commits must preserve the durable policy and must not accept a mode change by trusting an arbitrary snapshot field.

### Legacy reads, mutations and versioning

1. Verify ownership and set existence before reading policy. A missing row for an existing legacy set means Private. A missing set, authentication failure, malformed policy, unsupported policy format or failed decrypt is an error, never a fallback to Non-private.
2. Newly created/default sets write an explicit Private policy in the same transaction as their initial history records. Fork creates a new policy with the source mode; source-set mode is read under the coordination defined below. Existing migration paths seed Private and never overwrite an already valid policy.
3. Ordinary append, regenerate, reset, rename, memory/prompt change and chunk conversion preserve policy. Deleting a set removes its policy row with the other set records. No raw history mutation helper can downgrade policy.
4. A mode change checks `expected_version`, updates policy and advances the set version in one write transaction. For a whole-blob set, its existing version-bound ciphertext must be re-sealed; for a chunked set, the manifest must be re-sealed for the new version. Unchanged pairs/images need no re-encryption. Share the existing commit logic through a narrow transaction path rather than composing two independently committed operations.
5. Publish/invalidate caches after commit. Cache validity remains tied to set version. Read meta and policy consistently; do not cache an old mode against a newer version. Reapplying the already current mode is a no-op only after checking ownership, key and the supplied version.

### Upgrade and rollback contract

Allocate the next history schema version when adding the policy table. New code rejects a history schema newer than it supports. Legacy reads remain supported without requiring every user's key at startup; the policy row is materialized on that user's subsequent authorized writes as appropriate.

**Existing older binaries do not reject newer schema numbers and cannot enforce this policy.** A schema or `.config-version` increment does not fix those binaries. Once privacy selection is exposed, pre-feature images are unsupported for rollback against live data. Before deployment, the IaC/operator rollout must restrict automatic/manual rollback candidates to privacy-capable images, or stop traffic and restore a matched pre-upgrade database/config backup with an explicit loss-of-newer-data decision. The deploy config gate is a minimum config-schema check, not a data-reader compatibility check. Record this release boundary in the handoff; do not change `iac` as a side effect of this implementation without a scoped follow-up.

### Acceptance for A2

Test legacy whole blobs, chunked data and legacy import, missing versus corrupt policy, both users and both keys, all mutation paths above, ciphertext ownership binding, reopen/restart and warm/cold listing. Assert listing does not open history/pairs. Test CAS conflicts and fault/transaction rollback so policy and version cannot commit separately. Exercise newer-schema refusal in the new reader and document that it does not retrofit refusal into old releases.

## 5. Stage A3: concurrency and text/search enforcement

### A set-level coordinator, separate from session generation locks

Add an owned `SetPrivacyCoordinator`, shared by all `ChatService`/router clones handling the same history store. Its keys are `(normalized user, SetId)`. Retain current session generation locks; they address a different issue. For the current single-webserver process, shared/exclusive RAII permits suffice:

- Content operations acquire a shared permit **before** loading the authoritative mode and retain it while upstream work can still send data. This includes chat/regenerate streams, every search iteration and retry, and active STT/TTS synthesis.
- Mode changes acquire an exclusive permit using a non-blocking attempt. If any content operation is active, return `409 privacy_busy` without a write. Hold the permit across CAS mutation, cache publication and invalidation of queued voice tokens. A stale version still returns the established `409 version_conflict` shape.
- Both acquisition and policy mutation use the same coordinator, so there is no check-then-send gap. Release permits on error, abort, dropped response, timeout and completion. No redb transaction or blocking map mutex is held across a network await.
- Do not evict a coordination entry while any live permit or acquisition references it; two devices must never acquire different locks for the same set. Independent owned test services remain isolated. Multi-process writers/replicas would need cross-process coordination and are not covered by this in-process guarantee.

Resolve the actual set ID first (including legacy name/default lookup), then acquire the permit and reload its policy/content before preparing outbound input. A `PrepareCapture` records the initiating mode and version. Finalization CAS still protects history writes; it is not the privacy transmission gate. Ordinary mutations cannot change mode. Forks inherit the source mode under a shared permit, so a concurrent mode change cannot produce a silently relabeled branch.

### Enforcement and HTTP behavior

`chat.rs` and `regenerate.rs` apply the policy before opening any real provider stream, including fake-independent production paths. Resolve search requirements before sending the initial prompt. Recheck the eligibility of a different fallback target; no fallback on a privacy denial. Policies are server derived: ignore/reject caller-supplied mode overrides on these requests, and never use the existing `encrypted` boolean as permission to relax privacy.

Add authenticated, CSRF-protected `POST /set_privacy`:

```json
{"set_id":"<opaque ID>","expected_version":7,"privacy_level":"non_private"}
```

Require the valid per-request key. Return `{status:"success",set_id,version,privacy_level}`. Use `400` for invalid/missing fields, existing identity/key errors for those failures, `409 version_conflict` with `current_version` for stale writes, and `409 privacy_busy` for active work. Return `403 privacy_restricted` with a safe destination/category label when dispatch is disallowed; do not save such denials as assistant turns or retry them via the existing 401 session-refresh path.

A mode change affects future transmissions. The UI makes downgrading deliberate and explains the consequences; an upgrade cannot undo earlier remote retention. The first implementation refuses changes during an active operation rather than pretending it can retract sent data.

### Acceptance for A3

Use two independent login sessions for the same user/set. Pause a fake outbound request behind a test barrier; a mode update from the second session must receive `privacy_busy`. After releasing the operation, the update succeeds and subsequent disallowed dispatches cause zero outbound calls. Also test cancellation/drop permit cleanup, a fork during mode mutation, unrelated users/sets remaining unblocked, stale cache behavior, and both chat and regenerate. Avoid timing-based sleeps for race assertions.

## 6. Stage A4: voice privacy and queued work

### Attach the initiating conversation to voice requests

Extend `POST /tts` JSON with `set_id` and `POST /stt` multipart with `set_id`. For authenticated calls, verify the key and owned set and derive mode under its shared permit. Client-supplied `privacy_level` never authorizes anything. Do not consult whichever set happens to be active in session RAM: another tab may have changed it.

Browser and Capacitor JS capture identity when recording begins and when a TTS playback source is created, carry it through retries/queued clips, and discard/cancel results when that conversation generation is no longer active. Manual dictation, voice mode, play-history-message, regeneration/autoplay, native microphone encoding and desktop capture must all pass through this binding. In STT, parse the bounded multipart metadata before dispatch; the current code breaks on the first audio field, so merely appending a set field after audio is insufficient. Preserve the audio size limits and never log audio/text payloads while parsing.

Compatibility behavior is explicit:

| Caller | Privacy used for voice |
| --- | --- |
| Authenticated + valid owned `set_id` + key | Authoritative stored mode |
| Authenticated + no `set_id` (old client) | Private only; no implicit active-set lookup or downgrade; require the existing user key to be valid |
| Authenticated + invalid/foreign/deleted `set_id` or invalid key | Reject, with no upstream request |
| Guest without `set_id` | Existing guest access policy and deployment destinations; no Private guarantee |
| Guest with `set_id` | Reject instead of reading an authenticated set |

An authenticated legacy unbound request uses a server-created immutable Private context, with eligibility checked before STT dispatch or TTS admission and again at delayed synthesis. It has no set permit because no set mutation can relax that immutable context; never attach it retroactively to the active set. It can use only approved Private voice destinations; otherwise return a policy/context error explaining that updated clients can bind a Non-private chat. This preserves safe old-client use without silently approving cloud voice. Inspect `car/VoiceScreen.java` separately: it constructs HTTP requests directly and is not updated by server-pulled JS. If it needs request/auth changes, update and verify its native path and build an APK. Preserve the two-step TTS protocol and native barge-in invariant from `AGENTS.md`.

### TTS authorization must survive the pre-sign gap

At `POST /tts`, authorize the mode/destination under a shared permit and insert a pending token containing the cleaned text, opaque owner/set binding (or explicit legacy/guest binding), captured required privacy, and resolved synthesis destination/voice/codec needed for the job. **Never store the user's decryption key in the token.** Release the permit after insertion; merely queued or cached clips must not keep privacy settings locked for the token's ten-minute lifetime.

At `GET /tts_stream/{token}`, obtain the binding without awaiting under the token-map lock, acquire that set's shared permit, then re-fetch/begin the token (it may have been invalidated). Check the captured destination remains configured and eligible for the captured required privacy; use that destination, not a newly selected backend. Hold the permit through synthesis/its downstream sends. Cached audio has no new upstream send. The opaque token remains the browser-compatible playback credential; no new enc-key header is required on the GET.

A successful mode mutation invalidates **all pending/cached tokens for that set** while holding its exclusive permit. Active synthesis prevents the mutation with `privacy_busy`; queued tokens do not. An old token must never start a Non-private synthesis after a successful switch to Private. GET/POST/mutation follow coordinator-before-token-map order, and GET rechecks token existence after acquiring the permit. State disappears on restart as it does today.

STT holds the shared permit for its one outbound operation. Retried voice calls retain the original set binding. UI handling for a mode change stops recording/playback for that local set; other clients' stale queued tokens fail rather than silently inheriting the new context.

### Local logs and policy configuration

Remove transcript content from the affected voice logs: `tts.rs` currently logs text previews, including a warning for empty sanitized output; Android Auto logs transcriptions and response snippets. Inspect the corresponding voice-service temp/log path and browser `client_logs` forwarding before labeling the complete voice route Private. Use lengths, operation IDs and bounded error categories instead of content or authorization tokens. This is a focused audit of the voice path being certified, not a declaration that enabling a config flag proves arbitrary services are private.

### Acceptance for A4

Test STT/TTS with explicit set identity, legacy missing identity, malformed/foreign IDs, guest access, both multipart field orders, and zero outbound calls on denial. Test a queued Non-private token followed by a Private switch; an active synthesis concurrent with a mode change; token replay/cancel; backend config changes between POST and GET; and no key retained by the token. Verify all client submission paths carry their initiating set, and no stale recording is submitted as a turn to the newly selected chat. Run relevant voice behavior tests as well as syntax checks.

## 7. Stage A5: shared UI and release

Return `privacy_level` from set create/list/load/fork responses. `GET /` continues to publish only sanitized model metadata, extended with privacy/search eligibility and sanitized voice capabilities. Avoid copying secrets or provider base URLs into `APP_DATA`.

Display a persistent `🔒 Private` indicator near the current chat and offer a clearly labeled Non-private selection in chat settings. Explain that both modes keep this application's saved history encrypted; Non-private allows other services to retain data, use it for training where their terms allow, or save plaintext transcripts. Use text labels, not color alone. Existing and new sets initially show Private; guest copy says "Temporary in this app" and distinguishes provider retention.

For saved chats, disable send/search/voice until the selected set's policy has loaded; guest chats have no saved-set loading prerequisite. Filter model choices by both tier and privacy; preserve an incompatible last selection as unavailable with an explanation rather than silently submitting it or switching providers. Mode UI updates only after server acknowledgement, respects set-version/generation fencing, and handles `privacy_busy` separately from a version refresh/retry. An explicit mode change is not automatically retried into a different chat after a set switch.

Deliver Stage A as ordered commits: config/predicate and tests; storage and migration tests; coordination/dispatch and HTTP tests; voice binding/token tests; shared UI and docs. Intermediate commits must keep the existing suite runnable; do not expose a Private guarantee in UI before all in-scope outbound paths enforce it. Request approval before altering existing tests; preserve their behaviors while adding cases and explain any necessary fixture changes for new required struct fields.

Suggested targeted commands (new targets must actually be created and contain the described tests):

```bash
testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust --package chatbot-core --lib --filter config::tests::config_example_has_no_unknown_keys --exact
testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust --package chatbot-core --lib --filter history::
testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust --package chatbot-server --test privacy_policy
testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust --package chatbot-server --test js_syntax
```

Select existing voice/sets integration targets based on touched paths and run the appropriate new voice-policy tests. Tee logs to `temp/test-logs/`; verify nonzero selected tests and do not hide failures by narrowing. Build a debug APK through `testctl` if Java/native changes occur. Update `docs/design.md`, `docs/design-privacy.md`, config examples and release notes with actual guarantees and legacy-client behavior. The host operator deploys classification config and a privacy-capable rollback baseline before enabling the release, then rebuilds/restarts webserver; matching APK installation is needed when native code changed.

## 8. Stage B1: user connections and deployment egress policy

Connection settings become available after Stage A's policy exists. An authenticated enabled user enters a name, OpenCode base URL, Basic username and password. Connections are owned by the logged-in user, not an owner field supplied by the request. A user can manage/test connections even while viewing a Private chat; these actions do not submit conversation data.

Separate two data structures:

| User-owned encrypted connection | Deployment-owned policy |
| --- | --- |
| Opaque ID, name, `kind: opencode`, canonical base URL, Basic username/password, revision | Feature enabled, eligible accounts, whether public HTTPS destinations are allowed, restricted/private target exceptions with allowed accounts, exact base URL, approved resolved addresses and transport |

Proposed configuration is `external_connections` with `enabled: false`, `allowed_users: []`, `allow_public_https: false`, and `targets: []` by default. `targets` are **egress exceptions/restrictions**, not a mandatory connection catalog. An operator may enable public HTTPS for eligible users without configuring every public service URL. A matching target restriction is evaluated before the general public rule, so it cannot be bypassed by that rule. The initial personal sandbox gets an exact target rule for its private URL, operator account and approved address/port; other users cannot probe or use it through the chatbot. Optional UI suggestions can come later; first release accepts URLs rather than making server configuration the user's connection record.

Specify each target as `{id, base_url, allowed_users, allowed_ips, allow_tunneled_http}`. IDs and canonical base URLs must be unique, account lists nonempty, and `allowed_ips` a nonempty list of parsed exact IP addresses (not broad CIDRs). `allow_tunneled_http` defaults false. Conflicting account restrictions on the same reserved IP/port are invalid configuration. The parser validates target users against the feature's eligible accounts; account existence is checked at request time using the account service. Default public HTTPS port is 443; nonstandard ports require an explicit target rule.

Example of the proposed configuration for an operator-installed SSH/private tunnel terminating on the **chatbot host**; these are placeholders, not current working config:

```yaml
external_connections:
  enabled: true
  allowed_users: [operator-account]
  allow_public_https: false
  targets:
    - id: personal-sandbox
      base_url: http://127.0.0.1:14096
      allowed_users: [operator-account]
      allowed_ips: [127.0.0.1]
      allow_tunneled_http: true
```

The tunnel forwards that local endpoint to the agent host's authenticated loopback publish; it must be installed and restricted by the operator. Without the tunnel the check reports unavailable, and the application does not try a public route. An HTTPS private endpoint uses the same target structure with certificate verification and `allow_tunneled_http: false`.

Targets that are explicitly private or restricted must also reserve their destination IP/port for the allowed accounts; an alternate hostname or literal IP must not bypass a hostname restriction. New saved endpoints are not automatically trusted because a user has a password. Endpoints, names and credentials are encrypted user data; policy exception URLs are operator configuration and contain no passwords. `kind=opencode` has fixed Non-private eligibility in server code; reject user attempts to submit `privacy_level: private`.

### Outbound validation contract

All checks and later agent operations use one narrow `OpenCodeClient` with injected resolver/transport for tests. Creation and editing perform lexical/policy validation but no network request; DNS and connection checks occur only on explicit check/use.

1. Parse with the URL library; allow HTTPS, or an exact operator-authorized loopback/private-tunnel HTTP exception. Reject userinfo, query, fragment, unsupported schemes, ambiguous/encoded path traversal and nonconfigured ports. Normalize host/default port/path once; allow an explicit reverse-proxy base path with safe segment joining. API method/path are chosen by the adapter, never provided as arbitrary user input.
2. Public HTTPS routes may resolve only to globally routable addresses. Deny loopback, link-local, private/reserved/unspecified/multicast addresses and metadata services by default, including IPv6 and IPv4-mapped forms. A narrowly scoped target exception may permit specified private/loopback endpoints, not link-local cloud metadata or entire internal networks.
3. Re-resolve and authorize at each new connection; require all candidate addresses to be eligible and **pin the checked addresses to the actual HTTP connection**, preserving hostname/TLS SNI validation. Disable redirects and ambient proxy settings. Recheck deployment policy for each operation and bind client pools to connection revision/policy identity so DNS or edits cannot reuse an unauthorized route. This must be tested through the injected resolver, not only by string matching URL hosts.
4. Send only the adapter's Basic auth and required protocol headers. Never forward chatbot cookies, CSRF/enc-key headers, browser authorization, or arbitrary directory headers. Verify TLS certificates; no `accept_invalid_certs` fallback. HTTP exceptions require a documented encrypted tunnel/private transport; being on a LAN alone is not sufficient to send Basic credentials in cleartext.

This is application egress policy, not remote sandbox isolation. Native OpenCode authenticates the whole service; each user must connect only to an environment they are authorized to control.

## 9. Stage B2: encrypted connection service

Introduce an owned `ConnectionService` in `chatbot-core`, injected via `AppServices`. Keep credentials out of `UserStore`/`users.json` and out of the history API. Use a dedicated redb at `${HOST_DATA_DIR}/connections/redb`, opened once per owned service, with atomic per-record operations. This avoids a second handle to the history database and avoids making `HistoryService` own non-history account settings.

Use existing vetted AEAD/HKDF libraries and the encryption pattern already used by history, with a **connection-specific** domain/derivation and unambiguous AAD binding owner + opaque connection ID + schema + revision. Never reuse a history blob kind. Store URL, label, username, password and any diagnostic metadata in ciphertext. Plain index fields are limited to opaque ID, ownership and CAS revision. Avoid secret-bearing `Debug` output. Decrypt only with the valid per-request user key, release plaintext/keys at request end, and never retain that key for background checks.

Define create/list/update/delete with connection-level revision CAS. PATCH omitting a password preserves it; a supplied empty password is rejected. Edit URL/credentials invalidates last-check status. Delete removes the local connection only; it does not revoke the remote password or delete OpenCode sessions/files. Password recovery remains subject to the current key model; no plaintext recovery copy. Last-check results are timestamped observations, not a persistent authorization grant, and may be kept only in a bounded process-local cache keyed by owner/ID/revision.

Revoking a destination in deployment policy immediately blocks check/use, not an eligible owner's ability to list/delete the encrypted record or edit it to a permitted URL. Return a sanitized `blocked_by_policy` availability state that overrides a stale successful check. Validate the complete resulting endpoint on create/edit; local deletion needs no remote destination approval. Global feature/account access revocation remains a separate gate, with operator support for cleanup if the account is no longer eligible.

Initial service limits: 16 connections per user, 128-character name, 2,048-character base URL, 256-character Basic username (no colon/control characters), 4,096-byte password (no control characters), and 16 KiB JSON request body. Name, URL and credentials must be nonempty; the form may prefill username `opencode`. Use established account normalization and existing key verifier before any decryption. Open a newer unsupported connection schema only as an explicit error; no silent overwrite or fallback file.

## 10. Stage B3: settings API and UI

Every route requires login, valid user key and feature/account eligibility. Ownership is derived from authentication; return the same `404 connection_not_found` for unknown or other-user IDs. Require CSRF on writes and checks; GET performs no external I/O and returns `Cache-Control: no-store`. A request never needs a selected set ID.

| Method/path | Input and result |
| --- | --- |
| `GET /agent_connections` | Redacted own records: ID, revision, name, kind, canonical URL, username, `has_password`, fixed privacy level, timestamped last-check result if available |
| `POST /agent_connections` | `{name,kind,base_url,username,password}`; lexical/policy validation then encrypted save; `201` with redacted record; no automatic health request |
| `PATCH /agent_connections/{id}` | `expected_revision` plus changed fields; partial update, remote identity edits clear check state; `200` redacted record |
| `DELETE /agent_connections/{id}` | `expected_revision`; `204` on success, no remote deletion or credential revocation |
| `POST /agent_connections/{id}/check` | `expected_revision`; bounded `GET /global/health` only, followed by a revision/ownership recheck before recording status |

Use `400` for malformed fields, `403` for disabled/forbidden feature or target, `409 connection_version_conflict` with current revision for stale edits/checks, and `413` for oversized input. Local auth/key failures retain current semantics. Remote `401/403` must map to a safe `502 agent_auth_failed`, **not** a chatbot `401` that triggers login refresh. Map timeout to `504 agent_timeout`; network/TLS/bad JSON/unhealthy service to bounded `502` categories. Do not relay remote response bodies, headers, stack traces or credential challenges.

Health checking uses a 3-second connection timeout, 10-second total deadline including DNS/body, 64 KiB response cap, two concurrent checks per account and a modest per-account check rate limit (initially 6/minute). Return `{status:"reachable",version,checked_at}` only for authenticated JSON matching the service health shape. Health success establishes reachability/authentication, **not** support for every future session API. Snapshot connection revision before calling; deletion/rotation/policy revocation during a check prevents stale success publication. Already-sent credentials cannot be unsent; UI/documentation must not imply that deleting a record revokes remote access.

Add a shared Connections settings section with add, edit/rotate, test, remove and explicit Non-private description. Display the URL as an address reachable **from the chatbot server**, not the phone/browser. Inputs containing passwords are transient form values, cleared after submission, never returned by list/edit APIs, persisted in local/session storage or put in `APP_DATA`. Existing ordinary chat/voice remains independent when the service is offline. Allow testing from a Private chat because the check sends only service credentials and protocol metadata; future task submission still requires Non-private.

## 11. Stage B4: verification and cross-repo handoff

Use an in-process fake service with dummy Basic auth, explicit resolver/transport, and owned account/key stores. Sandbox startup is not a prerequisite for these tests.

| Test group | Required behavior |
| --- | --- |
| Ownership | Users can store distinct endpoints; another account cannot list/read/rotate/delete/check them; guest and invalid-key calls fail |
| Privacy separation | CRUD and metadata check work while viewing Private or no chat; the shared future content-eligibility predicate rejects OpenCode for Private. Do not count a nonexistent run endpoint as a meaningful negative test |
| Egress | Public HTTPS policy, restricted sandbox accounts, alias/literal-IP bypass, mixed DNS answers, DNS rebinding, IPv6/mapped IPs, redirects, ambient proxies, TLS failure, encoded URLs and private HTTP exceptions |
| Lifecycle | Revision conflict, URL/credential rotation, delete during check, policy revocation, no stale health result, offline service doesn't break chat/home |
| Storage | Reopen with valid key, wrong-user/key rejection, ciphertext tamper/swap, no URL/password/label markers in DB or error/log output, atomic concurrent updates |
| Health | Valid Basic response, wrong credentials, malformed/versionless/oversized JSON, slow DNS/connect/body, limits and sanitized upstream errors |
| Frontend | Same browser/Capacitor flow, safe rendering of names/URLs/errors, password never echoed, settings independent of selected set |

Suggested new target: `chatbot-server/tests/agent_connections.rs`, with new core connection tests in its module. Run through `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust --package chatbot-server --test agent_connections`, plus the targeted core tests and `js_syntax`. Keep existing tests; seek approval before modifying their expectations. CI provides the full release suite.

For the integration handoff, consume the sandbox team's sanitized health/auth fixtures and verified API version. After the operator deploys the listener and network route, the operator account adds its URL/credentials, checks it while viewing **either privacy mode**, and sees a redacted reachable result. An unrelated account cannot probe the restricted personal endpoint. Neither operation creates an OpenCode session or transmits a chat. Record actual version and transport evidence; exchange passwords outside tracked docs.

For the subsequent execution milestone, retain these boundary requirements: map owned connection + chat + run to backend-created remote session IDs; allow only those sessions and explicitly verified descendants into the UI; filter live events before user delivery; recover snapshots across SSE disconnects without blindly retrying side-effecting prompts; permit cancellation of owned work regardless of the current UI chat selection. Native session/config/auth/file APIs must never be exposed as an arbitrary proxy. Project directories select execution context, not filesystem isolation. Connection deletion, remote transcript deletion and workspace deletion are separate actions.

## 12. Completion and operator decisions

Each stage's handoff records implemented behavior, tested targets, known compatibility limits, and exact host actions. Plans and mock tests can complete without deploying live services. Runtime rollout remains operator-controlled.

Before live use, the operator supplies provider/search/voice classifications, connection-eligible accounts, the personal service's exact egress/transport exception, and the rollback-compatible image baseline. These are deployment values, not reasons to leave application ownership, locking, storage, or request semantics undecided. Background agent key custody, arbitrary workspace provisioning, Recoverable storage and Ephemeral conversations remain separate designs.
