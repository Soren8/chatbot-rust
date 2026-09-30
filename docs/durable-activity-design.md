# Durable Activity Design

## Contract

Operations and generations are server-owned objects; HTTP connections are disposable
views. A dropped connection never cancels work and never creates a duplicate turn.
Desktop and Capacitor use one protocol, including session recovery, event replay
and explicit Stop.

This is an approved implementation design, not a description of deployed routes.
The storage, CAS and privacy boundaries in `docs/design.md`,
`docs/design-history-store.md` and `docs/design-privacy.md` remain authoritative.

## Current boundary

`POST /chat` in `chatbot-server/src/chat.rs` acquires a generation lease. The lease,
finalize closure and a copy of the encryption key live in the streaming response
body. `StreamCompletionGuard` in `chatbot-server/src/chat_utils.rs` persists partial
text when a polled body is dropped: a network drop therefore acts as Stop.
`chatbot-server/src/regenerate.rs` has the same ownership boundary.

A second send while leased gets 429 Busy through `map_prepare_policy_err` in
`chatbot-server/src/http_error.rs`. `fetchWithGenerateRetry` in
`static/session-client.js` loops on 429. Neither body ownership nor contention
retry can distinguish a lost view from an intentional cancellation.

## Server-owned generations

### Admission and lifetime

`POST /chat` and `POST /regenerate` opt into durable admission with
`X-Generation-Mode: durable`, the existing message/options or target-pair payload,
`set_id`, `expected_version` and an `Idempotency-Key`. Successful admission returns
202 with an NDJSON event view and `X-Generation-Id` (plus
`X-Generation-Base-Version`) headers. Replays return the same worker's view.
There is no `POST /generations`. Without the header these routes permanently retain
the legacy text/plain stream and disconnect-as-Stop behavior for older clients.

A background worker owned by `AppServices` in `chatbot-server/src/services.rs`
owns the provider stream, cancellation, privacy permit, generation reservation
and the admitting request's encryption key. Response bodies only subscribe to
its output. Dropping, aborting or never polling a response cannot release the
reservation or cancel inference.

The request's key lives until the generation it starts settles as completed,
stopped or failed, with a maximum generation lifetime of 30 minutes; it is then
zeroized. This is the existing per-request key model in
`docs/design-privacy.md#per-request-encryption-key-model`, not new key custody.
No standing key is installed in a session, activity registry or receipt.

On settlement, the worker writes the turn through the normal history
finalization and CAS/versioning path. Stopped generations save partial text,
preserving Stop → Edit. An `ended` event denotes generation settlement; `saved`
confirms history persistence, so the client can distinguish streaming from
saving rather than infer persistence from a closed connection.

### Reservations and authorization

The reservation is per `(user, set_id)`, using guest identity for guests.
Reusing an `operation_id` returns the existing generation, not another worker.
A different send while a generation runs returns 409 `generation_active` with
its generation descriptor. The client attaches to it and keeps the new message
queued; it does not run a 429 retry loop.

Version-changing set operations on an active set also return
`generation_active`. True rate-limit 429 responses remain distinct from
reservation contention. Existing set CAS still rejects stale versions.

The owner comes from authentication, never from a client-supplied user field.
Other users receive not-found responses. The same user may attach from another
tab or device. Every status, attachment and Stop request rechecks ownership.

### Event buffer and transport

Each generation has a RAM-only buffer of sequenced events:

```text
{generation_id, seq, type, channel, text}
type = delta | thinking | status | error | ended | saved
```

The buffer remains until the generation is saved plus a short grace period for
reconnecting viewers. Plaintext in this buffer follows the same RAM lifecycle
rules as `SetCache` in `chatbot-core/src/history/cache.rs`; it is not a new
plaintext durable store.

`GET /generations/{id}/events?after=N` uses fetch with NDJSON. It replays buffered
events after `N`, then tails new events. Subscribe first, then reread the buffer
to avoid a replay/tail gap. Sequence numbers let the client discard overlap.
A slow subscriber is dropped and reconnects; it never stalls inference.

Use fetch, not EventSource: custom headers, abort support, session restore and
WebView parity are required. Responses send `Cache-Control: no-store` and
`X-Accel-Buffering: no`. A non-sequenced heartbeat frame is sent every five
seconds. The client reconnects after 20 seconds without receiving a frame;
heartbeats do not advance its event cursor.

`GET /generations/{id}` returns status. `GET /activity?set_id=` lists running
generations for attachment on load or reconnect. These reads allow a viewer to
recover even when the admission response was lost.

`POST /generations/{id}/stop {operation_id}` is the only cancellation action.
Switching chats, detaching, dropping a connection or closing a tab does not Stop.

A server restart mid-generation loses that generation, as it does today. The
client shows it as interrupted and offers Retry. It must not represent a missing
worker as a completed or saved turn, or attempt upstream-stream resumption.

## Idempotent mutations

Every mutating request carries a client-generated `operation_id`, created before
its first send and preserved across transport/session retries. This covers
chat, regenerate, Stop, `delete_message`, `reset_chat`, set create/fork/delete/
rename/privacy, memory, system prompt, agent connection CRUD/check,
TTS admission and STT.

`update_preferences` writes absolute field values, so a replay yields the same state; it carries no receipt, and ordering relative to later preference writes is the client sync layer's responsibility.

The server records a receipt containing operation ID, user scope, request
fingerprint, status and replayable response in the same transaction as the
mutation. Cookies and CSRF are excluded from the fingerprint; refreshing a
session must not change the identity of the intended operation.

After rechecking authentication and ownership, a repeat returns the original
response. The same ID with different content returns 409 `operation_id_reused`.
An in-flight duplicate returns status rather than executing a second time.
Generation admission binds its receipt to the existing generation descriptor.

Authentication, CSRF and key failures do not consume an ID. The client refreshes
credentials/session state and resends that ID. Validation and CAS rejections
are recorded; changing a rejected payload, including its expected version,
creates a new operation ID rather than overwriting the recorded intent.

Receipts are retained for 24 hours. Client pending operations live only while
the page is open. Read-only POSTs such as `load_set` and `history_pair` are safe
reads with retry, not mutations requiring receipts.

## Client synchronization

`static/activity-sync.js` is a new framework-free UMD module. It receives fetch,
timers and RNG as dependencies, touches no DOM, and is tested through the
existing Node-vm harness pattern in
`chatbot-server/tests/fixtures/session_client_test.js`.

The module owns all transport: an in-memory outbox, safe-read retry for page-load
reads, unresolved mutation replay, generation attachment and set reconciliation.
Network errors use exponential full-jitter backoff, approximately 500 ms initially
with a 30-second cap and no fixed give-up. Online, focus, visibility and resume
triggers are coalesced rather than starting competing recovery loops.

Recovery order is restore session/CSRF, resend unresolved operations, attach
running generations, then reconcile set versions. An unresolved admission is
resent with its original ID before attachment discovery can lead to a new send.
An active-generation conflict attaches to that generation while retaining the
new message as queued intent.

Events are applied contiguously by sequence number. Duplicate events are ignored;
a gap causes replay from the last contiguous cursor. Only newly applied text
reaches rendering and sentence discovery. Connection closure is a transport
condition, not an ended event or an instruction to finalize a turn.

The UI projects sending, streaming, reconnecting, saving and needs-action states.
An error followed by settlement, or a failed status after an event view closes,
is terminal rather than an invitation to reconnect forever. Missing workers are
shown as interrupted, including recovered and regenerated responses, with retry
controls. Reader cancellation cleanup never delays view recovery.
`static/conversation-state.js` remains the pure reducer. `static/chat.js` renders
and dispatches intents rather than issuing direct fetch calls. Session/CSRF
mechanics in `static/session-client.js` remain reusable beneath the transport
owner during migration.

No third-party library is introduced: none supplies this combination of
idempotent mutations, resumable encrypted generations and WebView parity, and
there is no bundler requirement.

## Voice and TTS

Sentence discovery consumes newly applied text only; replayed chunks never
requeue sentences. Playback has a per-generation cursor. Recovered text after
a reload does not autoplay.

Keep `POST /tts` → `GET /tts_stream/{token}` as implemented in
`chatbot-server/src/tts.rs`. Idempotent admission returns the same token.
STT results are deduplicated so replay never submits a second chat turn.

The two-phase barge-in invariant in `docs/mobile-apps.md` is unchanged: capture
starts on speech-like input, while TTS stops only at confirmed sustained speech.
Confirmed barge-in sends explicit Stop; aborting a view is not cancellation.

Android Auto's native HTTP client in
`android/app/src/main/java/com/chatbot/app/car/VoiceScreen.java` must adopt
operation IDs, event replay and explicit Stop. This requires an updated APK;
server-pulled WebView assets alone cannot provide native HTTP parity.

## Boundaries

Guests remain RAM-only. Pending unsent operations are memory-only: reloading
while fully offline loses unsent messages, with the visible draft retained where
possible. There is no client-side persisted outbox and no JS-readable key.

Upstream model streams are not resumed after a server restart. This design is
for a single-process deployment; it does not introduce distributed reservations,
workers or event storage.

## Delivery phases

Each phase is independently shippable and uses failing-first tests. Legacy routes
remain working behind capability negotiation until supported clients migrate.

1. Add operation IDs and atomic receipts to existing mutations. IDs remain
   optional for legacy callers. Cover response loss, duplicate execution,
   fingerprint mismatch and rejection replay before changing handlers.
2. Add server-owned workers, RAM event buffers, durable `/chat` and `/regenerate`
   admission, explicit Stop and 409 attachment. Keep header-free legacy behavior
   permanently. Verify that disconnects do not cancel and that Stop saves partial text.
3. Introduce `static/activity-sync.js`. Move page-load reads and mutations first,
   then chat/regenerate. Exercise session recovery, outbox replay, contiguous
   event application and set-version reconciliation with injected transports.
4. Bring voice/TTS/STT and Android Auto to parity. Verify sentence and STT
   deduplication, playback recovery and confirmed barge-in; ship the native APK.
5. Retire body-owned stream guards, the 429 Busy retry loop, the
   `GenerateConnectionError` manual path associated with commit `9ba449f`, and
   legacy client code path after supported APKs migrate; header-free server routes
   remain compatible permanently. Transport abort remains view detachment for durable clients.
