# Privacy Design Specification

## Design Rationale
Our privacy modes were created to offer users progressive security options without sacrificing usability. This balanced approach emerged from several key considerations:

- **Security Trade-offs**: Server-side encryption (Recoverable Mode) protects against external data theft but remains accessible to system administrators
- **The password reset dilemma**: Password-derived encryption (Private Mode) provides isolation at the cost of unrecoverable data
- **LLM logging risks**: Private Mode restricts providers to prevent opaque cloud logging
- **Tempest use cases**: Ephemeral Mode meets journalist/whistleblower needs for digital vapor trails
- **Hybrid reality**: Local GPU availability allows Private Mode without actual system hosting
- **User experience focus**: Modes map to clear mental models rather than abstract security classes

## Privacy Modes

We are moving to a **Per-Chat Privacy Model**. Users can choose the privacy level for each specific conversation.

### 1. Private Mode (Zero-Knowledge) [Current Default for Password Users]
*   **Best for:** Sensitive personal data, intellectual property, private matters.
*   **Key Management:** **Client-Derived.** The encryption key is derived directly from the user's secret (login password or separate storage password). The server *never* persists this key.
*   **Recoverability:** **None.** If the secret is lost, this data is mathematically irretrievable. Password resets will cause these chats to become inaccessible.
*   **OAuth Implication:** OAuth users must set a separate "Storage Password" to use this mode.
*   **Provider Access:** User should use local OpenAI-compatible providers (e.g. Ollama, LM Studio) for maximum privacy.

### 2. Recoverable Mode (Server-Managed) [Planned]
*   **Best for:** General tasks, coding assistance, OAuth users.
*   **Key Management:** **Server-Managed.** The encryption key is stored on the server, protected by a system master key.
*   **Recoverability:** **High.** Password resets or OAuth re-authentication allow full access to be restored.
*   **OAuth Implication:** This is the **default** mode for OAuth users.

### 3. Ephemeral Mode (Incognito) [Partially Implemented]
*   **Best for:** "Digital vapor trails", quick questions, testing.
*   **Key Management:** None (Keys exist only in volatile RAM).
*   **Recoverability:** **Impossible.** Data is destroyed on session end or inactivity.

## Risk Mitigation (User-Managed Security)

### 1. Recovery Kit (Emergency Access)
*   **Concept:** A user-downloadable file generated upon account creation/update containing the encryption key or salt.
*   **Usage:** Allows unlocking "Private" chats after a password reset.

### 2. Chat Export (Local Backup)
*   **Concept:** Ability to "eject" data from the system.
*   **Mechanism:** Server generates plaintext/JSON export using the active session key.
*   **Usage:** Users can locally backup their Private chats.

## Implementation Details

### Architecture & Authentication Matrix

| Feature | Password Auth (Current) | OAuth (Planned) |
| :--- | :--- | :--- |
| **Default Mode** | **Private** (using Login Password) | **Recoverable** (Server Key) |
| **Private Chats** | Implicit (uses Login Password) | **Requires separate Storage Password** |
| **Recoverable Chats** | Optional (Server Key) | Native / Default |
| **Account Recovery** | Only restores access to Recoverable Chats | Only restores access to Recoverable Chats |

## Per-Request Encryption Key Model
*Implemented June 2026*

Authenticated chat data requires **two independent secrets per request**:

1. **Session cookie** — bearer token proving the HTTP session is logged in.
2. **Enc-key cookie** (browsers: last-used `enc_key` and per-account `enc_key-{username}`) or **`X-Enc-Key` header** (tests / non-browser) — the client-derived Fernet data key. Page JS does not read or send this key.

The server validates the presented key against a per-user **key verifier** (HMAC-SHA256 over the key material) before any decrypt. The key exists in server RAM only for the lifetime of that request (**not** a standing copy in the session store), then is zeroized. Login establishes/rotates the verifier but **does not retain the key** after the redirect.

### Threat model addressed

| Attack | Mitigation |
| :--- | :--- |
| Stolen session / remember cookie used on another machine | Server has no standing key; other machine has no `enc_key` cookie → decrypt fails (401). |
| XSS reading the Fernet key from JS | Enc-key cookies are HttpOnly. Page JS does not unwrap or send the key. XSS can still scrape already-decrypted chat in the DOM. |
| XSS exporting login to another machine | Remember and enc-key cookies are HttpOnly (XSS cannot copy those). There is no `/login/keyauth`; the Fernet key is not a login credential. |
| Full browser profile theft | Cookie jar + profile copy still wins. |
| Server compromise while user idle | Data persisted to disk is guaranteed end-to-end encrypted (AEAD ciphertext). In RAM, plaintext working snapshots are evicted and wiped after the idle TTL expires. Server stores no standing master key. |

### In-Memory Plaintext Handling & RAM Lifecycle

End-to-end encryption is guaranteed for all data **persisted to disk** (stored in `redb` as AEAD ciphertext via `HistoryService`).

In contrast, **plaintext in memory is required during requests**, because LLM backends (both local inference engines and upstream APIs) cannot interact with or process ciphertext. When generating completions or assembling prompt context, chat history, memories, and system instructions must exist unencrypted in RAM.

To balance performance with security:
- The server maintains a process-local working snapshot cache (`SetCache` in `chatbot-core/src/history/cache.rs`) that temporarily holds decrypted snapshots (`SetSnapshot`) for active sets, avoiding repeated AEAD decrypt operations on hot paths.
- Plaintext data is **wiped from RAM after a period of time**: entries in `SetCache` expire and are evicted after an idle time-to-live (TTL, default 1 hour) or when cache capacity (default 256 sets) is reached.
- The single durable source of truth is always the encrypted ciphertext in `redb`.
- The session state (`SessionStore`) holds session metadata and a sealed working mirror; it does not retain standing encryption keys or permanent plaintext history. The user's derived encryption key is zeroized after request execution and validated per-request against an HMAC-SHA256 key verifier.

### Client-side key storage tiers

| Tier | Platform | UX | Protection |
| :--- | :--- | :--- | :--- |
| **Option 2 (default web)** | Browser | Zero extra steps after login | HttpOnly `enc_key` plus per-account `enc_key-{username}` (`SameSite=Strict`, same max-age as remember). IndexedDB stores account names for the login dropdown only. |
| **Option 3 (opt-in web)** | Browser with WebAuthn PRF (Pseudo-Random Function: authenticator HMACs a salt with a credential-bound secret) | One biometric/PIN per unlock (manual opt-in) | Not on the request path while page JS must not hold the data key. |
| **Option 4 (native keystore)** | Capacitor Android | One biometric/PIN unlock when logging in from cached credentials; 1-minute resume lock on backgrounded sessions | Android Keystore hardware-backed AES/GCM wrap for cached credentials (`NativeSecureKey` plugin). Plaintext cookies purged at rest from the WebView jar; injected on biometric unlock. Zero prompts during active session. iOS Keychain plugin still open when the iOS target ships. |

Browsers grant secure context (required for Web Crypto key derivation) for https:// origins and http://localhost (or 127.0.0.1). Plain HTTP to other LAN hostnames or IPs will not allow client-side key derivation; login then falls back to server-side derivation. The native Capacitor app loads over plain HTTP and derives the key via the `NativeSecureKey` plugin at password login only (`deriveKeyFromPassword`). On mobile, cached credentials (`remember` and `enc_key`) are sealed into Android Keystore; cached login prompts biometric unlock (`BiometricPrompt` with device PIN fallback) before native injects the cookies into `CookieManager`. Active logged-in sessions enforce a 1-minute resume lock with `FLAG_SECURE` (bypassed when background voice mode is running).

For LAN/browser development with full Private Mode support, use Tailscale Serve (or equivalent) to terminate TLS on your node with publicly-trusted certs, or access via http://localhost. See the development notes in README.md.

Enrollment flow: login derives the key client-side (or on the server if Web Crypto is unavailable) → server stores the key verifier and sets HttpOnly `enc_key` and, when remember is checked, `enc_key-{username}` → IndexedDB records the username for the login dropdown. Data requests send the cookies; tests may send `X-Enc-Key`.

### Transport requirements

- Browsers send the key in **HttpOnly** `enc_key` / `enc_key-{username}` cookies (`Path=/`, `SameSite=Strict`, `Secure` when CSRF is on). Tests and non-browser clients send `X-Enc-Key`. `<img src>` uses the Path=`/` `enc_key` cookie. Page JS must not write a JS-visible copy.
- Must travel over TLS (reverse-proxy terminated HTTPS in production).
- Must **never** appear in access logs, `tracing` spans, or error reports. Proxies should scrub `Cookie` and `X-Enc-Key` from logs.

### Migration

Existing users without a verifier get one created at **password login** (not from a data request presenting `X-Enc-Key`). Until a verified enc-key cookie (or test header) is present, encrypted endpoints return **401** with a clear unlock message.

### Remembered devices & cached logins
*Implemented August 2026*

**Remember this computer for 30 days** (login checkbox, checked by default; unchecking opts the device out and revokes any token it holds) issues a durable device token that restores the HTTP session after a server restart. Design properties:

- **Session-only.** The token restores the HTTP session; every data endpoint still requires the enc-key cookie (or `X-Enc-Key`), so a stolen remember token on another machine decrypts nothing (two-secrets model unchanged).
- **Hashed at rest, rotated on use.** The server persists only a hash of the token's current secret, and every restore rotates it. File locks serialize concurrent resumes so two tabs redeeming the current secret cannot false-revoke the family. Recent-generation tokens get a grace pass so concurrent tabs refreshing after a restart don't revoke each other; older replays revoke the whole family. Re-login as the same account refreshes that family instead of minting another. Logging in as a different remembered account mints or refreshes that account's family and does not revoke the previous account's. Logout does not revoke it.
- **HttpOnly cookie** (`Secure` when CSRF is on, automatically sanitized for plain HTTP) — the server cookie sanitization middleware strips `Secure` for plain HTTP requests without HTTPS proxy headers, allowing Android WebView / RFC 6265bis clients to accept cookies without requiring `csrf: false`. Reverse-proxied HTTPS requests retain the `Secure` flag.
- **Silent resume on app entry.** `GET /` restores a remembered session for guest visitors, making restarts invisible, and writes the rotated secret to both the last-used `remember` cookie and that account's `remember-{username}` cookie. `/login` never auto-restores — it is the account-selection surface. When a live page's request 401s mid-use (e.g. after a restart), the client transparently re-establishes the session (`POST /login/remember` with a bootstrapped CSRF token, adopting the restored session's CSRF from the response) and retries the call — no reload, no prompt; it only falls back to `/` when the device holds no valid token.
- **Cached-account picker.** Accounts remembered on this device appear in the login page's account dropdown. Login with no password calls `POST /login/remember` (per-account `remember-{username}` cookie, else last-used `remember` if it matches). A matching `enc_key-{username}` cookie (or test `X-Enc-Key`) is copied onto last-used `enc_key` — it cannot mint a session. Password is hidden unless restore fails; a typed password still posts `/login`. A ✕ control forgets an account locally and `POST /login/forget` revokes this device's remember token only when that cookie belongs to the forgotten username.
- **Checkbox semantics.** Checked: issue/refresh the 30-day last-used `remember` cookie, a per-account `remember-{username}` cookie, last-used `enc_key`, and `enc_key-{username}` (same max-age). Unchecked: revoke that account's remember family, clear `enc_key-{username}`, and issue a session-scoped enc-key cookie. **Switch account** (`GET /logout`) clears the session and last-used `enc_key` and redirects to `/login`; remember and `enc_key-{username}` cookies stay so cached accounts remain password-free. **Log out of this computer** forgets this account on this device (`POST /login/forget` + local slot) then logs out. ✕ on the login dropdown is the same forget. Visiting `/login` as a guest drops `remembered: false` username slots; remembered slots stay until forgotten or aged out (30 days, sliding on use).
- **Data-key verifier.** The HMAC verifier used on every enc-key check does not expire and is created only at password login. Missing verifiers are not enrolled from data requests (a stolen session cannot rebind the key). Pre-JSON `{user}_kv` files migrate in place.

### Trade-offs (session restore vs encryption key)

| Choice | What we kept | What we gave up |
| :--- | :--- | :--- |
| **Remember cookies** (HttpOnly; last-used + per-account) | Checkbox still means: no password on this computer for 30 days (app entry + login dropdown until ✕). XSS cannot copy the cookies. Logout is not forget. | Profile copy of the cookie jar still restores a session (not decrypt). |
| **No `/login/keyauth`** | The Fernet key cannot mint a session on another machine. | A copied IndexedDB slot is not enough to log in. |
| **HttpOnly `enc_key` + `enc_key-{username}`** | Cookie covers `<img>` and fetch. XSS cannot read the key from JS. Switch account stays password-free. | Cookie `Path=/`. Proxies must not log `Cookie` / `X-Enc-Key`. Profile copy still steals the cookie jar. |
| **First-party JS + tight CSP** | CDN compromise cannot run on this origin. | Vendored jquery/bootstrap/marked/hljs in `static/deps/`. |
| **Trusted Types** | `require-trusted-types-for 'script'`; first-party sinks use policy `chatbot`. | Policy `default` is identity so jquery/bootstrap/highlight.js still assign HTML. Accidental library sinks are not locked. |
| **WebAuthn PRF not default** | Desktops without Hello/Touch ID/a security key still work. | Profile copy of the default web store is only a partial mitigation. |

A compromised origin (XSS that runs) can still read decrypted chat in the DOM. CSRF tokens do not stop XSS. There is no posture where the page is owned and private chat stays private.

## Current Architecture Status
*As of July 2026*

The system currently operates in a **Strict Private Mode** with **per-request keying**. Per-chat mode selection (Private / Recoverable / Ephemeral dropdown) is **not** implemented yet — all authenticated durable data uses Private Mode rules.

1.  **Authenticated Users:**
    *   Durable chat sets live in **redb** as AEAD (AES-256-GCM + HKDF) ciphertext blobs via `HistoryService` (see [design-history-store.md](design-history-store.md)). Display names are only inside ciphertext.
    *   Optional multi-set ciphertext cache keyed `(user, set_id)`; session may still hold a Fernet-sealed **working mirror** of the active set for the request path (not durable SoT).
    *   Keys are derived from the login password on the client.
    *   The server stores only an HMAC key verifier, not the data key.
    *   Browsers send the key in HttpOnly cookies; page JS never holds it. WebAuthn PRF is not on the request path.
    *   **CRITICAL LIMITATION:** There is **NO Account Recovery**. Losing a password means permanent data loss.
    *   OAuth is not yet implemented.

2.  **Anonymous Users:**
    *   Guests operate in **Ephemeral Mode** (RAM-only history, no redb, no `X-Enc-Key` required).

## Roadmap

### Phase 1: Recoverable Mode & UX
- [ ] Implement Server-Managed Key infrastructure.
- [ ] Add UI dropdown for "Privacy Mode" (Private/Recoverable) per chat.
- [ ] Add tooltips explaining the "No Recovery" risk of Private Mode.
- [ ] Rename "Standard" concepts to "Recoverable Mode" across codebase and UI.

### Phase 2: OAuth & Hybrid Auth
- [ ] Implement OAuth (GitHub/Google).
- [ ] Build "Storage Password" flow for OAuth users accessing Private Mode.

### Phase 3: Advanced Features
- [ ] **Chat Migration:** Allow converting a chat from "Private" to "Recoverable".
- [ ] **Recovery Kit:** Implement the UI/Logic to generate and accept emergency kits.
