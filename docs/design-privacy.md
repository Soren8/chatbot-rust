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
2. **Enc-key cookie** (browsers) or **`X-Enc-Key` header** (tests / non-browser) — the client-derived Fernet data key.

The server validates the presented key against a per-user **key verifier** (HMAC-SHA256 over the key material) before any decrypt. The key exists in server RAM only for the lifetime of that request (**not** a standing copy in the session store), then is zeroized. Login establishes/rotates the verifier but **does not retain the key** after the redirect.

### Threat model addressed

| Attack | Mitigation |
| :--- | :--- |
| Stolen session / remember cookie used on another machine | Server has no standing key; other machine has no `enc_key` cookie and no wrapped key → decrypt fails (401). |
| XSS reading the Fernet key from JS | Live session also has an HttpOnly `enc_key` cookie. XSS on this origin can still unwrap IndexedDB / call keyauth. XSS can scrape already-decrypted chat in the DOM. |
| XSS exporting login to another machine | Remember and enc-key cookies are HttpOnly (XSS cannot copy those). Cached login uses the device-stored key via `/login/keyauth`. |
| Full browser profile theft | Cookie jar + profile copy still wins. Option 3/4 (WebAuthn PRF / Keystore) bind wrap keys to hardware; PRF is opt-in, not default. |
| Server compromise while user idle | No standing key in session record or plaintext cache; only ciphertext on disk and in memory. |

### Server-side cache (ciphertext-only)

The in-memory `SessionStore` retains Fernet ciphertext blobs for history, memory, and system prompt — never decrypted plaintext across requests. Each request decrypts the working set with the presented key, processes the request, re-encrypts into the cache, and zeroizes plaintext. A hijacked cookie without the key sees only ciphertext.

### Client-side key storage tiers

| Tier | Platform | UX | Protection |
| :--- | :--- | :--- | :--- |
| **Option 2 (default web)** | Browser | Zero extra steps after login | Non-extractable IndexedDB CryptoKey wraps the data key; HttpOnly `enc_key` cookie is also set at password/keyauth login. |
| **Option 3 (opt-in web)** | Browser with WebAuthn PRF (Pseudo-Random Function: authenticator HMACs a salt with a credential-bound secret) | One biometric/PIN per unlock (manual opt-in) | Wrapping secret derived from platform authenticator (Touch ID, Windows Hello, security key). Full profile copy on another machine is useless without the authenticator. Falls back to Option 2 when PRF is unsupported. **Not the web default** — many desktops have no platform authenticator or security key. |
| **Option 4 (native default)** | Capacitor Android | One fingerprint/PIN per login from cached credentials (cold app start); none during username/password logins or within a running app session. A second prompt is allowed if the app process died and a stale session must unlock the keystore again. | Android Keystore AES/GCM wrap with user-authentication required on the wrap key (`setUserAuthenticationRequired`, 24h validity after device unlock) plus a software biometric/PIN gate on cache miss (`NativeSecureKey` plugin). Per-account keystore entries; the plugin caches unlocked keys for the app-process lifetime so one unlock covers a whole login flow. Applied automatically at login on mobile; no WebAuthn button. iOS Keychain plugin follows the same pattern when the iOS target ships. |

Browsers grant secure context (required for Web Crypto + non-extractable IndexedDB key storage) for https:// origins and http://localhost (or 127.0.0.1). Plain HTTP to other LAN hostnames or IPs will not allow client-side key derivation/storage. The native Capacitor app loads over plain HTTP where `crypto.subtle` is unavailable, so it derives the key via the `NativeSecureKey` plugin, which keeps one encrypted keystore entry per account (`account` parameter on `storeKey`/`getKey`/`clearKey`).

For LAN/browser development with full Private Mode support, use Tailscale Serve (or equivalent) to terminate TLS on your node with publicly-trusted certs, or access via http://localhost. The native Capacitor app uses its own keystore plugin and works over plain HTTP. See the development notes in README.md.

Enrollment flow: login derives the key client-side → server stores key verifier and sets the HttpOnly `enc_key` cookie → client wraps the key in IndexedDB (or native keystore). Data requests send the cookie and, when JS has the unwrapped key, `X-Enc-Key`.

### Transport requirements

- Browsers send the key in an **HttpOnly** `enc_key` cookie (`Path=/`, `SameSite=Strict`, `Secure` when CSRF is on) and may also send `X-Enc-Key` from the device-stored key. Tests and non-browser clients send `X-Enc-Key`. `<img src>` uses a `Path=/history_image` `hist_enc_key` cookie.
- Must travel over TLS (reverse-proxy terminated HTTPS in production).
- Must **never** appear in access logs, `tracing` spans, or error reports. Proxies should scrub `Cookie` and `X-Enc-Key` from logs.

### Migration

Existing users without a verifier get one created at **password login** (not from a data request presenting `X-Enc-Key`). Until the client sends `X-Enc-Key`, encrypted endpoints return **401** with a clear unlock message.

### Remembered devices & cached logins
*Implemented August 2026*

**Remember this computer for 30 days** (login checkbox, checked by default; unchecking opts the device out and revokes any token it holds) issues a durable device token that restores the HTTP session after a server restart. Design properties:

- **Session-only.** The token restores the HTTP session; every data endpoint still requires the enc-key cookie (or `X-Enc-Key`), so a stolen remember token on another machine decrypts nothing (two-secrets model unchanged).
- **Hashed at rest, rotated on use.** The server persists only a hash of the token's current secret, and every restore rotates it. File locks serialize concurrent resumes so two tabs redeeming the current secret cannot false-revoke the family. Recent-generation tokens get a grace pass so concurrent tabs refreshing after a restart don't revoke each other; older replays revoke the whole family. Re-login as the same account refreshes that family instead of minting another. Logout revokes and clears it.
- **HttpOnly cookie** (`Secure` when CSRF is on) — note that Android WebView refuses `Secure` cookies over plain HTTP, so plain-HTTP deployments need `csrf: false` (or HTTPS) for mobile sessions to work at all.
- **Silent resume on app entry.** `GET /` restores a remembered session for guest visitors, making restarts invisible. `/login` never auto-restores — it is the account-selection surface. When a live page's request 401s mid-use (e.g. after a restart), the client transparently re-establishes the session (`POST /login/remember` with a bootstrapped CSRF token, adopting the restored session's CSRF from the response) and retries the call — no reload, no prompt; it only falls back to `/` when the device holds no valid token.
- **Cached-account picker.** Accounts remembered on this device appear in the login page's account dropdown. Login with no password calls `POST /login/keyauth` (stored encryption key in `X-Enc-Key`) and falls back to `POST /login/remember` when that cookie belongs to the selected username. Password is hidden unless both fail. A ✕ control forgets an account locally and `POST /login/forget` revokes this device's remember token only when that cookie belongs to the forgotten username.
- **Checkbox semantics.** Checked: issue/refresh the 30-day remember cookie and the `enc_key` cookie (same max-age). Unchecked: revoke remember and issue a session-scoped enc-key cookie. Logout revokes remember and clears `enc_key` — the next visit needs the password. Logging out or visiting `/login` as a guest drops `remembered: false` username slots; remembered slots stay until forgotten or aged out (30 days, sliding on use).
- **Data-key verifier.** The HMAC verifier used on every enc-key check does not expire and is created only at password login. Missing verifiers are not enrolled from data requests (a stolen session cannot rebind the key). Pre-JSON `{user}_kv` files migrate in place.

### Trade-offs (session restore vs encryption key)

| Choice | What we kept | What we gave up |
| :--- | :--- | :--- |
| **Remember cookie** (HttpOnly) is silent session restore on this device | Checkbox still means: no password on this computer for 30 days (app entry + login dropdown when the cookie matches). XSS cannot copy the cookie to another machine. | Logout revokes it. One cookie per browser (last remembered account). |
| **`/login/keyauth`** | Cached accounts stay password-free after logout and when switching accounts (device-stored key). | A copied IndexedDB slot (or XSS that unwraps it) can mint a session on another machine. |
| **HttpOnly `enc_key` cookie plus JS `X-Enc-Key`** | Cookie covers `<img>` and fetch after password/keyauth. Stored key covers auto-restore for accounts that logged in before the cookie existed. | Cookie `Path=/`. Proxies must not log `Cookie` / `X-Enc-Key`. Profile copy still steals the cookie jar and IndexedDB. |
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
    *   Browsers send the key in an HttpOnly cookie; WebAuthn PRF remains opt-in (not default).
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
