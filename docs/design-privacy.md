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
2. **`X-Enc-Key` header** — the client-derived Fernet data key, sent on every data endpoint call.

The server validates the presented key against a per-user **key verifier** (HMAC-SHA256 over the key material) before any decrypt. The key exists in server RAM only for the lifetime of that request, then is zeroized. Login establishes/rotates the verifier but **does not retain the key** after the redirect.

### Threat model addressed

| Attack | Mitigation |
| :--- | :--- |
| Stolen session cookie used on another machine | Server has no standing key; attacker has no client key store → decrypt fails (401). |
| XSS exfiltrating raw key from `localStorage` | Default web store wraps the key with a non-extractable `CryptoKey` in IndexedDB; JS can unwrap-to-use but cannot export wrapping key bytes. |
| Full browser profile theft | Partial mitigation with Option 2; full mitigation with device binding (Option 3/4 below). |
| Server compromise while user idle | No standing key in session record or plaintext cache; only ciphertext on disk and in memory. |

### Server-side cache (ciphertext-only)

The in-memory `SessionStore` retains Fernet ciphertext blobs for history, memory, and system prompt — never decrypted plaintext across requests. Each request decrypts the working set with the presented key, processes the request, re-encrypts into the cache, and zeroizes plaintext. A hijacked cookie without the key sees only ciphertext.

### Client-side key storage tiers

| Tier | Platform | UX | Protection |
| :--- | :--- | :--- | :--- |
| **Option 2 (default web)** | Browser | Zero extra steps after login | Non-extractable AES-GCM wrap key in IndexedDB; wrapped data key persisted as blob. |
| **Option 3 (opt-in web)** | Browser with WebAuthn PRF (Pseudo-Random Function: authenticator HMACs a salt with a credential-bound secret) | One biometric/PIN per unlock (manual opt-in) | Wrapping secret derived from platform authenticator (Touch ID, Windows Hello, security key). Full profile copy on another machine is useless without the authenticator. Falls back to Option 2 when PRF is unsupported. **Not the web default** — many desktops have no platform authenticator or security key. |
| **Option 4 (native default)** | Capacitor Android | One fingerprint/PIN per login from cached credentials (cold app start); none during username/password logins or within a running app session. A second prompt is allowed if the app process died and a stale session must unlock the keystore again. | Android Keystore AES/GCM wrap with user-authentication required on the wrap key (`setUserAuthenticationRequired`, 24h validity after device unlock) plus a software biometric/PIN gate on cache miss (`NativeSecureKey` plugin). Per-account keystore entries; the plugin caches unlocked keys for the app-process lifetime so one unlock covers a whole login flow. Applied automatically at login on mobile; no WebAuthn button. iOS Keychain plugin follows the same pattern when the iOS target ships. |

Browsers grant secure context (required for Web Crypto + non-extractable IndexedDB key storage) for https:// origins and http://localhost (or 127.0.0.1). Plain HTTP to other LAN hostnames or IPs will not allow client-side key derivation/storage. The native Capacitor app loads over plain HTTP where `crypto.subtle` is unavailable, so it derives the key via the `NativeSecureKey` plugin, which keeps one encrypted keystore entry per account (`account` parameter on `storeKey`/`getKey`/`clearKey`).

For LAN/browser development with full Private Mode support, use Tailscale Serve (or equivalent) to terminate TLS on your node with publicly-trusted certs, or access via http://localhost. The native Capacitor app uses its own keystore plugin and works over plain HTTP. See the development notes in README.md.

Enrollment flow: login derives the key client-side → server stores key verifier → client wraps key locally → raw key discarded from JS. Re-unlock: settings panel or automatic prompt on 401 from data endpoints.

### Transport requirements

- Browsers send the key in an **HttpOnly** `enc_key` cookie (`Path=/`, `SameSite=Strict`, `Secure` when CSRF is on). JS cannot read it. Tests and non-browser clients may still send `X-Enc-Key` (raw derived key bytes).
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
- **Cached-account picker.** Accounts remembered on this device appear in the login page's account dropdown (fills the username; password still required). A ✕ control forgets an account locally and `POST /login/forget` revokes this device's remember token only when that cookie belongs to the forgotten username. There is no password-free login via the encryption key.
- **Checkbox semantics.** The key cache always backs the live session (the client must hold the key for `X-Enc-Key`). Logging out or visiting `/login` as a guest drops `remembered: false` slots; remembered slots stay until forgotten or aged out (30 days, sliding on use).
- **Data-key verifier.** The HMAC verifier used on every `X-Enc-Key` call does not expire and is created only at password login. Missing verifiers are not enrolled from data requests (a stolen session cannot rebind the key). Pre-JSON `{user}_kv` files migrate in place.

## Current Architecture Status
*As of July 2026*

The system currently operates in a **Strict Private Mode** with **per-request keying**. Per-chat mode selection (Private / Recoverable / Ephemeral dropdown) is **not** implemented yet — all authenticated durable data uses Private Mode rules.

1.  **Authenticated Users:**
    *   Durable chat sets live in **redb** as AEAD (AES-256-GCM + HKDF) ciphertext blobs via `HistoryService` (see [design-history-store.md](design-history-store.md)). Display names are only inside ciphertext.
    *   Optional multi-set ciphertext cache keyed `(user, set_id)`; session may still hold a Fernet-sealed **working mirror** of the active set for the request path (not durable SoT).
    *   Keys are derived from the login password on the client.
    *   The server stores only an HMAC key verifier, not the data key.
    *   Clients wrap the key locally (IndexedDB non-extractable key by default; WebAuthn PRF opt-in; Android Keystore on native).
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
