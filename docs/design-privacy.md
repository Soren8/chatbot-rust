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
| **Option 3 (opt-in web)** | Browser with WebAuthn PRF | One biometric/PIN per unlock (manual opt-in) | Wrapping secret derived from platform authenticator (Touch ID, Windows Hello, security key). Full profile copy on another machine is useless without the authenticator. Falls back to Option 2 when PRF is unsupported. |
| **Option 4 (native default)** | Capacitor Android | One fingerprint/PIN at login and on unlock | Android Keystore AES/GCM wrap with biometric/device-credential gate (`NativeSecureKey` plugin). Applied automatically at login on mobile; no WebAuthn button. iOS Keychain plugin follows the same pattern when the iOS target ships. |

Browsers grant secure context (required for Web Crypto + non-extractable IndexedDB key storage) for https:// origins and http://localhost (or 127.0.0.1). Plain HTTP to other LAN hostnames or IPs will not allow client-side key derivation/storage.

For LAN/browser development with full Private Mode support, use Tailscale Serve (or equivalent) to terminate TLS on your node with publicly-trusted certs, or access via http://localhost. The native Capacitor app uses its own keystore plugin and works over plain HTTP. See the development notes in README.md.

Enrollment flow: login derives the key client-side → server stores key verifier → client wraps key locally → raw key discarded from JS. Re-unlock: settings panel or automatic prompt on 401 from data endpoints.

### Transport requirements

- `X-Enc-Key` carries the raw derived key bytes (URL-safe base64 string).
- Must travel over TLS (reverse-proxy terminated HTTPS in production).
- Must **never** appear in access logs, `tracing` spans, or error reports. Proxies should scrub this header from logs.

### Migration

Existing users without a verifier get one created on the first authenticated request that presents a valid derived key (same key as password login). Until the client sends `X-Enc-Key`, encrypted endpoints return **401** with a clear unlock message.

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
