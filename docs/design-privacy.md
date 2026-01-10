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
*   **Provider Access:** User should use Local Providers (Ollama) for maximum privacy.

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

## Current Architecture Status
*As of Jan 2026*

The system currently operates in a **Strict Private Mode**:

1.  **Authenticated Users:**
    *   All user data is stored using **Private Mode** logic.
    *   Keys are derived from the login password.
    *   **CRITICAL LIMITATION:** There is **NO Account Recovery**. Losing a password means permanent data loss.
    *   OAuth is not yet implemented.

2.  **Anonymous Users:**
    *   Guests operate in **Ephemeral Mode**.

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
