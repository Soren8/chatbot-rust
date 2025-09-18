# Privacy Design Specification

## Design Rationale
Our privacy tiers were created to offer users progressive security options without sacrificing usability. This balanced approach emerged from several key considerations:

- **True security compensations**: Server-side encryption (Standard) protects against external threats but not admin access
- **The password reset dilemma**: Password-derived encryption (Private) provides isolation at the cost of unrecoverable data
- **LLM logging risks**: Private tier restricts providers to prevent opaque cloud logging
- **Tempest use cases**: Ephemeral mode meets journalist/whistleblower needs for digital vapor trails
- **Hybrid reality**: Local GPU availability allows Private tier without actual system hosting
- **User experience focus**: Tiers map to clear mental models rather than abstract security classes

## Privacy Tiers

1. **Standard Tier**
   - **Authentication**: Password or OAuth
   - **Data Storage**: Server-managed AES-256 keys; login derives a per-user Fernet key from the password, keeps it in memory for the active session only, and expires it after inactivity
   - **LLM Providers**: Any provider
   - **Recoverability**: Full account recovery
   - **Use Case**: General conversations where convenience is prioritized

2. **Private Tier**
   - **Authentication**: Password + storage passphrase
   - **Data Storage**: Client-derived keys (passphrase never sent to server)
   - **LLM Providers**: On-prem only (Ollama/Local)
   - **Recoverability**: Passphrase-dependent
   - **Use Case**: Sensitive topics requiring zero-knowledge storage

3. **Ephemeral Tier**
   - **Authentication**: None
   - **Data Storage**: Memory-only (no disk writes)
   - **LLM Providers**: Free or on-prem providers
   - **Recoverability**: None
   - **Use Case**: Anonymous temporary conversations

## Implementation Details

### Provider Restrictions

The following matrix illustrates which providers are permitted in each privacy tier:

| Provider Type | Standard | Private | Ephemeral |
|---------------|----------|---------|-----------|
| On-prem       | ✅       | ✅      | ✅        |
| Free cloud    | ✅       | ❌      | ✅        |
| Paid cloud    | ✅       | ❌      | ❌        |

### Storage Mechanisms
```mermaid
flowchart TB
    A[Privacy Tier] --> B{Storage Method}
    B -->|Standard| C[Server-managed keys\n(derived per session, timed expiry)]
    B -->|Private| D[Client-derived keys]
    B -->|Ephemeral| E[Memory only]
```

### Security Properties
- **Standard**: Protects against storage theft but allows server access (threat model: protects local disk but not server-side compromise)
- **Private**: True zero-knowledge storage (server cannot access data) (threat model: server cannot access data but session may leak)
- **Ephemeral**: No persistent data = maximum session privacy (threat model: no data recoverability)

### UI Elements
- Privacy tier selector dropdown
- Dynamic LLM provider filtering
- Storage passphrase manager (Private tier)
- Session timeout warnings (Ephemeral tier)
- See [design.md](design.md) UI/UX Improvements section for related wireframes.
