# Web Auth History

This project has gone through three distinct web-auth eras.

## Era 1: Plaintext Password Login

The original web flow behaved like a traditional server-rendered login:

- The browser submitted `username` and plaintext `password` to `/login`.
- The server bcrypt-verified the password and then kept the user's encryption key in server memory.
- Authenticated requests relied on a server-issued session cookie.
- State-changing routes also required a CSRF token tied to that cookie.

This worked, but it had two major downsides:

1. The plaintext password crossed the network on every login.
2. Restarting the server wiped the in-memory session cache, which logged users out even if their browser still had a cookie.

## Era 2: Transitional Client Derivation

We later added browser-side PBKDF2 derivation for storage encryption, but the wire protocol was still half old, half new.

- The browser derived a `storage_key` from the password with `PBKDF2-HMAC-SHA256`.
- That derived value was used as the Fernet encryption key.
- But `/login` still accepted and bcrypt-verified the plaintext password server-side.

This meant the app got some client-side encryption benefits without actually removing plaintext-password transmission. It was an awkward transitional design and the user correctly called it out as a mistake: if the derived key comes from the password, the app should not send both.

## Era 3: Token-Based Persistent Login

The current design removes that split-brain behavior.

### Client derivation

For password users, the browser now does all key derivation:

1. Fetch `/auth/salt/:username`.
2. Derive a 32-byte master secret with `PBKDF2-HMAC-SHA256`.
3. Run `HKDF-SHA256` with domain separation to derive:
   - `auth_token`
   - `enc_key`

The PBKDF2 work factor is `600_000` iterations.

### Server storage

The server never stores the plaintext password and does not store the derived auth token directly.

- `signup` stores `bcrypt(auth_token)` with cost `14`.
- Each user now has two independent 32-byte salts:
  - `auth_salt`
  - `enc_salt`

The server can verify `auth_token`, but it cannot reconstruct the user's encryption key.

### Request auth

Authenticated requests now use headers instead of cookies:

- `Authorization: Bearer <auth_token>`
- `X-Auth-User: <username>`
- `X-Enc-Key: <enc_key>`

Guest continuity uses:

- `X-Guest-Session: <random-id>`

Because auth no longer depends on ambient cookies, the CSRF layer was removed from the authenticated API flow.

### Persistence model

The browser stores derived credentials in:

- `localStorage` when the user chooses "Remember this computer for 30 days"
- `sessionStorage` otherwise

This fixes the original "server restart logs me out" problem. A restart clears only the in-memory auth cache; the next authenticated request can be revalidated from the persisted bearer token.

## Why Cookies Were Removed

Moving away from cookie-backed auth was not mainly about fashion. It solved several concrete problems at once:

- no plaintext password submission on login
- no cookie/CSRF dance on every authenticated route
- no forced logout after a server restart
- much smaller server diff surface once auth lived behind an extractor

That last point mattered more than expected. Before the auth refactor, the same cookie/session/CSRF boilerplate was duplicated across many handlers and tests, which made a small protocol change look like a 42-file rewrite.

## Architectural Cleanup

Before landing the token migration, the server was refactored so auth behavior had clear seams:

- `chatbot-server/src/auth/mod.rs` centralizes request auth extraction
- `chatbot-server/src/responses.rs` centralizes repeated response helpers
- `chatbot-test-support::AuthedClient` hides the auth wire protocol from integration tests

That refactor turned the real migration from a sprawling boilerplate edit into a focused protocol swap.

## Important Behavioral Notes

- Password users must re-sign up after this schema change because the stored credential format changed from password hash to auth-token hash.
- `logout` now means "clear client-held auth state" rather than "invalidate a server-issued session cookie". The browser forgets the derived credential; the server is no longer the primary owner of session state.
- Private-mode persistence still depends on the client-supplied encryption key. Losing the password still means losing access to encrypted data.

## In Short

The old system was a classic cookie session with CSRF and server-side password verification.

The new system is a client-derived, password-never-sent design where the browser proves knowledge of a derived auth token, keeps the encryption key client-side, and can survive server restarts without silently logging the user out.
