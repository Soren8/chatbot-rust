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

The current design keeps the persistent bearer-token model, but it does so in a legacy-compatible way so existing accounts and encrypted data continue working.

### Client derivation

For password users, the browser derives the same storage key that older encrypted data already used:

1. Fetch `/auth/salt/:username`.
2. Derive a storage key with `PBKDF2-HMAC-SHA256`.
3. Use that derived storage key as:
   - the encryption key for Fernet-protected user data
   - the bearer credential that can be cached locally for persistent login

The important compatibility detail is that the derived storage key matches the legacy encryption behavior for existing password users, so old encrypted sets still decrypt.

### Server storage

The server stores a bcrypt hash of the derived storage key for token-style login. It also keeps supporting legacy password-hash accounts during migration.

- `signup` stores `bcrypt(storage_key)` with cost `14`.
- New-style login verifies the derived token directly.
- Legacy users can still log in with their password; on successful login, the server backfills the token hash so future logins can use the stored derived credential.
- User salts remain compatibility-oriented so old encrypted data is not rekeyed out from under the user.

### Request auth

Authenticated requests now use headers instead of cookies:

- `Authorization: Bearer <storage_key>`
- `X-Auth-User: <username>`
- `X-Enc-Key: <storage_key>`

Guest continuity uses:

- `X-Guest-Session: <random-id>`

Because auth no longer depends on ambient cookies, the CSRF layer was removed from the authenticated API flow.

### Persistence model

The browser stores the derived credential in:

- `localStorage` when the user chooses "Remember this computer for 30 days"
- `sessionStorage` otherwise

This fixes the original "server restart logs me out" problem. A restart clears only the in-memory auth cache; the next authenticated request can be revalidated from the persisted bearer token.

For compatibility, there is still a legacy bridge:

- if an account only has the old password hash, the browser can submit the password once
- the server validates it, derives the same old storage key, and backfills token auth
- after that, remembered logins can continue using the stored derived credential

## Why Cookies Were Removed

Moving away from cookie-backed auth was not mainly about fashion. It solved several concrete problems at once:

- no cookie/CSRF dance on every authenticated route
- no forced logout after a server restart
- optional remembered login using a browser-cached derived credential

The system still allows a one-time legacy password login for older accounts during migration, because existing password hashes cannot be converted into token hashes without a successful password-based login. That bridge is what avoids breaking existing users and encrypted data.
- much smaller server diff surface once auth lived behind an extractor

That last point mattered more than expected. Before the auth refactor, the same cookie/session/CSRF boilerplate was duplicated across many handlers and tests, which made a small protocol change look like a 42-file rewrite.

## Architectural Cleanup

Before landing the token migration, the server was refactored so auth behavior had clear seams:

- `chatbot-server/src/auth/mod.rs` centralizes request auth extraction
- `chatbot-server/src/responses.rs` centralizes repeated response helpers
- `chatbot-test-support::AuthedClient` hides the auth wire protocol from integration tests

That refactor turned the real migration from a sprawling boilerplate edit into a focused protocol swap.

## Important Behavioral Notes

- Existing password users do not need to re-sign up. The migration is lazy and happens on successful legacy login.
- Existing encrypted data is not rekeyed; the browser still derives the same storage key shape needed to decrypt it.
- `logout` now primarily means "clear client-held auth state" rather than "invalidate a server-issued session cookie".
- Remembered login is time-bounded in the browser cache; if that cached credential expires and the user has forgotten the password, the account cannot be re-derived client-side.
- Private-mode persistence still depends on the client-supplied encryption key. Losing the password still means losing access to encrypted data.

## In Short

The old system was a classic cookie session with CSRF and server-side password verification.

The new system keeps auth in bearer headers and lets the browser cache a derived credential so server restarts do not silently log the user out, while still preserving compatibility with existing password users and encrypted data through a legacy migration bridge.
