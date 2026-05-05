# threat model

---

## defended

**Replay attacks via signature counter.**
Every authentication response includes a counter incremented by the authenticator. `@simplewebauthn/server` checks that the new counter is ≥ the stored one and rejects responses where a non-zero counter has decreased. The stored counter is updated after each successful sign-in. See [webauthn-primer.md](./webauthn-primer.md) for counter semantics.

Exception: synced passkeys (cloud-backed credentials on iOS/Android/etc.) typically report counter=0 indefinitely because the spec explicitly carves out this case. We accept counter=0 without enforcing monotonicity — `@simplewebauthn` handles this correctly. See [implementation-notes.md](./implementation-notes.md).

**Phishing via RP ID binding.**
The RP ID (`finance.gabbrousset.dev` in production, `localhost` in dev) is baked into the signed challenge. The browser will not let an authenticator sign a challenge for a different origin. A fake site at a lookalike domain cannot trigger valid assertions for our RP ID. This is the core anti-phishing property of WebAuthn. See [webauthn-primer.md](./webauthn-primer.md).

**Credential theft requires physical device access + biometric/PIN.**
The private key never leaves the authenticator. A database dump gives an attacker public keys and credential IDs — neither is useful for logging in. Impersonating a user requires the physical device (or synced credential manager account) plus the user's biometric/PIN.

**Recovery codes stored as argon2id hashes.**
Plaintext codes are shown once and never stored. The `recovery_codes` table holds `argon2id` hashes. Brute-forcing a code from the hash is compute-expensive. Codes are drawn from a 32-character alphabet (16-char codes in 4-char groups, ~80 bits of entropy) — see [implementation-notes.md](./implementation-notes.md) for the alphabet.

**Session tokens hashed at rest.**
The `session` cookie value is a random 32-byte base64url string. The `sessions` table stores `SHA-256(cookieValue)`. A read-only leak of the sessions table does not yield valid cookie values.

**Last-passkey deletion blocked.**
`revokePasskey` throws if the user has only one passkey, preventing accidental self-lockout via the settings UI.

**Revoked sessions are immediately invalid.**
Sign-out deletes the session row. The cookie is also cleared, but even if an attacker had the cookie value from a prior intercept, the hash would no longer be in the table.

**Recovery code uniform error response.**
`signinWithRecoveryCode` returns `null` whether the username doesn't exist or the code is wrong. The page-server returns the same error string either way: `'invalid username or recovery code'`. An attacker cannot distinguish a valid username from an invalid one through this endpoint.

---

## acknowledged — unmitigated in v3.0

**Lost device + lost codes = lost account.**
If a user loses all passkeys (e.g., factory reset, stolen device, unsynced credential) and has also lost all recovery codes, the account is permanently inaccessible. There is no email-based recovery, no admin backdoor. This is intentional — the privacy floor we've chosen. The tradeoff is documented in [overview.md](./overview.md) and surfaced to users on the signup page.

**Username enumeration on `/signup`.**
`beginSignup` throws `'username already taken'` when the username is registered. The page action returns this as an `error` field in the response. The error text differs from the validation failure message (`'username must be 3–24 chars...'`). A script can enumerate registered usernames by watching the error response shape. Impact is low (usernames are not sensitive by design), but it's a gap worth noting. Mitigation — uniform error message on all `/signup` failures — is pending; not fixed in v3.0.

**No rate-limit on `/recover`.**
`signinWithRecoveryCode` is the only endpoint that can be brute-forced toward a valid code. Argon2id slows each verification attempt significantly (argon2id default cost parameters), and code entropy is ~80 bits, so brute force is impractical with a static code space. However, there is no request-rate limit on the endpoint in v3.0. This is a known gap. A rate-limit (e.g., 5 attempts per IP per 10 minutes) will be added before public launch.

**`force_passkey_setup` is a nudge, not enforcement.**
After a recovery code sign-in, the user is redirected to `/settings/passkeys?force=1` and shown a banner. The app layout does not enforce that a new passkey be registered. An authenticated user can navigate freely without registering. A recovery-only user without a passkey remains in a vulnerable state (their next sign-in will consume another recovery code). This is acceptable for v3.0 friend-group use, but enforcement should be added for any broader deployment.

---

## out of scope

**TLS interception.** All connections are HTTPS; TLS is terminated by nginx. We trust nginx and the cert chain. If TLS is compromised, all bets are off — this is a given for any web service.

**OS-level malware on the client.** If the user's device is compromised at the OS level, an attacker can exfiltrate cookies, intercept biometric prompts, etc. WebAuthn does not protect against this.

**OS-level malware on the server.** If the server is compromised, an attacker can read the session table (SHA-256 hashes), passkey public keys, and usernames. They cannot recover private keys or plaintext recovery codes.

**Supply-chain compromise of `@simplewebauthn`.** We use `@simplewebauthn/server` and `@simplewebauthn/browser` for the cryptographic heavy lifting. A malicious version of either package would undermine all of the above. We don't have a mitigation for this beyond normal package auditing.

**Account takeover via synced credentials.** If a user's iCloud Keychain or Google Password Manager account is compromised, all synced passkeys are compromised. This is entirely outside our control.
