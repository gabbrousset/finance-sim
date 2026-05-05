# auth overview

finance-sim uses passkeys as the sole credential type. No passwords, no email. The only fallback is a set of one-time recovery codes shown once at signup.

---

## privacy posture

The registration flow collects a username (3–24 chars, letters/digits/`_`/`-`) and an optional display name. That's it. No email address, no phone number, no real name required. A breach of the user table exposes usernames and display names — nothing that can be used outside this app.

---

## what we store

Four auth-related tables:

**`users`** — `id` (cuid2), `username`, `display_name`, `cash_cents`, `created_at`. No credentials here.

**`passkeys`** — one row per registered credential. Stores the `credential_id` (base64url), `public_key` (CBOR blob), `counter`, `transports` (JSON array), `device_name`, `aaguid`, `backup_eligible`, `backup_state`, `last_used_at`. The private key never leaves the authenticator; the server only holds the public half.

**`recovery_codes`** — 8 rows per user at signup. Each stores an argon2id hash of a one-time code; `used_at` is set when consumed. Plaintext is shown once and never stored.

**`sessions`** — the cookie value is a random 32-byte base64url string. The row stores `SHA-256(cookieValue)` as the primary key, not the cookie itself. Lifetime is 30 days.

**`auth_challenges`** — short-lived (5 min) rows backing the two-step WebAuthn ceremony. The row's `id` is `SHA-256(challengeCookieValue)`. See [passkey-flows.md](./passkey-flows.md) for how these are consumed.

What we don't store: passwords, email addresses, phone numbers, IP addresses, or any PII beyond the username/display name the user chose.

---

## auth model

Every sign-in goes through one of two paths:

1. **Passkey assertion** — the authenticator signs a server-issued challenge with the credential's private key. The server verifies with the stored public key. No secret is transmitted.

2. **Recovery code** — a plain-text code is submitted, argon2id-verified against the stored hash, marked used, and a session is created. After recovery sign-in the user is nudged (soft redirect + banner) to register a new passkey before continuing.

A user can have multiple passkeys (e.g., iPhone + MacBook + hardware key). Adding a passkey requires an active session. Removing one is blocked if it's the last.

See [passkey-flows.md](./passkey-flows.md) for step-by-step ceremony diagrams.

---

## the trade-off

No email means no "forgot password" flow. If you lose all your passkeys **and** all your recovery codes, the account is permanently inaccessible — there is no out-of-band recovery path. This is intentional. It is the privacy floor we've chosen: we can't be coerced into handing over an account if we have no way to verify ownership.

Recovery codes exist to bridge the "new device before synced passkeys propagate" gap. They are one-time and limited to 8 per account. Once used, a code is permanently consumed.

See [threat-model.md](./threat-model.md) for what this posture defends against and where the gaps are.

---

## implementation

The auth stack lives in `src/lib/server/auth/`:

- `webauthn.ts` — thin wrappers around `@simplewebauthn/server` (challenge generation, response verification, RP config)
- `sessions.ts` — create / resolve / revoke session rows
- `recovery.ts` — generate / verify / regenerate recovery codes
- `service.ts` — high-level flows: `beginSignup`, `completeSignup`, `beginSignin`, `completeSignin`, `beginAddPasskey`, `completeAddPasskey`, `revokePasskey`, `signinWithRecoveryCode`
- `aaguid.ts` — maps known AAGUID values to human-readable device names

Session resolution happens in `src/hooks.server.ts` on every request. The `(app)` layout server enforces auth by redirecting to `/signin` if `locals.user` is null.

For protocol-level concepts (RP ID, signature counter, CBOR, transports) see [webauthn-primer.md](./webauthn-primer.md).
