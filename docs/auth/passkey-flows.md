# passkey flows

Sequence diagrams for every auth ceremony. Each flow lists the HTTP calls, DB operations, cookies set/cleared, and error paths.

For protocol background (challenges, assertions, RP ID, counters) see [webauthn-primer.md](./webauthn-primer.md).

---

## signup

Two-step form action: `?/begin` collects username, `?/complete` receives the attestation.

```
browser                  /signup page-server           auth-service (service.ts)       db
   │                            │                              │                         │
   │  POST ?/begin              │                              │                         │
   │  {username, displayName}   │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  beginSignup(...)            │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  SELECT users           │
   │                            │                              │  WHERE username=?       │
   │                            │                              │ ──────────────────────> │
   │                            │                              │ <── row | null ──────── │
   │                            │                              │  generateRegistration   │
   │                            │                              │  Challenge (webauthn.ts)│
   │                            │                              │  INSERT auth_challenges │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {options, cookie} ─────  │                         │
   │                            │  set: signup_challenge       │                         │
   │ <── options + cookie ─────  │                              │                         │
   │                            │                              │                         │
   │  navigator.credentials     │                              │                         │
   │    .create(options)        │                              │                         │
   │  [user touches biometric]  │                              │                         │
   │                            │                              │                         │
   │  POST ?/complete           │                              │                         │
   │  {attestation}             │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  completeSignup(...)         │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  consumeChallenge       │
   │                            │                              │  (DELETE auth_challenges│
   │                            │                              │   verify purpose+expiry)│
   │                            │                              │ ──────────────────────> │
   │                            │                              │  verifyRegistration     │
   │                            │                              │  (webauthn.ts)          │
   │                            │                              │  INSERT users           │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  INSERT passkeys        │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  INSERT recovery_codes  │
   │                            │                              │  x8 (argon2id each)     │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  INSERT sessions        │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {recoveryCodes, session} │                         │
   │                            │  delete: signup_challenge    │                         │
   │                            │  set: session (30d, lax)     │                         │
   │ <── success + codes ──────  │                              │                         │
```

**cookies:** `signup_challenge` set on begin (httpOnly, strict, 5 min), deleted on complete. `session` set on complete (httpOnly, lax, 30 days).

**error paths:**
- username fails regex → `fail(400)` before calling service
- username already taken → service throws `'username already taken'` → `fail(400)` (same shape as regex error — deliberate, but username existence is still inferrable from this endpoint; see [threat-model.md](./threat-model.md))
- `signup_challenge` cookie missing on complete → `fail(400, { error: 'missing or expired challenge' })`
- challenge expired (>5 min) or not found → service throws → `fail(400)`
- user cancels biometric prompt → `startRegistration` throws → `fail(400)`
- attestation fails verification → `fail(400)`

**tables touched:** `users` (SELECT, INSERT), `passkeys` (INSERT), `recovery_codes` (INSERT ×8), `sessions` (INSERT), `auth_challenges` (INSERT on begin; SELECT + DELETE on complete).

---

## signin (passkey)

```
browser                  /signin page-server           auth-service (service.ts)       db
   │                            │                              │                         │
   │  POST ?/begin              │                              │                         │
   │  (no body)                 │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  beginSignin(db, rp)         │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  generateAuthentication │
   │                            │                              │  Challenge (webauthn.ts)│
   │                            │                              │  INSERT auth_challenges │
   │                            │                              │  (userId=null)          │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {options, cookie} ─────  │                         │
   │                            │  set: signin_challenge       │                         │
   │ <── options + cookie ─────  │                              │                         │
   │                            │                              │                         │
   │  startAuthentication       │                              │                         │
   │  (useBrowserAutofill:false)│                              │                         │
   │  [user selects passkey]    │                              │                         │
   │                            │                              │                         │
   │  POST ?/complete           │                              │                         │
   │  {assertion}               │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  completeSignin(...)         │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  consumeChallenge       │
   │                            │                              │  (DELETE auth_challenges│
   │                            │                              │   check purpose+expiry) │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  SELECT passkeys        │
   │                            │                              │  WHERE credential_id=?  │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  verifyAuthentication   │
   │                            │                              │  (webauthn.ts)          │
   │                            │                              │  UPDATE passkeys        │
   │                            │                              │  SET counter, lastUsedAt│
   │                            │                              │ ──────────────────────> │
   │                            │                              │  INSERT sessions        │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {sessionCookieValue} ──  │                         │
   │                            │  delete: signin_challenge    │                         │
   │                            │  set: session (30d, lax)     │                         │
   │ <── success ──────────────  │                              │                         │
   │  redirect → /portfolio     │                              │                         │
```

**cookies:** `signin_challenge` set on begin (httpOnly, strict, 5 min), deleted on complete. `session` set on complete (httpOnly, lax, 30 days).

**error paths:**
- `signin_challenge` cookie missing on complete → `fail(400)`
- challenge expired or not found → `completeSignin` returns null → `fail(400)`
- credential ID not in `passkeys` table → `completeSignin` returns null → `fail(400)`
- signature verification fails → `completeSignin` returns null → `fail(400)`

The begin step has no required inputs — `allowCredentials: []` means the browser shows all available passkeys for this RP. The credential ID in the assertion is used to look up the right row.

**tables touched:** `auth_challenges` (INSERT on begin; SELECT + DELETE on complete), `passkeys` (SELECT, UPDATE), `sessions` (INSERT).

---

## signin (recovery code)

Single form action at `/recover`. No WebAuthn.

```
browser                  /recover page-server          auth-service (service.ts)       db
   │                            │                              │                         │
   │  POST (default action)     │                              │                         │
   │  {username, code}          │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  signinWithRecovery(...)     │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  SELECT users           │
   │                            │                              │  WHERE username=?       │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  SELECT recovery_codes  │
   │                            │                              │  WHERE user_id=?        │
   │                            │                              │  AND used_at IS NULL    │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  argon2id.verify(each)  │
   │                            │                              │  UPDATE recovery_codes  │
   │                            │                              │  SET used_at=now        │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  INSERT sessions        │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {sessionCookieValue} ──  │                         │
   │                            │  set: session (30d, lax)     │                         │
   │                            │  set: force_passkey_setup    │                         │
   │                            │  redirect → /settings/       │                         │
   │                            │            passkeys?force=1  │                         │
   │ <── 303 redirect ─────────  │                              │                         │
```

**cookies:** `session` set (httpOnly, lax, 30 days). `force_passkey_setup=1` set (httpOnly, lax, 30 days) — prompts the settings page to show a "register a new passkey" banner.

**error paths:**
- username or code field empty → `fail(400, { error: 'username and code required' })` (before calling service)
- unknown username → service returns `null` → `fail(400, { error: 'invalid username or recovery code' })`
- code doesn't match any unused hash → service returns `null` → same `fail(400)` (uniform response, same error string regardless of whether username was found)
- all 8 codes already used → same `null` return

The `force_passkey_setup` cookie is a nudge, not enforcement. The `(app)` layout only checks `locals.user`; a recovery-authenticated user can navigate freely. The settings page reads both the `?force=1` query param and the cookie together to decide whether to show the banner.

**tables touched:** `users` (SELECT), `recovery_codes` (SELECT all unused for user; UPDATE matched row), `sessions` (INSERT).

---

## add passkey on existing account

Requires an active session. Initiated from `/settings/passkeys`.

```
browser               /settings/passkeys server          auth-service (service.ts)      db
   │                            │                              │                         │
   │  POST ?/beginAdd           │                              │                         │
   │  (no body)                 │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  locals.user checked         │                         │
   │                            │  beginAddPasskey(...)        │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  SELECT users WHERE id= │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  SELECT passkeys        │
   │                            │                              │  WHERE user_id=?        │
   │                            │                              │ ──────────────────────> │
   │                            │                              │  generateRegistration   │
   │                            │                              │  Challenge (excludes    │
   │                            │                              │  existing credentials)  │
   │                            │                              │  INSERT auth_challenges │
   │                            │                              │  (userId=plain string)  │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {options, cookie} ─────  │                         │
   │                            │  set: add_passkey_challenge  │                         │
   │ <── options + cookie ─────  │                              │                         │
   │                            │                              │                         │
   │  startRegistration(options)│                              │                         │
   │  [user touches biometric]  │                              │                         │
   │                            │                              │                         │
   │  POST ?/completeAdd        │                              │                         │
   │  {attestation}             │                              │                         │
   │ ────────────────────────>  │                              │                         │
   │                            │  locals.user checked         │                         │
   │                            │  completeAddPasskey(...)     │                         │
   │                            │ ─────────────────────────>   │                         │
   │                            │                              │  consumeChallenge       │
   │                            │                              │  verifyRegistration     │
   │                            │                              │  INSERT passkeys        │
   │                            │                              │ ──────────────────────> │
   │                            │ <── {passkeyId} ───────────  │                         │
   │                            │  delete: add_passkey_challenge                         │
   │                            │  delete: force_passkey_setup │                         │
   │ <── success ──────────────  │                              │                         │
```

**cookies:** `add_passkey_challenge` set on beginAdd (httpOnly, strict, 5 min), deleted on completeAdd. `force_passkey_setup` is deleted on completeAdd (clears the recovery-flow nudge).

**error paths:**
- not authenticated → `fail(401)`
- `add_passkey_challenge` cookie missing on completeAdd → `fail(400)`
- challenge expired, not found, or userId mismatch → service throws → `fail(400)`
- user tries to register a credential they already have → `excludeCredentials` in the options causes the authenticator to reject it before it reaches the server
- attestation verification fails → `fail(400)`

The challenge row stores `userId` as a plain string (not JSON). `completeAddPasskey` checks whether the challenge's `rawUserId` parses as JSON and, if so, extracts `.userId` from it — this handles the edge case where a signup challenge were passed here (it would still reject, because the outer userId check would catch any mismatch). See [implementation-notes.md](./implementation-notes.md).

**tables touched:** `users` (SELECT), `passkeys` (SELECT for excludeCredentials; INSERT), `auth_challenges` (INSERT on beginAdd; SELECT + DELETE on completeAdd).

---

## sign-out

```
browser                  /signout server
   │                            │
   │  POST /signout             │
   │ ────────────────────────>  │
   │                            │  revokeSession(db, cookie)
   │                            │  DELETE sessions WHERE id=SHA256(cookie)
   │                            │  delete: session
   │                            │  delete: force_passkey_setup
   │ <── 303 redirect → / ─────  │
```

**cookies:** `session` deleted. `force_passkey_setup` deleted (belt-and-suspenders cleanup).

**tables touched:** `sessions` (DELETE).
