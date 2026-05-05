# implementation notes

Things that bit me, or will confuse a future reader of the auth code.

---

## `userID` is `Uint8Array`, not string (`@simplewebauthn` v10+)

`generateRegistrationOptions` changed `userID` from `string` to `Uint8Array` in v10 and confirmed it in v13. Most tutorials still pass a plain string and it silently broke in newer versions.

We encode it:

```ts
userID: new TextEncoder().encode(args.userId)
```

This is in `webauthn.ts:34`. The `userId` value passed in is a cuid2 string.

---

## `publicKey` Buffer vs Uint8Array

`verifyAuthenticationResponse` (v13) expects `credential.publicKey` typed as `Uint8Array<ArrayBuffer>`. SQLite via `better-sqlite3` returns BLOB columns as `Buffer`. `Buffer` extends `Uint8Array` so it mostly works, but TypeScript complains about the `ArrayBuffer` generic.

The workaround in `webauthn.ts:81`:

```ts
publicKey: args.storedCredential.publicKey as Uint8Array<ArrayBuffer>
```

The call site in `service.ts:259` wraps the buffer explicitly:

```ts
publicKey: new Uint8Array(passkey.publicKey)
```

Both sides work at runtime; the cast is just a type appeasement.

---

## challenge `userId` column dual-encoding (the JSON hack)

`auth_challenges.user_id` was designed to hold a plain `userId` string. During `beginSignup` we need to stash `{ userId, username, displayName }` so `completeSignup` can create the user row without a separate DB lookup or a schema change mid-sprint.

The workaround: `beginSignup` JSON-encodes the metadata and stores it in `user_id`:

```ts
userId: JSON.stringify({ userId, username, displayName })
```

`completeSignup` always parses it as JSON and throws if it can't — that path is only valid for signup.

`beginAddPasskey` stores a plain string (just the `userId`). `completeAddPasskey` defensively tries to JSON-parse `rawUserId` and falls back to treating it as a plain string:

```ts
try {
  const meta = JSON.parse(rawUserId ?? '') as SignupMeta;
  challengeUserId = meta.userId;
} catch {
  challengeUserId = rawUserId ?? '';
}
```

This is a known schema wart. A future migration should split `user_id` out of `auth_challenges` and store a proper `signup_meta` JSON column separately, or add a dedicated `signup_challenges` table. Don't remove the dual-encoding logic without migrating existing in-flight challenges.

---

## counter handling for synced passkeys

WebAuthn Level 3 §6.1.1 says: "If `authData.signCount` is 0 and `storedSignCount` is 0, the authenticator may not support signCount and the RP may ignore it."

Synced passkeys (iCloud Keychain, Google Password Manager, etc.) report counter=0 on every assertion. `@simplewebauthn` handles this correctly — it only enforces strict counter monotonicity when both the new and stored counters are non-zero.

We don't do any counter management ourselves beyond:
1. Storing `credential.counter` from the registration info
2. After each successful authentication, updating to `verification.authenticationInfo.newCounter`

If you see counter=0 in the passkeys table and it never increments, that's expected for a synced credential, not a bug.

See [webauthn-primer.md](./webauthn-primer.md) for more on counter semantics.

---

## `force_passkey_setup` cookie and `?force=1`

After a successful recovery code sign-in (`/recover` action), two things happen:

```ts
cookies.set('force_passkey_setup', '1', { ... });
throw redirect(303, '/settings/passkeys?force=1');
```

The settings page `load` function checks both conditions together:

```ts
forceSetup: url.searchParams.get('force') === '1' && cookies.get('force_passkey_setup') === '1'
```

Why both? The query param alone could be bookmarked or linked; the cookie prevents showing the banner on a direct navigation. The cookie alone would persist across navigations unexpectedly.

The cookie is deleted on a successful `completeAdd`. It's also deleted on sign-out. Neither the layout nor any other route enforces that setup is completed — it's a nudge only.

---

## `useBrowserAutofill: false` in `startAuthentication`

`signin/+page.svelte` calls:

```ts
startAuthentication({ optionsJSON: options, useBrowserAutofill: false })
```

`useBrowserAutofill: true` is the conditional UI (autofill-assisted) mode — the browser shows passkeys in the password autofill dropdown on an `<input autocomplete="webauthn">` field. We don't use conditional UI; the sign-in flow is button-triggered, not autofill-triggered. Setting it to `false` is explicit and avoids `@simplewebauthn/browser` trying to run `navigator.credentials.get({ mediation: 'conditional' })` which would conflict with the button-triggered flow.

If conditional UI is added in a future iteration, the input needs `autocomplete="username webauthn"` and `beginSignin` needs to be invoked on page load, not on button click.

---

## RP ID in localhost vs production

The RP ID must match the effective domain of the origin. Rules:

- `localhost` in dev: RP ID = `localhost`, origin = `http://localhost:5173`. This works because WebAuthn exempts `localhost` from the HTTPS requirement.
- Production: RP ID = `finance.gabbrousset.dev`, origin = `https://finance.gabbrousset.dev`.

The RP ID **cannot** include a port. `localhost:5173` is invalid. `localhost` is correct.

Both are configured via environment variables:

```ts
const rp = {
  rpId: env.RP_ID ?? 'localhost',
  expectedOrigin: env.ORIGIN ?? 'http://localhost:5173',
  rpName: 'finance-sim'
};
```

This block is duplicated in `signup/+page.server.ts`, `signin/+page.server.ts`, and `settings/passkeys/+page.server.ts`. A future refactor could centralise it (module-level singleton from env), but given better-sqlite3's synchronous nature and SvelteKit's server module lifecycle it's low priority.

If `RP_ID` and `ORIGIN` are misconfigured in production, all WebAuthn ceremonies will fail with an origin mismatch error from `@simplewebauthn`. The error message is not surfaced to the user — check the server logs.

---

## recovery code alphabet

```ts
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I confusion
```

The comment says "no 0/O/1/I confusion." This omits `0`, `O`, `1`, and `I` (commonly confused in sans-serif fonts). `L` is retained — it's visually ambiguous with `I` in some fonts, but wasn't identified as a problem here.

Codes are 16 characters in four groups of four, hyphen-separated: `XXXX-XXXX-XXXX-XXXX`. With 32 symbols and 16 characters, entropy is log2(32^16) ≈ 80 bits. The `/recover` form accepts codes with or without hyphens because the server calls `argon2.verify(hash, code)` against the raw user input — hyphens don't matter as long as the user pastes the code unmodified.

Wait — actually: the form submits the `code` field value, and `recovery.ts:verifyRecoveryCode` calls `argon2.verify(row.codeHash, code)` directly. The stored hash was made from the string including hyphens. So the user must include hyphens when entering the code. There's no normalization. This is a minor UX rough edge; if users report failed recovery codes, check whether they stripped the hyphens.

---

## `@simplewebauthn` API differences vs older tutorials

Tutorials written for v7 or earlier often show:

- `generateRegistrationOptions({ user: { id, name, displayName }, ... })` — the `user` object shape. v13 uses `userID`, `userName`, `userDisplayName` as top-level params.
- `verifyRegistrationResponse({ credential: ... })` — v13 uses `response:`.
- String `userID` — v10+ requires `Uint8Array`.
- `credential.credentialID` (base64url string) — v13 uses `credential.id`.
- `credential.credentialPublicKey` — v13 uses `credential.publicKey`.

All of these are breaking changes across major versions. If you're copying from a tutorial, check which version it targets. The `@simplewebauthn` changelog and migration guides are at `https://simplewebauthn.dev/docs/`.
