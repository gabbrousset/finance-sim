# webauthn / passkeys primer

Reference doc for the auth implementation. Sources: [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [passkeys.dev](https://passkeys.dev/docs/), [simplewebauthn server docs](https://simplewebauthn.dev/docs/packages/server), [simplewebauthn browser docs](https://simplewebauthn.dev/docs/packages/browser), [FIDO Alliance](https://fidoalliance.org/passkeys/).

---

## what's a passkey

A passkey is a discoverable FIDO2/WebAuthn credential — specifically, a public/private keypair scoped to a single relying party (RP).

- **private key** — lives on the authenticator (device's secure enclave, TPM, or in a cloud-synced credential manager). Never leaves. The RP never sees it.
- **public key** — sent to the RP during registration. The RP stores it alongside a credential ID and metadata. This is all the server needs to verify future logins.
- **credential ID** — an opaque byte string the authenticator uses to identify a specific keypair. The RP stores it, sends it as a hint during authentication, and the authenticator uses it to look up the right key.

The RP stores no secret. A breach of the credential database gives an attacker public keys and credential IDs — neither is useful for logging in.

"Passkey" is the user-facing term for a discoverable credential. The two are interchangeable in practice. ([passkeys.dev terms](https://passkeys.dev/docs/reference/terms/))

---

## registration ceremony

What happens when a user registers a passkey:

```
Browser                          RP Server                        Authenticator
  |                                  |                                  |
  |  GET /register/begin             |                                  |
  |--------------------------------->|                                  |
  |                                  |                                  |
  |  PublicKeyCredentialCreationOptions                                 |
  |<---------------------------------|                                  |
  |                                  |                                  |
  |  navigator.credentials.create()  |                                  |
  |-------------------------------------------------->|                |
  |                                  |    user gesture (biometric/PIN)  |
  |                                  |<---------------------------------|
  |  AuthenticatorAttestationResponse|                                  |
  |<--------------------------------------------------|                |
  |                                  |                                  |
  |  POST /register/finish           |                                  |
  |--------------------------------->|                                  |
  |                                  |  verifyRegistrationResponse()   |
  |  200 OK                          |  store credential record        |
  |<---------------------------------|                                  |
```

**Server side — generate options:**

```ts
const options = await generateRegistrationOptions({
  rpName: 'Finance Sim',
  rpID: 'finance-sim.example.com',
  userName: user.email,
  attestationType: 'none',           // avoids attestation UX friction
  authenticatorSelection: {
    residentKey: 'required',          // makes it discoverable (passwordless)
    userVerification: 'preferred',
  },
  excludeCredentials: existingCreds, // prevent duplicate registration
});
// store options.challenge in session; it's single-use
```

**Server side — verify response:**

```ts
const { verified, registrationInfo } = await verifyRegistrationResponse({
  response: body,
  expectedChallenge: session.challenge,
  expectedOrigin: 'https://finance-sim.example.com',
  expectedRPID: 'finance-sim.example.com',
});

if (verified) {
  const { credential, credentialDeviceType, credentialBackedUp } =
    registrationInfo;
  // store: credential.id, credential.publicKey (bytes), credential.counter,
  //        credential.transports, credentialDeviceType, credentialBackedUp,
  //        aaguid (from registrationInfo.aaguid)
}
```

The challenge must be random (≥16 bytes), tied to the session, and discarded after use — whether verification succeeds or fails. Reusing challenges breaks replay protection.

**What the authenticator signs:**

The response contains a `clientDataJSON` (origin, challenge, type) and an `attestationObject`. Inside the attestation object is the **authenticator data** (authData): a 37+ byte structure with the RP ID hash, flags byte, signature counter, and (for registration) attested credential data including the AAGUID and the public key in COSE format.

The RP verifies the RP ID hash against `sha256(rpID)`, checks the challenge matches, confirms the `UP` (user presence) flag is set, and extracts the public key for storage.

---

## authentication ceremony

What happens when a user logs in:

```
Browser                          RP Server                        Authenticator
  |                                  |                                  |
  |  GET /auth/begin                 |                                  |
  |--------------------------------->|                                  |
  |                                  |                                  |
  |  PublicKeyCredentialRequestOptions                                  |
  |<---------------------------------|                                  |
  |                                  |                                  |
  |  navigator.credentials.get()     |                                  |
  |  (browser shows passkey picker)  |                                  |
  |-------------------------------------------------->|                |
  |                                  |    user gesture                  |
  |                                  |<---------------------------------|
  |  AuthenticatorAssertionResponse  |                                  |
  |<--------------------------------------------------|                |
  |                                  |                                  |
  |  POST /auth/finish               |                                  |
  |--------------------------------->|                                  |
  |                                  |  verifyAuthenticationResponse() |
  |  session token                   |  update counter in DB           |
  |<---------------------------------|                                  |
```

**Server side — generate options:**

```ts
const options = await generateAuthenticationOptions({
  rpID: 'finance-sim.example.com',
  // omit allowCredentials for passwordless (let the authenticator pick)
  userVerification: 'preferred',
});
// store options.challenge in session
```

**Server side — verify response:**

```ts
const { verified, authenticationInfo } = await verifyAuthenticationResponse({
  response: body,
  expectedChallenge: session.challenge,
  expectedOrigin: 'https://finance-sim.example.com',
  expectedRPID: 'finance-sim.example.com',
  credential: {
    id: storedCred.id,
    publicKey: storedCred.publicKey, // Uint8Array
    counter: storedCred.counter,
    transports: storedCred.transports,
  },
});

if (verified) {
  await db.updateCounter(storedCred.id, authenticationInfo.newCounter);
}
```

The authenticator signs the authData + clientDataJSON hash using the credential's private key. The RP verifies the signature against the stored public key. If the signature checks out and the counter is valid, the user is authenticated.

---

## rp id rules

The RP ID is the domain that "owns" a credential. Once registered, a credential can only be used on pages where the origin's effective domain equals the RP ID or has the RP ID as a suffix.

**The rule:** `rpID` must be equal to or a registrable domain suffix of the origin's effective domain. ([HTML spec: registrable domain suffix](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain))

**Examples:**

| Origin | RP ID | Valid? |
|--------|-------|--------|
| `https://finance-sim.example.com` | `finance-sim.example.com` | yes — exact match |
| `https://finance-sim.example.com` | `example.com` | yes — registrable suffix |
| `https://example.com` | `finance-sim.example.com` | **no** — suffix can't scope *up* to a subdomain |
| `https://example.com` | `com` | **no** — public suffix |
| `http://localhost` | `localhost` | yes — browsers allow localhost as a secure context |

**Localhost in dev:** `localhost` is treated as a secure context by all major browsers, so you can register RP ID `localhost` without HTTPS. The origin must be `http://localhost` or `https://localhost` — `localhost:3000` still works because the effective domain is `localhost`.

**Prod:** your RP ID must exactly match your production domain. Credentials registered in dev against `localhost` will not work in prod against `example.com`. They're scoped to different RP IDs and are distinct credentials.

**IP addresses don't work.** The domain suffix check requires both values to be domains, not IP addresses. `192.168.1.1` cannot be an RP ID (except for `localhost`, which resolves through separate browser logic).

---

## backup_eligible and backup_state flags

These are two bits in the authenticator data flags byte:

| Bit | Name | simplewebauthn | Meaning |
|-----|------|---------------|---------|
| 3 | BE | `credentialDeviceType === 'multiDevice'` | credential *can* sync |
| 4 | BS | `credentialBackedUp === true` | credential *is currently* synced |

**BE = 0** (single-device): the private key is device-bound. It cannot leave the authenticator — hardware security key or platform key configured for no sync. If the device is lost, the credential is gone.

**BE = 1** (multi-device / "passkey"): the credential is eligible for backup. The platform may sync it to the cloud. This is iCloud Keychain, Google Password Manager, 1Password, etc.

**BS** can change over time on the same credential. If a user registers while signed into iCloud (BE=1, BS=1), then signs out of iCloud on that device, a subsequent assertion may show BE=1, BS=0. Store and update BS on every ceremony.

**Concrete values you'll see:**

- iCloud Keychain passkey at registration: BE=1, BS=1
- YubiKey (hardware security key): BE=0, BS=0
- Credential registered on Android, Google sync disabled: BE=1, BS=0

**Why store them:** recovery flows. If a user has only device-bound credentials (BE=0) and loses their device, they're locked out — you need a recovery path (email OTP, backup code). If they have synced credentials, they can sign in on any of their synced devices.

**simplewebauthn reference:**
```ts
const { credentialDeviceType, credentialBackedUp } = registrationInfo;
// credentialDeviceType: 'singleDevice' | 'multiDevice'
// credentialBackedUp: boolean  (this is the BS bit)
```

---

## aaguid

AAGUID stands for Authenticator Attestation Globally Unique Identifier. It's a 16-byte UUID that identifies the *model* of authenticator, not the individual device.

**Where it appears:** in the attested credential data section of the authData, during registration only. Layout:

```
authData:
  [32 bytes]  rpIdHash
  [1 byte]    flags
  [4 bytes]   signCount
  [16 bytes]  AAGUID            ← here
  [2 bytes]   credentialIdLength
  [n bytes]   credentialId
  [variable]  credentialPublicKey (COSE)
```

simplewebauthn exposes it as `registrationInfo.aaguid` (a UUID string).

**What it tells you:** each authenticator model has a known AAGUID. Apple Passwords: `fbfc3007-154e-4ecc-8c0b-6e020557d7bd`. iCloud Keychain (managed): `dd4ec289-e01d-41c9-bb89-70fa845d4bf2`. Google Password Manager has another. YubiKey 5 NFC has another. By mapping AAGUID → device name, you can show "Signed in with Apple Passwords" in account settings instead of "Passkey ending in a3f9". (AAGUIDs verified from [passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) JSON.)

**AAGUID database:** [passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) on GitHub is the community-maintained list. JSON format, keys are AAGUIDs, values are `{ name, icon_dark, icon_light }`. The readme notes this list may be retired and is not intended for security decisions — use it only for display purposes.

**FIDO Metadata Service (MDS)** is the authoritative source if you need attestation trust chains or security properties. For a display name, the community list is sufficient.

**AAGUID = all zeros** (`00000000-0000-0000-0000-000000000000`) means the authenticator either doesn't support attestation or attestation was stripped. Common with `attestationType: 'none'`. In that case you can't determine the device model — skip the name lookup and show a generic label.

---

## synced vs device-bound credentials in 2026

As of 2026, synced passkeys are the mainstream case on consumer devices:

| Platform | Sync provider | Notes |
|----------|--------------|-------|
| iOS / macOS | iCloud Keychain | Available across all Apple devices signed into same Apple ID |
| Android | Google Password Manager | Syncs across Android devices on same Google account |
| Windows | Windows Hello | Microsoft account sync; also supports third-party managers |
| Cross-platform | 1Password, Bitwarden, Dashlane, etc. | Sync across all platforms via their own cloud |

A synced passkey is always BE=1. When the sync has completed, BS=1.

**Device-bound credentials** remain relevant in enterprise and high-assurance contexts:
- Hardware security keys (YubiKey, Titan Key) — BE=0, BS=0
- Platform authenticators configured for no sync (possible on some enterprise MDM policies)

**Practical implication for this app:** most users registering on consumer devices will have BE=1, BS=1. Design recovery flows assuming users may lose access to an individual device but retain their passkey through sync. For users with BE=0 credentials, flag this in the UI and prompt for a backup auth method.

---

## hybrid transport ("scan QR with phone")

Hybrid is the `hybrid` value in the `AuthenticatorTransport` enum (added in WebAuthn Level 3). It enables cross-device authentication: you're on a desktop browser, your passkeys are on your phone.

**User-visible flow:**

1. User visits the login page on desktop. Browser calls `navigator.credentials.get()`.
2. Browser shows a passkey picker. User selects "Use a passkey on a different device" (or similar platform UI).
3. Browser displays a QR code.
4. User scans the QR with their phone's camera.
5. Phone shows a confirmation UI: "Sign in to finance-sim.example.com?"
6. User approves with biometric/PIN on the phone.
7. Desktop browser completes the authentication.

**How it actually works (FIDO Cross-Device Authentication / CDA):**

The QR code encodes a URL that contains a tunnel ID and a public key for the phone. The desktop browser and phone establish a tunnel through a cloud relay (Bluetooth Low Energy is used only to verify proximity — the phone and desktop must be physically near each other, which prevents remote attackers from intercepting). The actual credential exchange goes through the relay tunnel using a CTAP2 hybrid subprotocol, not directly over BLE.

The BLE proximity check is the anti-phishing piece: an attacker who intercepts the QR code from a screenshot wouldn't be near the user's phone, so the BLE handshake would fail.

Full cryptographic details: CTAP 2.2 specification, section on hybrid transport. I couldn't confirm all platform-specific behaviors from primary sources — treat the BLE+relay description as the documented architecture, not verified implementation behavior for each OS version.

**For the RP:** you don't need to do anything special. Store `transports` from registration (it will include `'hybrid'` for credentials that can be used via CDA). Pass stored transports in `allowCredentials` during authentication — this hints to the browser which transports are available, so it can show appropriate UI options.

```ts
await generateAuthenticationOptions({
  rpID,
  allowCredentials: [
    { id: cred.id, transports: cred.transports }
  ],
});
```

---

## signature counter

The authenticator increments a counter each time it produces an assertion. The RP stores the last-seen counter and checks each new value against it.

**Purpose:** detect cloned authenticators. If someone extracts a private key and puts it in a second device, both devices will produce assertions — but counters diverge. Counter going backwards (or two sessions seeing the same counter value) indicates possible cloning.

**Counter handling — spec §7.2 (Verifying an Authentication Assertion) guidance:**

```
if (newCounter > storedCounter) {
  // normal — update storedCounter to newCounter
} else if (newCounter === 0 && storedCounter === 0) {
  // authenticator doesn't implement counter (common with synced passkeys)
  // accept silently
} else {
  // storedCounter > 0 and newCounter <= storedCounter
  // possible clone — either reject the ceremony or accept and flag for investigation
}
```

**The caveat for passkeys:** many synced passkey implementations (notably iCloud Keychain) set `signCount` to 0 on every assertion. The counter is effectively unused. This is allowed by the spec because synced passkeys can exist on multiple devices simultaneously by design — a rising counter doesn't make sense when the same credential is legitimately on three devices. ([W3C WebAuthn §6.1.1](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter))

**Practical recommendation:**
- Store the counter. On registration it will be 0.
- If both stored and new are 0: accept, don't update.
- If new > stored: accept, update.
- If new <= stored and stored > 0: reject the ceremony; log and investigate.

simplewebauthn's `verifyAuthenticationResponse` returns `authenticationInfo.newCounter`. The library does not enforce counter policy — you decide what to do.

---

## resident credentials / discoverable credentials

A **discoverable credential** (also called a resident key or resident credential — older terminology) is one where the authenticator stores enough data locally to produce an assertion without the RP providing a credential ID hint.

**Why this matters:** with a non-discoverable credential, the RP must send `allowCredentials` containing the user's registered credential IDs. That means the server has to know who the user is before authentication begins — the user must type a username first.

With a discoverable credential, `allowCredentials` can be empty. The browser shows a passkey picker, the user selects their account, and the authenticator sends back the user handle along with the assertion. The RP looks up the user by credential ID. **No username entry required.**

This is the passkey UX: tap → biometric → logged in.

**Enabling it:**

```ts
// registration
await generateRegistrationOptions({
  authenticatorSelection: {
    residentKey: 'required',     // 'required' or 'preferred'
    userVerification: 'preferred',
  },
});
```

```ts
// authentication — omit allowCredentials entirely
await generateAuthenticationOptions({
  rpID,
  // no allowCredentials → passwordless picker UI
});
```

**Storage requirement:** discoverable credentials are stored in the authenticator's memory (or the platform credential manager). Hardware security keys have finite storage — typically 25–100 slots. Platform authenticators (iCloud Keychain, Google PM) have no practical limit.

**`userHandle` in the assertion:** the authenticator returns `response.userHandle` in the assertion response. This is the `user.id` value you set during registration (not the username — an opaque byte string like a UUID). Use it to look up the user record.

---

## threats webauthn doesn't address

WebAuthn is strong against phishing and credential stuffing. It has nothing to say about:

- **Account takeover via the registration flow** — if an attacker can trick a user into registering the attacker's passkey (e.g., by being MITM'd before the user is authenticated), the attacker has access. WebAuthn has no opinion on how you verify identity before registration.
- **Session hijacking after authentication** — once a session token is issued, WebAuthn is done. Stolen cookies, token leakage, or session fixation are out of scope.
- **Malware on the device** — if the device's secure enclave is compromised or the browser extension is malicious, WebAuthn can't help. (This is the "device is the trust boundary" problem.)
- **Social engineering** — WebAuthn doesn't prevent a user from approving a sign-in they didn't initiate, if an attacker is watching over their shoulder or they're confused about the prompt.
- **Backup/recovery account takeover** — if you offer email OTP as a fallback recovery path, and an attacker can compromise the user's email, they can bypass passkeys entirely. Recovery channels are the soft underbelly.
- **RP server compromise** — storing public keys is safe, but if an attacker can write to your credential store (e.g., add their own credential for a victim's account), they gain access. Authorization checks around credential management endpoints matter.

The threat model doc covers which of these apply to this app specifically and what mitigations are in place.

---

## sources

- W3C WebAuthn Level 3 (CR snapshot 2026-01-13): https://www.w3.org/TR/webauthn-3/
- passkeys.dev docs and reference: https://passkeys.dev/docs/
- simplewebauthn server: https://simplewebauthn.dev/docs/packages/server
- simplewebauthn browser: https://simplewebauthn.dev/docs/packages/browser
- FIDO Alliance / Passkey Central: https://fidoalliance.org/passkeys/
- HTML Living Standard (effective domain): https://html.spec.whatwg.org/multipage/origin.html
- AAGUID community database: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
