import { eq } from 'drizzle-orm';
import { createHash, randomBytes } from 'node:crypto';
import { createId } from '@paralleldrive/cuid2';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON
} from '@simplewebauthn/server';

import { schema, type Db } from '$lib/server/db/client';
import type { RpConfig } from './webauthn';
import {
  generateRegistrationChallenge,
  verifyRegistration,
  generateAuthenticationChallenge,
  verifyAuthentication
} from './webauthn';
import { createSession } from './sessions';
import { verifyRecoveryCode, generateRecoveryCodes } from './recovery';
import { suggestDeviceName } from './aaguid';

export type { RpConfig };

const CHALLENGE_LIFETIME_SEC = 60 * 5; // 5 minutes

function hashCookieValue(cookieValue: string): string {
  return createHash('sha256').update(cookieValue).digest('hex');
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// Challenge storage
//
// The challenge row's `userId` column stores either:
//   - a plain userId string (for beginAddPasskey / beginSignin)
//   - a JSON-encoded object { userId, username, displayName } (for beginSignup,
//     so completeSignup can recover the user metadata without a schema change)
// ---------------------------------------------------------------------------

interface SignupMeta {
  userId: string;
  username: string;
  displayName: string;
}

async function storeRegistrationChallenge(
  db: Db,
  challenge: string,
  meta: SignupMeta
): Promise<string> {
  const cookieValue = randomBytes(32).toString('base64url');
  const id = hashCookieValue(cookieValue);
  const expiresAt = nowSec() + CHALLENGE_LIFETIME_SEC;
  db.insert(schema.authChallenges).values({
    id,
    challenge,
    purpose: 'register',
    userId: JSON.stringify(meta),
    expiresAt
  }).run();
  return cookieValue;
}

async function storeAuthChallenge(db: Db, challenge: string): Promise<string> {
  const cookieValue = randomBytes(32).toString('base64url');
  const id = hashCookieValue(cookieValue);
  const expiresAt = nowSec() + CHALLENGE_LIFETIME_SEC;
  db.insert(schema.authChallenges).values({
    id,
    challenge,
    purpose: 'authenticate',
    userId: null,
    expiresAt
  }).run();
  return cookieValue;
}

function consumeChallenge(
  db: Db,
  cookieValue: string,
  purpose: 'register' | 'authenticate'
): { challenge: string; rawUserId: string | null } {
  const id = hashCookieValue(cookieValue);
  const row = db.select().from(schema.authChallenges).where(eq(schema.authChallenges.id, id)).get();
  if (!row) throw new Error('challenge not found or already consumed');
  if (row.expiresAt <= nowSec()) {
    db.delete(schema.authChallenges).where(eq(schema.authChallenges.id, id)).run();
    throw new Error('challenge expired');
  }
  if (row.purpose !== purpose) throw new Error(`challenge purpose mismatch: expected ${purpose}`);
  db.delete(schema.authChallenges).where(eq(schema.authChallenges.id, id)).run();
  return { challenge: row.challenge, rawUserId: row.userId ?? null };
}

// ---------------------------------------------------------------------------
// beginSignup
// ---------------------------------------------------------------------------

export interface BeginSignupResult {
  options: PublicKeyCredentialCreationOptionsJSON;
  challengeCookieValue: string;
}

export async function beginSignup(
  db: Db,
  rp: RpConfig,
  username: string,
  displayName: string,
  _userAgent: string
): Promise<BeginSignupResult> {
  const existing = db.select().from(schema.users).where(eq(schema.users.username, username)).get();
  if (existing) throw new Error('username already taken');

  const userId = createId();

  const options = await generateRegistrationChallenge({
    rp,
    userId,
    username,
    displayName,
    excludeCredentialIds: []
  });

  const challengeCookieValue = await storeRegistrationChallenge(db, options.challenge, {
    userId,
    username,
    displayName
  });

  return { options, challengeCookieValue };
}

// ---------------------------------------------------------------------------
// completeSignup
// ---------------------------------------------------------------------------

export interface CompleteSignupResult {
  userId: string;
  recoveryCodes: string[];
  sessionCookieValue: string;
}

export async function completeSignup(
  db: Db,
  rp: RpConfig,
  challengeCookieValue: string,
  attestation: RegistrationResponseJSON
): Promise<CompleteSignupResult> {
  const { challenge, rawUserId } = consumeChallenge(db, challengeCookieValue, 'register');
  if (!rawUserId) throw new Error('challenge missing user metadata');

  let meta: SignupMeta;
  try {
    meta = JSON.parse(rawUserId) as SignupMeta;
  } catch {
    // Fallback: plain userId string (beginAddPasskey path — shouldn't reach completeSignup)
    throw new Error('challenge is not a signup challenge');
  }

  const verification = await verifyRegistration({
    rp,
    expectedChallenge: challenge,
    response: attestation
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('registration verification failed');
  }

  const { registrationInfo } = verification;
  const { credential, aaguid, credentialDeviceType, credentialBackedUp } = registrationInfo;

  const now = nowSec();

  // Not wrapped in a transaction — generateRecoveryCodes uses async argon2 hashing
  // and better-sqlite3 transactions are synchronous. Sequential inserts are fine at this scale.

  db.insert(schema.users).values({
    id: meta.userId,
    username: meta.username,
    displayName: meta.displayName,
    cashCents: 1_000_000,
    createdAt: now
  }).run();

  const passkeyId = createId();
  db.insert(schema.passkeys).values({
    id: passkeyId,
    userId: meta.userId,
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey),
    counter: credential.counter,
    transports: JSON.stringify(credential.transports ?? []),
    deviceName: suggestDeviceName(aaguid),
    aaguid,
    backupEligible: credentialDeviceType === 'multiDevice' ? 1 : 0,
    backupState: credentialBackedUp ? 1 : 0,
    createdAt: now,
    lastUsedAt: now
  }).run();

  const recoveryCodes = await generateRecoveryCodes(db, meta.userId);

  const { cookieValue: sessionCookieValue } = await createSession(db, meta.userId, 'signup');

  return { userId: meta.userId, recoveryCodes, sessionCookieValue };
}

// ---------------------------------------------------------------------------
// beginSignin
// ---------------------------------------------------------------------------

export async function beginSignin(
  db: Db,
  rp: RpConfig
): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeCookieValue: string }> {
  const options = await generateAuthenticationChallenge({ rp });
  const challengeCookieValue = await storeAuthChallenge(db, options.challenge);
  return { options, challengeCookieValue };
}

// ---------------------------------------------------------------------------
// completeSignin
// ---------------------------------------------------------------------------

export async function completeSignin(
  db: Db,
  rp: RpConfig,
  challengeCookieValue: string,
  assertion: AuthenticationResponseJSON,
  userAgent: string
): Promise<{ sessionCookieValue: string; userId: string } | null> {
  let challengeData: { challenge: string; rawUserId: string | null };
  try {
    challengeData = consumeChallenge(db, challengeCookieValue, 'authenticate');
  } catch {
    return null;
  }

  // assertion.id is the base64url-encoded credentialId
  const passkey = db
    .select()
    .from(schema.passkeys)
    .where(eq(schema.passkeys.credentialId, assertion.id))
    .get();
  if (!passkey) return null;

  let verification;
  try {
    verification = await verifyAuthentication({
      rp,
      expectedChallenge: challengeData.challenge,
      storedCredential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(passkey.publicKey),
        counter: passkey.counter,
        transports: JSON.parse(passkey.transports) as string[]
      },
      response: assertion
    });
  } catch {
    return null;
  }

  if (!verification.verified) return null;

  const now = nowSec();
  db.update(schema.passkeys)
    .set({ counter: verification.authenticationInfo.newCounter, lastUsedAt: now })
    .where(eq(schema.passkeys.id, passkey.id))
    .run();

  const { cookieValue: sessionCookieValue } = await createSession(db, passkey.userId, userAgent);
  return { sessionCookieValue, userId: passkey.userId };
}

// ---------------------------------------------------------------------------
// beginAddPasskey
// ---------------------------------------------------------------------------

export async function beginAddPasskey(
  db: Db,
  rp: RpConfig,
  userId: string
): Promise<{ options: PublicKeyCredentialCreationOptionsJSON; challengeCookieValue: string }> {
  const user = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
  if (!user) throw new Error('user not found');

  const existingPasskeys = db
    .select()
    .from(schema.passkeys)
    .where(eq(schema.passkeys.userId, userId))
    .all();

  const options = await generateRegistrationChallenge({
    rp,
    userId,
    username: user.username,
    displayName: user.displayName,
    excludeCredentialIds: existingPasskeys.map((p) => p.credentialId)
  });

  // Store userId as plain string (not JSON) — completeAddPasskey uses a separate userId param
  const cookieValue = randomBytes(32).toString('base64url');
  const id = hashCookieValue(cookieValue);
  db.insert(schema.authChallenges).values({
    id,
    challenge: options.challenge,
    purpose: 'register',
    userId,
    expiresAt: nowSec() + CHALLENGE_LIFETIME_SEC
  }).run();

  return { options, challengeCookieValue: cookieValue };
}

// ---------------------------------------------------------------------------
// completeAddPasskey
// ---------------------------------------------------------------------------

export async function completeAddPasskey(
  db: Db,
  rp: RpConfig,
  userId: string,
  challengeCookieValue: string,
  attestation: RegistrationResponseJSON
): Promise<{ passkeyId: string }> {
  const { challenge, rawUserId } = consumeChallenge(db, challengeCookieValue, 'register');

  // rawUserId is either a plain string userId or a JSON signup meta — handle both
  let challengeUserId: string;
  try {
    const meta = JSON.parse(rawUserId ?? '') as SignupMeta;
    challengeUserId = meta.userId;
  } catch {
    challengeUserId = rawUserId ?? '';
  }

  if (challengeUserId !== userId) throw new Error('challenge userId mismatch');

  const verification = await verifyRegistration({
    rp,
    expectedChallenge: challenge,
    response: attestation
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('registration verification failed');
  }

  const { registrationInfo } = verification;
  const { credential, aaguid, credentialDeviceType, credentialBackedUp } = registrationInfo;

  const passkeyId = createId();
  const now = nowSec();

  db.insert(schema.passkeys).values({
    id: passkeyId,
    userId,
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey),
    counter: credential.counter,
    transports: JSON.stringify(credential.transports ?? []),
    deviceName: suggestDeviceName(aaguid),
    aaguid,
    backupEligible: credentialDeviceType === 'multiDevice' ? 1 : 0,
    backupState: credentialBackedUp ? 1 : 0,
    createdAt: now,
    lastUsedAt: now
  }).run();

  return { passkeyId };
}

// ---------------------------------------------------------------------------
// revokePasskey
// ---------------------------------------------------------------------------

export async function revokePasskey(db: Db, userId: string, passkeyId: string): Promise<void> {
  const count = db
    .select()
    .from(schema.passkeys)
    .where(eq(schema.passkeys.userId, userId))
    .all().length;
  if (count <= 1) throw new Error('cannot revoke last passkey for this account');
  db.delete(schema.passkeys).where(eq(schema.passkeys.id, passkeyId)).run();
}

// ---------------------------------------------------------------------------
// signinWithRecoveryCode
// ---------------------------------------------------------------------------

export async function signinWithRecoveryCode(
  db: Db,
  username: string,
  code: string,
  userAgent: string
): Promise<{ userId: string; sessionCookieValue: string } | null> {
  const user = db.select().from(schema.users).where(eq(schema.users.username, username)).get();
  if (!user) return null; // avoid username enumeration

  const valid = await verifyRecoveryCode(db, user.id, code);
  if (!valid) return null;

  const { cookieValue: sessionCookieValue } = await createSession(db, user.id, userAgent);
  return { userId: user.id, sessionCookieValue };
}
