import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import * as auth from './service';

describe('auth service', () => {
  let db: Db;
  const rp = { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' };

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
  });

  it('beginSignup returns options + a challenge cookie', async () => {
    const out = await auth.beginSignup(db, rp, 'alice', 'Alice', 'jest-ua');
    expect(out.options.user.name).toBe('alice');
    expect(out.challengeCookieValue).toBeDefined();
  });

  it('beginSignup rejects taken usernames', async () => {
    db.insert(schema.users).values({
      id: 'x', username: 'alice', displayName: 'Alice', cashCents: 0, createdAt: 0
    }).run();
    await expect(auth.beginSignup(db, rp, 'alice', 'Alice', 'jest-ua')).rejects.toThrow();
  });

  it('signinWithRecoveryCode returns a session for valid code', async () => {
    const userId = 'u1';
    db.insert(schema.users).values({
      id: userId, username: 'alice', displayName: 'Alice', cashCents: 1_000_000, createdAt: 0
    }).run();
    const codes = await (await import('./recovery')).generateRecoveryCodes(db, userId);
    const sess = await auth.signinWithRecoveryCode(db, 'alice', codes[0]!, 'jest-ua');
    expect(sess?.userId).toBe(userId);
  });

  it('signinWithRecoveryCode returns null on bad code', async () => {
    db.insert(schema.users).values({
      id: 'u1', username: 'alice', displayName: 'Alice', cashCents: 1_000_000, createdAt: 0
    }).run();
    const sess = await auth.signinWithRecoveryCode(db, 'alice', 'bogus', 'jest-ua');
    expect(sess).toBeNull();
  });

  it('revokePasskey refuses to delete the last passkey', async () => {
    const userId = 'u1';
    db.insert(schema.users).values({
      id: userId, username: 'a', displayName: 'A', cashCents: 0, createdAt: 0
    }).run();
    db.insert(schema.passkeys).values({
      id: 'pk1', userId, credentialId: 'c1', publicKey: Buffer.from([1]),
      counter: 0, transports: '[]', deviceName: 'Phone', aaguid: '00000000-0000-0000-0000-000000000000',
      backupEligible: 1, backupState: 1, createdAt: 0, lastUsedAt: 0
    }).run();
    await expect(auth.revokePasskey(db, userId, 'pk1')).rejects.toThrow(/last passkey/);
  });
});
