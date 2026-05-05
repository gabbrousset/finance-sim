import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { createSession, resolveSession, revokeSession, hashSessionId } from './sessions';

describe('sessions', () => {
  let db: Db;
  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
  });

  it('creates a session and resolves it via the cookie value', async () => {
    const { cookieValue, expiresAt } = await createSession(db, 'u1', 'jest');
    expect(cookieValue.length).toBeGreaterThanOrEqual(32);
    expect(expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    const resolved = await resolveSession(db, cookieValue);
    expect(resolved?.userId).toBe('u1');
  });

  it('returns null for unknown cookie values', async () => {
    expect(await resolveSession(db, 'unknown')).toBeNull();
  });

  it('returns null for expired sessions', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest', -1);
    expect(await resolveSession(db, cookieValue)).toBeNull();
  });

  it('revokes a session', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest');
    await revokeSession(db, cookieValue);
    expect(await resolveSession(db, cookieValue)).toBeNull();
  });

  it('stores hashed session id, never the raw cookie value', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest');
    const rows = db.select().from(schema.sessions).all();
    expect(rows[0]?.id).not.toBe(cookieValue);
    expect(rows[0]?.id).toBe(hashSessionId(cookieValue));
  });
});
