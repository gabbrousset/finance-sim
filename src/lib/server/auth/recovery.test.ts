import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { generateRecoveryCodes, verifyRecoveryCode, regenerateRecoveryCodes } from './recovery';

describe('recovery codes', () => {
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

  it('generates exactly 8 unique codes', async () => {
    const codes = await generateRecoveryCodes(db, 'u1');
    expect(codes).toHaveLength(8);
    expect(new Set(codes).size).toBe(8);
  });

  it('verifies a code once, then rejects reuse', async () => {
    const codes = await generateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', codes[0]!)).toBe(true);
    expect(await verifyRecoveryCode(db, 'u1', codes[0]!)).toBe(false);
  });

  it('rejects unknown codes', async () => {
    await generateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', 'WRONG-CODE-1234-WXYZ')).toBe(false);
  });

  it('regenerate replaces all unused codes', async () => {
    const first = await generateRecoveryCodes(db, 'u1');
    const second = await regenerateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', first[0]!)).toBe(false);
    expect(await verifyRecoveryCode(db, 'u1', second[0]!)).toBe(true);
  });
});
