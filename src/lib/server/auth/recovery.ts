import { eq, and, isNull } from 'drizzle-orm';
import argon2 from 'argon2';
import { createId } from '@paralleldrive/cuid2';
import { randomBytes } from 'node:crypto';
import { schema, type Db } from '$lib/server/db/client';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I confusion
const GROUP = 4;
const GROUPS = 4;
const COUNT = 8;

function generateCode(): string {
  const buf = randomBytes(GROUP * GROUPS);
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    out += ALPHABET[buf[i]! % ALPHABET.length];
    if ((i + 1) % GROUP === 0 && i !== buf.length - 1) out += '-';
  }
  return out;
}

export async function generateRecoveryCodes(db: Db, userId: string): Promise<string[]> {
  const codes: string[] = [];
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < COUNT; i++) {
    const code = generateCode();
    codes.push(code);
    const codeHash = await argon2.hash(code, { type: argon2.argon2id });
    db.insert(schema.recoveryCodes).values({
      id: createId(),
      userId,
      codeHash,
      usedAt: null,
      createdAt: now
    }).run();
  }
  return codes;
}

export async function verifyRecoveryCode(db: Db, userId: string, code: string): Promise<boolean> {
  const rows = db
    .select()
    .from(schema.recoveryCodes)
    .where(and(eq(schema.recoveryCodes.userId, userId), isNull(schema.recoveryCodes.usedAt)))
    .all();
  for (const row of rows) {
    if (await argon2.verify(row.codeHash, code)) {
      db.update(schema.recoveryCodes)
        .set({ usedAt: Math.floor(Date.now() / 1000) })
        .where(eq(schema.recoveryCodes.id, row.id))
        .run();
      return true;
    }
  }
  return false;
}

export async function regenerateRecoveryCodes(db: Db, userId: string): Promise<string[]> {
  db.delete(schema.recoveryCodes).where(eq(schema.recoveryCodes.userId, userId)).run();
  return generateRecoveryCodes(db, userId);
}
