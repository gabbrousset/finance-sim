import { eq, lt } from 'drizzle-orm';
import { createHash, randomBytes } from 'node:crypto';
import { schema, type Db } from '$lib/server/db/client';

const SESSION_LIFETIME_SEC = 60 * 60 * 24 * 30; // 30 days

export function hashSessionId(cookieValue: string): string {
  return createHash('sha256').update(cookieValue).digest('hex');
}

export interface CreatedSession {
  cookieValue: string;
  expiresAt: number;
}

export async function createSession(
  db: Db,
  userId: string,
  userAgent: string,
  lifetimeSecOverride?: number
): Promise<CreatedSession> {
  const cookieValue = randomBytes(32).toString('base64url');
  const id = hashSessionId(cookieValue);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + (lifetimeSecOverride ?? SESSION_LIFETIME_SEC);
  db.insert(schema.sessions).values({
    id,
    userId,
    expiresAt,
    createdAt: now,
    userAgent
  }).run();
  return { cookieValue, expiresAt };
}

export interface ResolvedSession {
  userId: string;
  expiresAt: number;
}

export async function resolveSession(
  db: Db,
  cookieValue: string
): Promise<ResolvedSession | null> {
  const id = hashSessionId(cookieValue);
  const now = Math.floor(Date.now() / 1000);
  const row = db
    .select()
    .from(schema.sessions)
    .where(eq(schema.sessions.id, id))
    .get();
  if (!row) return null;
  if (row.expiresAt <= now) {
    db.delete(schema.sessions).where(eq(schema.sessions.id, id)).run();
    return null;
  }
  return { userId: row.userId, expiresAt: row.expiresAt };
}

export async function revokeSession(db: Db, cookieValue: string): Promise<void> {
  const id = hashSessionId(cookieValue);
  db.delete(schema.sessions).where(eq(schema.sessions.id, id)).run();
}

export async function revokeExpired(db: Db): Promise<number> {
  const now = Math.floor(Date.now() / 1000);
  const res = db.delete(schema.sessions).where(lt(schema.sessions.expiresAt, now)).run();
  return res.changes;
}
