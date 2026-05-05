import { describe, it, expect } from 'vitest';
import { createDb, applyMigrations, schema } from './client';

describe('db client', () => {
  it('applies migrations and round-trips users', () => {
    const db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
    const rows = db.select().from(schema.users).all();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.username).toBe('alice');
  });
});
