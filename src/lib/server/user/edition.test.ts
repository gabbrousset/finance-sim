import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema, type Db } from '$lib/server/db/client';
import { editionNoForUser } from './edition';

describe('editionNoForUser', () => {
	let db: Db;

	beforeEach(() => {
		db = createDb(':memory:');
		applyMigrations(db);
		db.insert(schema.users)
			.values({
				id: 'u1',
				username: 'alice',
				displayName: 'Alice',
				cashCents: 1_000_000,
				createdAt: 0
			})
			.run();
	});

	it('returns 1 for a user with no transactions', () => {
		expect(editionNoForUser(db, 'u1')).toBe(1);
	});

	it('returns count(distinct trading day) + 1', () => {
		const day1 = Math.floor(new Date('2026-05-01T14:00:00Z').getTime() / 1000);
		const day1b = Math.floor(new Date('2026-05-01T18:00:00Z').getTime() / 1000);
		const day2 = Math.floor(new Date('2026-05-02T14:00:00Z').getTime() / 1000);

		db.insert(schema.transactions)
			.values([
				{ id: 't1', userId: 'u1', symbol: 'AAPL', shares: 5, priceCents: 29277, executedAt: day1 },
				{ id: 't2', userId: 'u1', symbol: 'AAPL', shares: -1, priceCents: 29300, executedAt: day1b },
				{ id: 't3', userId: 'u1', symbol: 'MSFT', shares: 3, priceCents: 41492, executedAt: day2 }
			])
			.run();

		expect(editionNoForUser(db, 'u1')).toBe(3); // 2 distinct days + 1
	});

	it('only counts the queried user', () => {
		db.insert(schema.users)
			.values({ id: 'u2', username: 'bob', displayName: 'Bob', cashCents: 1_000_000, createdAt: 0 })
			.run();
		const day1 = Math.floor(new Date('2026-05-01T14:00:00Z').getTime() / 1000);
		db.insert(schema.transactions)
			.values({ id: 't1', userId: 'u2', symbol: 'AAPL', shares: 5, priceCents: 29277, executedAt: day1 })
			.run();
		expect(editionNoForUser(db, 'u1')).toBe(1);
		expect(editionNoForUser(db, 'u2')).toBe(2);
	});
});
