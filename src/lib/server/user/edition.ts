import { sql } from 'drizzle-orm';
import type { Db } from '$lib/server/db/client';

/**
 * Decorative "edition number" shown in the masthead and sidebar.
 * Equals the count of distinct calendar days on which the user has transactions, plus 1.
 * A user with zero trades sees "No. 1" on their first day.
 */
export function editionNoForUser(db: Db, userId: string): number {
	const result = db.all<{ days: number | bigint }>(
		sql`SELECT COUNT(DISTINCT DATE(executed_at, 'unixepoch')) AS days
		    FROM transactions WHERE user_id = ${userId}`
	);
	const days = result[0]?.days ?? 0;
	return Number(days) + 1;
}
