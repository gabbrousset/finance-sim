import { redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import type { PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';
import { PortfolioService } from '$lib/server/portfolio/service';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(302, '/signin');
	const db = getDb();
	const userId = locals.user.id;

	// Get current cash
	const userRow = db
		.select({ cashCents: schema.users.cashCents })
		.from(schema.users)
		.where(eq(schema.users.id, userId))
		.get();
	const currentCash = userRow?.cashCents ?? 0;

	// Get the ledger (newest first)
	const svc = new PortfolioService(db);
	const ledger = svc.transactionLedger(userId);

	// Compute running cash AFTER each transaction (to display alongside).
	// Walk backward from currentCash:
	//   cashAfter[newest] = currentCash
	//   cashAfter[i+1] = cashAfter[i] + shares[i] * price[i]  (reverses the trade)
	// Buy (positive shares) debits cash; reversal credits it back.
	// Sell (negative shares) credits cash; reversal debits it back.
	const rows = ledger.map((tx) => ({ tx, runningCash: 0 }));
	let running = currentCash;
	for (let i = 0; i < ledger.length; i++) {
		rows[i]!.runningCash = running;
		running += ledger[i]!.shares * ledger[i]!.priceCents;
	}

	return {
		currentCash,
		rows: rows.map((r) => ({
			id: r.tx.id,
			symbol: r.tx.symbol,
			shares: r.tx.shares,
			priceCents: r.tx.priceCents,
			executedAt: r.tx.executedAt,
			runningCash: r.runningCash
		}))
	};
};
