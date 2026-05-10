import { fail, redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import type { Actions, PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { PortfolioService } from '$lib/server/portfolio/service';
import { isValidSymbol, normalizeSymbol } from '$lib/shared/symbols';
import { formatUsd } from '$lib/shared/money';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(302, '/signin');
	const db = getDb();
	const userId = locals.user.id;
	const userRow = db
		.select({ cashCents: schema.users.cashCents })
		.from(schema.users)
		.where(eq(schema.users.id, userId))
		.get();
	const holdings = db
		.select()
		.from(schema.holdings)
		.where(eq(schema.holdings.userId, userId))
		.all();
	return {
		cashCents: userRow?.cashCents ?? 0,
		holdings: holdings.map((h) => ({ symbol: h.symbol, shares: h.shares }))
	};
};

export const actions: Actions = {
	default: async ({ request, locals }) => {
		if (!locals.user) return fail(401, { error: 'unauthorized' });
		const form = await request.formData();
		const mode = String(form.get('mode') ?? '');
		const rawSymbol = String(form.get('symbol') ?? '').trim();
		const sharesStr = String(form.get('shares') ?? '').trim();

		if (mode !== 'buy' && mode !== 'sell') {
			return fail(400, { error: 'mode must be buy or sell', mode, symbol: rawSymbol, shares: sharesStr });
		}

		const symbol = normalizeSymbol(rawSymbol);
		if (!isValidSymbol(symbol)) {
			return fail(400, { error: 'invalid symbol', mode, symbol: rawSymbol, shares: sharesStr });
		}

		const shares = Number.parseInt(sharesStr, 10);
		if (!Number.isFinite(shares) || shares <= 0) {
			return fail(400, { error: 'shares must be a positive integer', mode, symbol: rawSymbol, shares: sharesStr });
		}

		const db = getDb();
		const market = getMarketData();
		const quote = await market.getLiveQuote(symbol);
		if (!quote) {
			return fail(400, { error: `no quote available for ${symbol}`, mode, symbol: rawSymbol, shares: sharesStr });
		}

		const svc = new PortfolioService(db);
		try {
			if (mode === 'buy') {
				svc.buy(locals.user.id, symbol, shares, quote.priceCents);
			} else {
				svc.sell(locals.user.id, symbol, shares, quote.priceCents);
			}
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'trade failed';
			return fail(400, { error: msg, mode, symbol: rawSymbol, shares: sharesStr });
		}

		return {
			success: true,
			mode,
			symbol,
			shares,
			priceCents: quote.priceCents,
			message: `Filled. ${mode === 'buy' ? 'Bought' : 'Sold'} ${shares} ${symbol} @ ${formatUsd(quote.priceCents)}`
		};
	}
};
