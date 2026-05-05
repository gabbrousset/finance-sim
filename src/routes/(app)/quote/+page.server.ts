import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getMarketData } from '$lib/server/market/factory';
import { isValidSymbol, normalizeSymbol } from '$lib/shared/symbols';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(302, '/signin');
	return {};
};

export const actions: Actions = {
	default: async ({ request, locals }) => {
		if (!locals.user) return fail(401, { error: 'unauthorized' });
		const form = await request.formData();
		const raw = String(form.get('symbol') ?? '').trim();
		const symbol = normalizeSymbol(raw);
		if (!isValidSymbol(symbol)) return fail(400, { error: 'invalid symbol', symbol: raw });

		const market = getMarketData();
		const quote = await market.getLiveQuote(symbol);
		if (!quote) return fail(400, { error: `no quote for ${symbol}`, symbol: raw });

		return { symbol, priceCents: quote.priceCents, fetchedAt: quote.fetchedAt };
	}
};
