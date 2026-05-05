import type { RequestHandler } from './$types';
import { json, error } from '@sveltejs/kit';
import { getMarketData } from '$lib/server/market/factory';
import { isValidSymbol, normalizeSymbol } from '$lib/shared/symbols';

export const GET: RequestHandler = async ({ params, locals }) => {
  if (!locals.user) throw error(401, 'unauthorized');

  const symbol = normalizeSymbol(params.symbol ?? '');
  if (!isValidSymbol(symbol)) throw error(400, 'invalid symbol');

  const market = getMarketData();
  const today = new Date();
  const from = new Date(today);
  from.setDate(today.getDate() - 45); // 45 calendar days ≈ 30 trading days
  const fromIso = from.toISOString().slice(0, 10);
  const toIso = today.toISOString().slice(0, 10);

  const bars = await market.getHistoricalCloses(symbol, fromIso, toIso);
  return json({
    symbol,
    closes: bars.map((b) => b.closeCents),
    dates: bars.map((b) => b.date)
  });
};
