import type { PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import { schema } from '$lib/server/db/client';
import { PortfolioService } from '$lib/server/portfolio/service';
import { equityCurve } from '$lib/server/portfolio/equity-curve';
import { getMarketData } from '$lib/server/market/factory';
import { redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';

export const load: PageServerLoad = async ({ locals }) => {
  if (!locals.user) throw redirect(302, '/signin');
  const userId = locals.user.id;
  const db = getDb();
  const market = getMarketData();
  const svc = new PortfolioService(db);

  // Fetch current holdings to determine which symbols need live quotes.
  const holdingsRows = db
    .select()
    .from(schema.holdings)
    .where(eq(schema.holdings.userId, userId))
    .all();
  const symbols = holdingsRows.map((h) => h.symbol);

  // Fetch live quotes for all held symbols in parallel.
  const quoteEntries = await Promise.all(
    symbols.map(async (s) => {
      const q = await market.getLiveQuote(s);
      return [s, q?.priceCents ?? 0] as const;
    })
  );
  const quotes = new Map(quoteEntries);

  const valuation = svc.valuate(userId, quotes);

  // Equity curve: last 30 days.
  // equityCurve replays the full transaction ledger from startingCashCents
  // to derive state at fromIso before walking forward — so we always pass
  // the original per-user default (1_000_000 cents = $10,000).
  const today = new Date();
  const from = new Date(today);
  from.setDate(today.getDate() - 30);
  const fromIso = from.toISOString().slice(0, 10);
  const toIso = today.toISOString().slice(0, 10);

  const startingCash = 1_000_000; // default from schema; equityCurve replays full ledger

  const curve = await equityCurve(db, userId, market, startingCash, fromIso, toIso);

  return {
    cashCents: valuation.cashCents,
    holdings: valuation.holdings.map((h) => ({
      symbol: h.symbol,
      shares: h.shares,
      priceCents: h.priceCents,
      valueCents: h.valueCents
    })),
    totalCents: valuation.totalCents,
    curve
  };
};
