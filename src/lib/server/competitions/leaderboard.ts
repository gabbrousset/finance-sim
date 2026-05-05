import { eq } from 'drizzle-orm';
import type { Db } from '$lib/server/db/client';
import { schema } from '$lib/server/db/client';
import type { MarketData } from '$lib/server/market/types';
import { toIsoDate } from '$lib/shared/dates';

export interface LeaderboardRow {
  userId: string;
  displayName: string;
  rank: number;
  totalCents: number;
  returnPct: number;
}

export async function computeLeaderboard(
  db: Db,
  market: MarketData,
  competitionId: string
): Promise<LeaderboardRow[]> {
  // 1. Load comp.
  const comp = db
    .select()
    .from(schema.competitions)
    .where(eq(schema.competitions.id, competitionId))
    .get();
  if (!comp) return [];

  // 2. Load members + display names.
  const members = db
    .select({
      userId: schema.competitionMembers.userId,
      displayName: schema.users.displayName
    })
    .from(schema.competitionMembers)
    .innerJoin(schema.users, eq(schema.users.id, schema.competitionMembers.userId))
    .where(eq(schema.competitionMembers.competitionId, competitionId))
    .all();

  // 3. Load cash per user.
  const cashRows = db
    .select()
    .from(schema.competitionCash)
    .where(eq(schema.competitionCash.competitionId, competitionId))
    .all();
  const cashByUser = new Map(cashRows.map((r) => [r.userId, r.cashCents]));

  // 4. Load holdings per user.
  const holdingRows = db
    .select()
    .from(schema.competitionHoldings)
    .where(eq(schema.competitionHoldings.competitionId, competitionId))
    .all();

  const holdingsByUser = new Map<string, { symbol: string; shares: number }[]>();
  for (const h of holdingRows) {
    if (!holdingsByUser.has(h.userId)) holdingsByUser.set(h.userId, []);
    holdingsByUser.get(h.userId)!.push({ symbol: h.symbol, shares: h.shares });
  }

  // 5. Determine prices based on status and type.
  const symbols = Array.from(new Set(holdingRows.map((h) => h.symbol)));
  const prices = new Map<string, number>();

  if (comp.status === 'finished') {
    const date = toIsoDate(comp.endDate);
    for (const s of symbols) {
      const p = await market.getCloseAt(s, date);
      prices.set(s, p ?? 0);
    }
  } else if (comp.status === 'running') {
    for (const s of symbols) {
      const q = await market.getLiveQuote(s);
      prices.set(s, q?.priceCents ?? 0);
    }
  } else if (comp.status === 'open' && comp.type === 'historical') {
    const date = toIsoDate(comp.startDate);
    for (const s of symbols) {
      const p = await market.getCloseAt(s, date);
      prices.set(s, p ?? 0);
    }
  }
  // open + live: no holdings exist yet; no price lookups needed.

  // 6. Compute totals per user.
  const rows = members.map((m) => {
    const cash = cashByUser.get(m.userId) ?? comp.startingCashCents;
    const myHoldings = holdingsByUser.get(m.userId) ?? [];
    const holdingsValue = myHoldings.reduce(
      (sum, h) => sum + h.shares * (prices.get(h.symbol) ?? 0),
      0
    );
    const totalCents = cash + holdingsValue;
    const returnPct = (totalCents - comp.startingCashCents) / comp.startingCashCents;
    return { userId: m.userId, displayName: m.displayName, totalCents, returnPct };
  });

  // 7. Sort descending by totalCents, assign 1-based rank.
  rows.sort((a, b) => b.totalCents - a.totalCents);
  return rows.map((r, i) => ({ ...r, rank: i + 1 }));
}
