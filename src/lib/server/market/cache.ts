import { eq, and } from 'drizzle-orm';
import { schema, type Db } from '$lib/server/db/client';
import { isMarketOpen } from './market-hours';
import { toIsoDate } from '$lib/shared/dates';

const LIVE_TTL_OPEN_SEC = 60;

export function getCachedLive(
  db: Db,
  symbol: string,
  now = Math.floor(Date.now() / 1000)
): { priceCents: number; fetchedAt: number } | null {
  const row = db
    .select()
    .from(schema.quoteCacheLive)
    .where(eq(schema.quoteCacheLive.symbol, symbol))
    .get();
  if (!row) return null;
  // Open hours: 60s TTL.
  // Closed hours (weekend, after-hours, holiday): infinite — price won't move.
  if (isMarketOpen(now)) {
    if (now - row.fetchedAt > LIVE_TTL_OPEN_SEC) return null;
  }
  return { priceCents: row.priceCents, fetchedAt: row.fetchedAt };
}

export function setCachedLive(
  db: Db,
  symbol: string,
  priceCents: number,
  now = Math.floor(Date.now() / 1000)
): void {
  db.insert(schema.quoteCacheLive)
    .values({ symbol, priceCents, fetchedAt: now })
    .onConflictDoUpdate({
      target: schema.quoteCacheLive.symbol,
      set: { priceCents, fetchedAt: now }
    })
    .run();
}

export function getCachedEod(
  db: Db,
  symbol: string,
  date: string,
  now = Math.floor(Date.now() / 1000)
): { closeCents: number } | null {
  // Today's date is never EOD-cached — it isn't a closed bar.
  if (date === toIsoDate(now)) return null;
  const row = db
    .select()
    .from(schema.quoteCacheEod)
    .where(
      and(
        eq(schema.quoteCacheEod.symbol, symbol),
        eq(schema.quoteCacheEod.tradeDate, date)
      )
    )
    .get();
  return row ? { closeCents: row.closeCents } : null;
}

export function setCachedEod(
  db: Db,
  symbol: string,
  date: string,
  closeCents: number
): void {
  db.insert(schema.quoteCacheEod)
    .values({ symbol, tradeDate: date, closeCents })
    .onConflictDoUpdate({
      target: [schema.quoteCacheEod.symbol, schema.quoteCacheEod.tradeDate],
      set: { closeCents }
    })
    .run();
}

export function bulkSetEod(
  db: Db,
  rows: { symbol: string; date: string; closeCents: number }[]
): void {
  if (rows.length === 0) return;
  db.transaction((tx) => {
    for (const r of rows) {
      tx.insert(schema.quoteCacheEod)
        .values({ symbol: r.symbol, tradeDate: r.date, closeCents: r.closeCents })
        .onConflictDoUpdate({
          target: [schema.quoteCacheEod.symbol, schema.quoteCacheEod.tradeDate],
          set: { closeCents: r.closeCents }
        })
        .run();
    }
  });
}
