import { eq, asc } from 'drizzle-orm';
import type { Db } from '$lib/server/db/client';
import { schema } from '$lib/server/db/client';
import type { MarketData } from '$lib/server/market/types';
import { isMarketOpen } from '$lib/server/market/market-hours';
import { parseIsoDate, toIsoDate, daysBetween } from '$lib/shared/dates';

export interface EquityPoint {
  date: string;       // 'YYYY-MM-DD'
  valueCents: number; // cash + sum(shares * close)
}

/**
 * Walks forward day-by-day across [fromIso, toIso] (inclusive),
 * replaying transactions chronologically and computing portfolio
 * value at each day's close.
 *
 * - User starts with `startingCashCents` at the beginning of the run.
 * - Transactions before fromIso are applied before the first day to
 *   establish initial state.
 * - Each transaction's trading date is determined via toIsoDate(executedAt),
 *   which uses UTC midnight. Trades made after midnight UTC but before market
 *   close ET will be attributed to the next calendar day (UTC midnight ≈ 8pm ET).
 *   For v3.0, this approximation is acceptable; callers should use executedAt
 *   values that fall within the target day in UTC.
 * - For each trading day, look up the close price per held symbol via
 *   MarketData.getCloseAt; if null, fall back to the last known close per symbol
 *   (or 0 if never seen).
 * - Non-trading days (weekends/holidays) are skipped.
 *
 * Returns one EquityPoint per trading day in the range.
 */
export async function equityCurve(
  db: Db,
  userId: string,
  market: MarketData,
  startingCashCents: number,
  fromIso: string,
  toIso: string
): Promise<EquityPoint[]> {
  // Pull all transactions for the user sorted by executedAt ascending
  const txns = db
    .select({
      symbol: schema.transactions.symbol,
      shares: schema.transactions.shares,
      priceCents: schema.transactions.priceCents,
      executedAt: schema.transactions.executedAt
    })
    .from(schema.transactions)
    .where(eq(schema.transactions.userId, userId))
    .orderBy(asc(schema.transactions.executedAt))
    .all();

  // Running state
  let cashCents = startingCashCents;
  const holdings = new Map<string, number>(); // symbol -> shares
  const lastKnownClose = new Map<string, number>(); // symbol -> last seen close cents

  // Apply all transactions before fromIso to establish initial state
  let txnIdx = 0;
  for (; txnIdx < txns.length; txnIdx++) {
    const txn = txns[txnIdx]!;
    const txnDate = toIsoDate(txn.executedAt);
    if (txnDate >= fromIso) break;
    cashCents -= txn.shares * txn.priceCents;
    updateHolding(txn.symbol, txn.shares, holdings);
  }

  const result: EquityPoint[] = [];
  const totalDays = daysBetween(fromIso, toIso);
  const fromUnix = parseIsoDate(fromIso);

  for (let i = 0; i < totalDays; i++) {
    const dayUnix = fromUnix + i * 86_400;
    const dateIso = toIsoDate(dayUnix);

    // Apply any transactions whose date matches this day
    for (; txnIdx < txns.length; txnIdx++) {
      const txn = txns[txnIdx]!;
      const txnDate = toIsoDate(txn.executedAt);
      if (txnDate !== dateIso) break;
      cashCents -= txn.shares * txn.priceCents;
      updateHolding(txn.symbol, txn.shares, holdings);
    }

    // Skip non-trading days (weekends/holidays)
    if (!isTradingDay(dateIso)) continue;

    // Look up closes for all held symbols and compute total holding value
    let holdingValue = 0;
    for (const [symbol, shares] of holdings) {
      if (shares === 0) continue;
      const close = await market.getCloseAt(symbol, dateIso);
      let closeCents: number;
      if (close !== null) {
        closeCents = close;
        lastKnownClose.set(symbol, close);
      } else {
        closeCents = lastKnownClose.get(symbol) ?? 0;
      }
      holdingValue += shares * closeCents;
    }

    result.push({ date: dateIso, valueCents: cashCents + holdingValue });
  }

  return result;
}

function updateHolding(symbol: string, shares: number, holdings: Map<string, number>): void {
  const current = holdings.get(symbol) ?? 0;
  const updated = current + shares;
  if (updated === 0) {
    holdings.delete(symbol);
  } else {
    holdings.set(symbol, updated);
  }
}

function isTradingDay(iso: string): boolean {
  // noon-ET-ish in UTC: parseIsoDate(iso) gives 00:00 UTC; add 16h to land at noon ET.
  return isMarketOpen(parseIsoDate(iso) + 16 * 3600);
}
