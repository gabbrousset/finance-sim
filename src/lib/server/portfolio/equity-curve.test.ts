import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { MockMarketData } from '$lib/server/market/mock';
import { equityCurve } from './equity-curve';

describe('equityCurve', () => {
  let db: Db;
  let mkt: MockMarketData;

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'a',
      displayName: 'A',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
    mkt = new MockMarketData();
  });

  it('all-cash portfolio is flat at starting cash on every trading day', async () => {
    // No transactions. Starting cash $10k. Mon-Fri week with no holidays.
    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-10', '2024-06-14');
    expect(curve).toHaveLength(5); // 5 trading days
    for (const p of curve) expect(p.valueCents).toBe(1_000_000);
  });

  it('skips weekends and holidays', async () => {
    // Range spans a weekend; 2024-06-15 is Sat, 2024-06-16 is Sun
    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-14', '2024-06-17');
    expect(curve.map((p) => p.date)).toEqual(['2024-06-14', '2024-06-17']);
  });

  it('reflects buy on the trade day', async () => {
    // Buy 5 AAPL at $190 on 2024-06-17 (Mon)
    db.insert(schema.transactions).values({
      id: 't1',
      userId: 'u1',
      symbol: 'AAPL',
      shares: 5,
      priceCents: 19000,
      executedAt: parseUnixSecondsFor('2024-06-17')
    }).run();
    mkt.setHistorical('AAPL', '2024-06-17', 19500);
    mkt.setHistorical('AAPL', '2024-06-18', 20000);

    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-17', '2024-06-18');
    // Day 1: cash = 1M - 5*19000 = 905,000; holdings val = 5*19500 = 97500; total = 1,002,500
    // Day 2: cash unchanged; holdings val = 5*20000 = 100,000; total = 1,005,000
    expect(curve[0]?.valueCents).toBe(1_002_500);
    expect(curve[1]?.valueCents).toBe(1_005_000);
  });

  it('uses last known close when a date has no entry in market data', async () => {
    db.insert(schema.transactions).values({
      id: 't1',
      userId: 'u1',
      symbol: 'AAPL',
      shares: 1,
      priceCents: 19000,
      executedAt: parseUnixSecondsFor('2024-06-17')
    }).run();
    mkt.setHistorical('AAPL', '2024-06-17', 19500);
    // No data for 06-18

    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-17', '2024-06-18');
    expect(curve[0]?.valueCents).toBe(1_000_000 - 19000 + 19500);
    expect(curve[1]?.valueCents).toBe(1_000_000 - 19000 + 19500); // re-uses 19500
  });

  it('pre-existing transactions before range are applied to initial state', async () => {
    // Buy 10 AAPL before the range; the range should start with fewer cash and shares held
    db.insert(schema.transactions).values({
      id: 't0',
      userId: 'u1',
      symbol: 'AAPL',
      shares: 10,
      priceCents: 18000,
      executedAt: parseUnixSecondsFor('2024-06-10') // before range
    }).run();
    mkt.setHistorical('AAPL', '2024-06-17', 20000);

    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-17', '2024-06-17');
    // cash = 1M - 10*18000 = 820,000; holdings val = 10*20000 = 200,000; total = 1,020,000
    expect(curve).toHaveLength(1);
    expect(curve[0]?.valueCents).toBe(820_000 + 200_000);
  });

  it('sell reduces holdings on trade day', async () => {
    // Buy 10 AAPL before range, sell 4 on first day of range
    db.insert(schema.transactions).values([
      {
        id: 't0',
        userId: 'u1',
        symbol: 'AAPL',
        shares: 10,
        priceCents: 18000,
        executedAt: parseUnixSecondsFor('2024-06-10')
      },
      {
        id: 't1',
        userId: 'u1',
        symbol: 'AAPL',
        shares: -4,
        priceCents: 19000,
        executedAt: parseUnixSecondsFor('2024-06-17')
      }
    ]).run();
    mkt.setHistorical('AAPL', '2024-06-17', 20000);

    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-17', '2024-06-17');
    // cash = 1M - 10*18000 + 4*19000 = 820,000 + 76,000 = 896,000
    // holdings val = 6*20000 = 120,000; total = 1,016,000
    expect(curve[0]?.valueCents).toBe(896_000 + 120_000);
  });

  it('returns correct date labels', async () => {
    // Use a Mon-Fri week with no NYSE holidays (June 10-14, 2024)
    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-10', '2024-06-14');
    expect(curve.map((p) => p.date)).toEqual([
      '2024-06-10',
      '2024-06-11',
      '2024-06-12',
      '2024-06-13',
      '2024-06-14'
    ]);
  });

  it('returns empty array for range with no trading days', async () => {
    // Saturday and Sunday
    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-06-15', '2024-06-16');
    expect(curve).toHaveLength(0);
  });

  it('skips NYSE holidays', async () => {
    // 2024-07-04 is Independence Day (NYSE holiday)
    const curve = await equityCurve(db, 'u1', mkt, 1_000_000, '2024-07-03', '2024-07-05');
    // July 3 = Wed (open), July 4 = Thu (holiday), July 5 = Fri (open)
    expect(curve.map((p) => p.date)).toEqual(['2024-07-03', '2024-07-05']);
  });
});

function parseUnixSecondsFor(iso: string): number {
  // 12:00 ET on date iso. (UTC midnight + 16h ~= noon ET in summer; close enough for tests.)
  return (
    Date.UTC(
      Number(iso.slice(0, 4)),
      Number(iso.slice(5, 7)) - 1,
      Number(iso.slice(8, 10))
    ) /
      1000 +
    16 * 3600
  );
}
