import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { MockMarketData } from '$lib/server/market/mock';
import { CompetitionService } from './service';
import { computeLeaderboard } from './leaderboard';
import { toIsoDate } from '$lib/shared/dates';

describe('computeLeaderboard', () => {
  let db: Db;
  let mkt: MockMarketData;
  let svc: CompetitionService;
  let nowSec = 1_700_000_000; // ~2023-11-14

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users)
      .values([
        { id: 'host', username: 'host', displayName: 'Host', cashCents: 0, createdAt: 0 },
        { id: 'guest', username: 'guest', displayName: 'Guest', cashCents: 0, createdAt: 0 }
      ])
      .run();
    mkt = new MockMarketData();
    svc = new CompetitionService(db, mkt, () => nowSec);
  });

  it('returns empty array for unknown competition', async () => {
    const board = await computeLeaderboard(db, mkt, 'nonexistent');
    expect(board).toEqual([]);
  });

  it('open live comp: everyone tied at starting cash, rank assigned, returnPct 0', async () => {
    const c = svc.create({
      hostId: 'host',
      name: 'live',
      type: 'live',
      startDateUnix: nowSec + 3600,
      endDateUnix: nowSec + 86400,
      startingCashCents: 1_000_000
    });
    svc.join(c.id, 'guest');

    const board = await computeLeaderboard(db, mkt, c.id);
    expect(board).toHaveLength(2);
    expect(board.every((r) => r.totalCents === 1_000_000)).toBe(true);
    expect(board.every((r) => r.returnPct === 0)).toBe(true);
    expect(board[0]?.rank).toBe(1);
    expect(board[1]?.rank).toBe(2);
  });

  it('finished historical comp: prices at end_date close', async () => {
    const start = nowSec - 86400 * 30;
    const end = nowSec - 86400 * 5;
    mkt.setHistorical('AAPL', toIsoDate(start), 19000);
    mkt.setHistorical('AAPL', toIsoDate(end), 21000);

    const c = svc.create({
      hostId: 'host',
      name: 'h',
      type: 'historical',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    svc.join(c.id, 'guest');
    await svc.tradeInComp({ competitionId: c.id, userId: 'host', symbol: 'AAPL', shares: 5 });
    svc.resolveHistorical(c.id);

    const board = await computeLeaderboard(db, mkt, c.id);
    // host: cash = 1M - 5*19000 = 905k; holdings @ end = 5*21000 = 105k; total = 1.01M
    // guest: 1M
    expect(board[0]?.userId).toBe('host');
    expect(board[0]?.totalCents).toBe(1_010_000);
    expect(board[0]?.rank).toBe(1);
    expect(board[1]?.userId).toBe('guest');
    expect(board[1]?.totalCents).toBe(1_000_000);
    expect(board[1]?.rank).toBe(2);
  });

  it('open historical comp with trade: prices at start_date close (invariant: total = starting cash)', async () => {
    const start = nowSec - 86400 * 30;
    const end = nowSec - 86400 * 5;
    mkt.setHistorical('AAPL', toIsoDate(start), 20000);
    mkt.setHistorical('AAPL', toIsoDate(end), 30000); // would be higher if end used, but shouldn't be

    const c = svc.create({
      hostId: 'host',
      name: 'open-hist',
      type: 'historical',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    svc.join(c.id, 'guest');
    // host buys 3 shares at start close (20000 each)
    await svc.tradeInComp({ competitionId: c.id, userId: 'host', symbol: 'AAPL', shares: 3 });

    const board = await computeLeaderboard(db, mkt, c.id);
    // host: cash = 1M - 3*20000 = 940k; holdings @ start = 3*20000 = 60k; total = 1M exactly
    expect(board.find((r) => r.userId === 'host')?.totalCents).toBe(1_000_000);
    expect(board.find((r) => r.userId === 'host')?.returnPct).toBe(0);
  });

  it('running live comp: prices at live quote', async () => {
    const start = nowSec + 3600;
    const end = nowSec + 86400;
    const c = svc.create({
      hostId: 'host',
      name: 'run-live',
      type: 'live',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    svc.join(c.id, 'guest');

    // Advance time to running, then trade
    nowSec = start + 1;
    svc = new CompetitionService(db, mkt, () => nowSec);
    svc.tickStatuses();

    await svc.tradeInComp({
      competitionId: c.id,
      userId: 'host',
      symbol: 'AAPL',
      shares: 5,
      priceCents: 15000
    });

    // Live quote at evaluation time
    mkt.setLive('AAPL', 18000);

    const board = await computeLeaderboard(db, mkt, c.id);
    // host: cash = 1M - 5*15000 = 925k; holdings @ live = 5*18000 = 90k; total = 1.015M
    const hostRow = board.find((r) => r.userId === 'host');
    expect(hostRow?.totalCents).toBe(1_015_000);
    expect(hostRow?.rank).toBe(1);
    const guestRow = board.find((r) => r.userId === 'guest');
    expect(guestRow?.totalCents).toBe(1_000_000);
    expect(guestRow?.rank).toBe(2);
  });

  it('null price treats holding as worthless', async () => {
    const start = nowSec - 86400 * 30;
    const end = nowSec - 86400 * 5;
    // Set start price so trade can happen, but don't set end price
    mkt.setHistorical('AAPL', toIsoDate(start), 20000);

    const c = svc.create({
      hostId: 'host',
      name: 'null-price',
      type: 'historical',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    await svc.tradeInComp({ competitionId: c.id, userId: 'host', symbol: 'AAPL', shares: 4 });
    svc.resolveHistorical(c.id);

    // No end-date price set → getCloseAt returns null → holding valued at 0
    const board = await computeLeaderboard(db, mkt, c.id);
    // host: cash = 1M - 4*20000 = 920k; holding @ null = 0; total = 920k
    expect(board[0]?.totalCents).toBe(920_000);
  });

  it('returnPct computed correctly for gain and loss', async () => {
    const start = nowSec - 86400 * 30;
    const end = nowSec - 86400 * 5;
    mkt.setHistorical('MSFT', toIsoDate(start), 10000);
    mkt.setHistorical('MSFT', toIsoDate(end), 15000); // 50% gain per share

    const c = svc.create({
      hostId: 'host',
      name: 'ret-pct',
      type: 'historical',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    await svc.tradeInComp({ competitionId: c.id, userId: 'host', symbol: 'MSFT', shares: 100 });
    svc.resolveHistorical(c.id);

    const board = await computeLeaderboard(db, mkt, c.id);
    // host: cash = 1M - 100*10000 = 0; holdings @ end = 100*15000 = 1.5M; total = 1.5M
    // returnPct = (1.5M - 1M) / 1M = 0.5
    const hostRow = board.find((r) => r.userId === 'host');
    expect(hostRow?.totalCents).toBe(1_500_000);
    expect(hostRow?.returnPct).toBeCloseTo(0.5);
  });

  it('sort descending and display names populated', async () => {
    const start = nowSec - 86400 * 30;
    const end = nowSec - 86400 * 5;
    mkt.setHistorical('AAPL', toIsoDate(start), 10000);
    mkt.setHistorical('AAPL', toIsoDate(end), 20000);

    const c = svc.create({
      hostId: 'host',
      name: 'sort-test',
      type: 'historical',
      startDateUnix: start,
      endDateUnix: end,
      startingCashCents: 1_000_000
    });
    svc.join(c.id, 'guest');
    // guest buys 10 shares — should come out ahead
    await svc.tradeInComp({ competitionId: c.id, userId: 'guest', symbol: 'AAPL', shares: 10 });
    svc.resolveHistorical(c.id);

    const board = await computeLeaderboard(db, mkt, c.id);
    expect(board[0]?.userId).toBe('guest');
    expect(board[0]?.displayName).toBe('Guest');
    expect(board[0]?.rank).toBe(1);
    expect(board[1]?.userId).toBe('host');
    expect(board[1]?.displayName).toBe('Host');
    expect(board[1]?.rank).toBe(2);
  });
});
