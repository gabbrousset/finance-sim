import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { getCachedLive, setCachedLive, getCachedEod, setCachedEod, bulkSetEod } from './cache';

describe('cache', () => {
  let db: Db;
  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
  });

  describe('getCachedLive / setCachedLive', () => {
    it('returns null when nothing is cached', () => {
      expect(getCachedLive(db, 'AAPL')).toBeNull();
    });

    it('caches and reads live quote during market hours (within TTL)', () => {
      // 2024-06-17 (Monday) 14:00 UTC == 10:00 ET — market open
      const open = 1718632800;
      setCachedLive(db, 'AAPL', 19500, open);
      expect(getCachedLive(db, 'AAPL', open + 30)).toEqual({ priceCents: 19500, fetchedAt: open });
    });

    it('expires after 60s during market hours', () => {
      const open = 1718632800;
      setCachedLive(db, 'AAPL', 19500, open);
      expect(getCachedLive(db, 'AAPL', open + 90)).toBeNull();
    });

    it('expires exactly at 60s boundary (strictly greater than TTL returns null)', () => {
      const open = 1718632800;
      setCachedLive(db, 'AAPL', 19500, open);
      // 60s exactly: now - fetchedAt = 60 > 60 is false, so still valid
      expect(getCachedLive(db, 'AAPL', open + 60)).toEqual({ priceCents: 19500, fetchedAt: open });
      // 61s: now - fetchedAt = 61 > 60 → null
      expect(getCachedLive(db, 'AAPL', open + 61)).toBeNull();
    });

    it('caches indefinitely outside market hours (Saturday)', () => {
      // 2024-06-15 (Saturday)
      const closed = 1718452800;
      setCachedLive(db, 'AAPL', 19500, closed);
      expect(getCachedLive(db, 'AAPL', closed + 86400)).toEqual({ priceCents: 19500, fetchedAt: closed });
    });

    it('caches indefinitely after market hours on a weekday', () => {
      // 2024-06-17 (Monday) 21:00 UTC == 17:00 ET — after close
      const afterHours = 1718654400;
      setCachedLive(db, 'AAPL', 20000, afterHours);
      expect(getCachedLive(db, 'AAPL', afterHours + 3600)).toEqual({ priceCents: 20000, fetchedAt: afterHours });
    });

    it('upserts on second write', () => {
      const t = 1718632800;
      setCachedLive(db, 'AAPL', 19500, t);
      setCachedLive(db, 'AAPL', 20000, t + 10);
      expect(getCachedLive(db, 'AAPL', t + 15)?.priceCents).toBe(20000);
    });
  });

  describe('getCachedEod / setCachedEod', () => {
    it('returns null for today\'s date (never EOD)', () => {
      const now = Math.floor(Date.now() / 1000);
      const today = new Date(now * 1000).toISOString().slice(0, 10);
      setCachedEod(db, 'AAPL', today, 19500);
      expect(getCachedEod(db, 'AAPL', today, now)).toBeNull();
    });

    it('returns null when nothing is cached for a past date', () => {
      expect(getCachedEod(db, 'AAPL', '2024-01-02')).toBeNull();
    });

    it('caches past EOD and returns it', () => {
      setCachedEod(db, 'AAPL', '2024-01-02', 18500);
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(18500);
    });

    it('upserts on second write for same symbol+date', () => {
      setCachedEod(db, 'AAPL', '2024-01-02', 18500);
      setCachedEod(db, 'AAPL', '2024-01-02', 19000);
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(19000);
    });

    it('stores different symbols separately', () => {
      setCachedEod(db, 'AAPL', '2024-01-02', 18500);
      setCachedEod(db, 'MSFT', '2024-01-02', 38000);
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(18500);
      expect(getCachedEod(db, 'MSFT', '2024-01-02')?.closeCents).toBe(38000);
    });
  });

  describe('bulkSetEod', () => {
    it('is a no-op for empty array', () => {
      expect(() => bulkSetEod(db, [])).not.toThrow();
    });

    it('inserts many rows at once', () => {
      bulkSetEod(db, [
        { symbol: 'AAPL', date: '2024-01-02', closeCents: 18500 },
        { symbol: 'AAPL', date: '2024-01-03', closeCents: 18400 },
        { symbol: 'MSFT', date: '2024-01-02', closeCents: 38000 }
      ]);
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(18500);
      expect(getCachedEod(db, 'AAPL', '2024-01-03')?.closeCents).toBe(18400);
      expect(getCachedEod(db, 'MSFT', '2024-01-02')?.closeCents).toBe(38000);
    });

    it('upserts on conflict', () => {
      setCachedEod(db, 'AAPL', '2024-01-02', 18500);
      bulkSetEod(db, [{ symbol: 'AAPL', date: '2024-01-02', closeCents: 19000 }]);
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(19000);
    });
  });
});
