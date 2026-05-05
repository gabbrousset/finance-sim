import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createDb, applyMigrations } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { MockMarketData } from './mock';
import { MarketDataService } from './service';
import { setCachedEod, getCachedEod } from './cache';

describe('MarketDataService', () => {
  let db: Db;
  let live: MockMarketData;
  let historical: MockMarketData;
  let svc: MarketDataService;

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    live = new MockMarketData();
    historical = new MockMarketData();
    svc = new MarketDataService(db, live, historical);
  });

  describe('getLiveQuote', () => {
    it('returns null for invalid symbols', async () => {
      expect(await svc.getLiveQuote('aapl ')).toBeNull();
      expect(await svc.getLiveQuote('')).toBeNull();
      expect(await svc.getLiveQuote('123')).toBeNull();
    });

    it('returns null when underlying adapter has no data', async () => {
      expect(await svc.getLiveQuote('AAPL')).toBeNull();
    });

    it('fetches from live adapter and returns quote', async () => {
      live.setLive('AAPL', 19500);
      const q = await svc.getLiveQuote('AAPL');
      expect(q).not.toBeNull();
      expect(q!.symbol).toBe('AAPL');
      expect(q!.priceCents).toBe(19500);
    });

    it('normalizes symbol (lowercase input)', async () => {
      live.setLive('AAPL', 19500);
      const q = await svc.getLiveQuote('aapl');
      expect(q?.priceCents).toBe(19500);
    });

    it('calls live adapter only once due to caching', async () => {
      live.setLive('AAPL', 19500);
      const spy = vi.spyOn(live, 'getLiveQuote');
      await svc.getLiveQuote('AAPL');
      await svc.getLiveQuote('AAPL');
      // First call fetches; second hits cache (regardless of market hours,
      // the cached value is always within the TTL window on the same second).
      expect(spy).toHaveBeenCalledTimes(1);
    });
  });

  describe('getCloseAt', () => {
    it('returns null for invalid symbols', async () => {
      expect(await svc.getCloseAt('bad symbol!', '2024-01-02')).toBeNull();
    });

    it('getCloseAt(today) falls through to live quote', async () => {
      live.setLive('AAPL', 19500);
      const today = new Date().toISOString().slice(0, 10);
      expect(await svc.getCloseAt('AAPL', today)).toBe(19500);
    });

    it('getCloseAt(today) returns null when live has no data', async () => {
      const today = new Date().toISOString().slice(0, 10);
      expect(await svc.getCloseAt('AAPL', today)).toBeNull();
    });

    it('getCloseAt(past) returns null when nothing is cached and historical has no data', async () => {
      expect(await svc.getCloseAt('AAPL', '2024-01-02')).toBeNull();
    });

    it('getCloseAt(past) hits cache when present, skips historical', async () => {
      setCachedEod(db, 'AAPL', '2024-01-02', 18500);
      const spy = vi.spyOn(historical, 'getCloseAt');
      expect(await svc.getCloseAt('AAPL', '2024-01-02')).toBe(18500);
      expect(spy).not.toHaveBeenCalled();
    });

    it('getCloseAt(past) falls through to historical on cache miss, then caches', async () => {
      historical.setHistorical('AAPL', '2024-01-02', 18500);
      expect(await svc.getCloseAt('AAPL', '2024-01-02')).toBe(18500);
      // second call must hit cache, not historical
      const spy = vi.spyOn(historical, 'getCloseAt');
      expect(await svc.getCloseAt('AAPL', '2024-01-02')).toBe(18500);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('getHistoricalCloses', () => {
    it('returns empty array for invalid symbols', async () => {
      expect(await svc.getHistoricalCloses('bad!', '2024-01-02', '2024-01-03')).toEqual([]);
    });

    it('returns empty array when historical has no data', async () => {
      expect(await svc.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-03')).toEqual([]);
    });

    it('fetches bars from historical adapter', async () => {
      historical.setHistorical('AAPL', '2024-01-02', 18500);
      historical.setHistorical('AAPL', '2024-01-03', 18400);
      const bars = await svc.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-03');
      expect(bars.length).toBe(2);
      expect(bars[0]).toEqual({ date: '2024-01-02', closeCents: 18500 });
      expect(bars[1]).toEqual({ date: '2024-01-03', closeCents: 18400 });
    });

    it('bulk-caches results so subsequent getCloseAt hits cache', async () => {
      historical.setHistorical('AAPL', '2024-01-02', 18500);
      historical.setHistorical('AAPL', '2024-01-03', 18400);
      await svc.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-03');
      // verify cache was populated
      expect(getCachedEod(db, 'AAPL', '2024-01-02')?.closeCents).toBe(18500);
      expect(getCachedEod(db, 'AAPL', '2024-01-03')?.closeCents).toBe(18400);
    });

    it('subsequent getCloseAt calls use cache after getHistoricalCloses', async () => {
      historical.setHistorical('AAPL', '2024-01-02', 18500);
      await svc.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-02');
      const spy = vi.spyOn(historical, 'getCloseAt');
      expect(await svc.getCloseAt('AAPL', '2024-01-02')).toBe(18500);
      expect(spy).not.toHaveBeenCalled();
    });
  });
});
