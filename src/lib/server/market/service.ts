import type { MarketData, Quote, HistoricalBar } from './types';
import type { Db } from '$lib/server/db/client';
import { normalizeSymbol, isValidSymbol } from '$lib/shared/symbols';
import { toIsoDate } from '$lib/shared/dates';
import {
  getCachedLive,
  setCachedLive,
  getCachedEod,
  setCachedEod,
  bulkSetEod
} from './cache';

export class MarketDataService implements MarketData {
  constructor(
    private db: Db,
    private live: MarketData,
    private historical: MarketData
  ) {}

  async getLiveQuote(symbol: string): Promise<Quote | null> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return null;
    const cached = getCachedLive(this.db, norm);
    if (cached) {
      return { symbol: norm, priceCents: cached.priceCents, fetchedAt: cached.fetchedAt };
    }
    const fresh = await this.live.getLiveQuote(norm);
    if (fresh) {
      setCachedLive(this.db, norm, fresh.priceCents, fresh.fetchedAt);
    }
    return fresh;
  }

  async getCloseAt(symbol: string, date: string): Promise<number | null> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return null;
    const today = toIsoDate(Math.floor(Date.now() / 1000));
    if (date === today) {
      const live = await this.getLiveQuote(norm);
      return live?.priceCents ?? null;
    }
    const cached = getCachedEod(this.db, norm, date);
    if (cached) return cached.closeCents;
    const fresh = await this.historical.getCloseAt(norm, date);
    if (fresh != null) {
      setCachedEod(this.db, norm, date, fresh);
    }
    return fresh;
  }

  async getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return [];
    const bars = await this.historical.getHistoricalCloses(norm, from, to);
    if (bars.length > 0) {
      bulkSetEod(
        this.db,
        bars.map((b) => ({ symbol: norm, date: b.date, closeCents: b.closeCents }))
      );
    }
    return bars;
  }
}
