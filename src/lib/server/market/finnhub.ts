import type { MarketData, Quote, HistoricalBar } from './types';
import { RateLimitError } from './types';
import { isValidSymbol, normalizeSymbol } from '../../shared/symbols';

const FINNHUB_BASE = 'https://finnhub.io/api/v1/quote';

interface FinnhubQuote {
  c: number;  // current price
  d: number;  // change
  dp: number; // change percent
  h: number;  // high
  l: number;  // low
  o: number;  // open
  pc: number; // previous close
  t: number;  // timestamp (unix)
}

export class FinnhubAdapter implements MarketData {
  private inFlight = new Map<string, Promise<Quote | null>>();

  constructor(private apiKey: string) {}

  async getLiveQuote(symbol: string): Promise<Quote | null> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return null;

    const existing = this.inFlight.get(norm);
    if (existing) return existing;

    const p = this.doFetch(norm).finally(() => this.inFlight.delete(norm));
    this.inFlight.set(norm, p);
    return p;
  }

  private async doFetch(symbol: string): Promise<Quote | null> {
    const url = `${FINNHUB_BASE}?symbol=${encodeURIComponent(symbol)}&token=${encodeURIComponent(this.apiKey)}`;
    const res = await fetch(url);

    if (res.status === 429) {
      const retryHeader = res.headers.get('retry-after');
      const retryAfterSec = retryHeader ? parseInt(retryHeader, 10) : 60;
      throw new RateLimitError(isNaN(retryAfterSec) ? 60 : retryAfterSec);
    }

    if (!res.ok) return null;

    const data: FinnhubQuote = await res.json();

    // Finnhub returns c=0 when the symbol is unknown
    if (data.c === 0) return null;

    return {
      symbol,
      priceCents: Math.round(data.c * 100),
      fetchedAt: data.t * 1000,
    };
  }

  async getHistoricalCloses(_symbol: string, _from: string, _to: string): Promise<HistoricalBar[]> {
    // Finnhub free tier doesn't grant reliable /candle access; use Stooq for historical data.
    return [];
  }

  async getCloseAt(_symbol: string, _date: string): Promise<number | null> {
    return null;
  }
}
