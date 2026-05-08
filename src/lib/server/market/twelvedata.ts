import type { MarketData, Quote, HistoricalBar } from './types';
import { RateLimitError } from './types';
import { isValidSymbol, normalizeSymbol } from '../../shared/symbols';

const TD_BASE = 'https://api.twelvedata.com/time_series';

interface TdValue {
  datetime: string;
  close: string;
}

interface TdResponse {
  meta?: unknown;
  values?: TdValue[];
  status?: 'ok' | 'error';
  code?: number;
  message?: string;
}

export class TwelveDataAdapter implements MarketData {
  constructor(private apiKey: string) {}

  async getLiveQuote(_symbol: string): Promise<Quote | null> {
    // TwelveData has /price but we use Finnhub for live quotes.
    return null;
  }

  async getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return [];
    if (!this.apiKey) return [];

    const url =
      `${TD_BASE}?symbol=${encodeURIComponent(norm)}&interval=1day` +
      `&start_date=${from}&end_date=${to}&apikey=${encodeURIComponent(this.apiKey)}`;

    const res = await fetch(url);
    if (res.status === 429) throw new RateLimitError(60);

    const body = (await res.json()) as TdResponse;

    if (body.status === 'error') {
      if (body.code === 429) throw new RateLimitError(60);
      return [];
    }

    if (!Array.isArray(body.values) || body.values.length === 0) return [];

    const bars: HistoricalBar[] = [];
    for (const v of body.values) {
      const closeFloat = Number.parseFloat(v.close);
      if (!Number.isFinite(closeFloat)) continue;
      bars.push({ date: v.datetime, closeCents: Math.round(closeFloat * 100) });
    }
    // TwelveData returns values descending; sort ascending to match interface expectations.
    bars.sort((a, b) => a.date.localeCompare(b.date));
    return bars;
  }

  async getCloseAt(symbol: string, date: string): Promise<number | null> {
    const bars = await this.getHistoricalCloses(symbol, date, date);
    const row = bars.find((b) => b.date === date);
    return row?.closeCents ?? null;
  }
}
