export interface Quote {
  symbol: string;
  priceCents: number;
  fetchedAt: number;
}

export interface HistoricalBar {
  date: string;     // 'YYYY-MM-DD'
  closeCents: number;
}

export interface MarketData {
  getLiveQuote(symbol: string): Promise<Quote | null>;
  getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]>;
  getCloseAt(symbol: string, date: string): Promise<number | null>;
}

export class RateLimitError extends Error {
  constructor(public retryAfterSec: number) {
    super(`rate limited, retry after ${retryAfterSec}s`);
    this.name = 'RateLimitError';
  }
}
