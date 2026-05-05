import type { MarketData, Quote, HistoricalBar } from './types';

export class MockMarketData implements MarketData {
  private live = new Map<string, number>();
  private eod = new Map<string, Map<string, number>>();

  setLive(symbol: string, priceCents: number) {
    this.live.set(symbol, priceCents);
  }
  setHistorical(symbol: string, date: string, closeCents: number) {
    if (!this.eod.has(symbol)) this.eod.set(symbol, new Map());
    this.eod.get(symbol)!.set(date, closeCents);
  }

  async getLiveQuote(symbol: string): Promise<Quote | null> {
    const c = this.live.get(symbol);
    if (c == null) return null;
    return { symbol, priceCents: c, fetchedAt: Math.floor(Date.now() / 1000) };
  }
  async getCloseAt(symbol: string, date: string): Promise<number | null> {
    return this.eod.get(symbol)?.get(date) ?? null;
  }
  async getHistoricalCloses(
    symbol: string,
    from: string,
    to: string
  ): Promise<HistoricalBar[]> {
    const map = this.eod.get(symbol);
    if (!map) return [];
    const out: HistoricalBar[] = [];
    for (const [date, closeCents] of map) {
      if (date >= from && date <= to) out.push({ date, closeCents });
    }
    return out.sort((a, b) => a.date.localeCompare(b.date));
  }
}
