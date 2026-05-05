import type { MarketData, Quote, HistoricalBar } from './types';
import { isValidSymbol, normalizeSymbol } from '../../shared/symbols';

const STOOQ_BASE = 'https://stooq.com/q/d/l/';

function toStooqDate(iso: string): string {
  return iso.replace(/-/g, '');
}

function parseCsv(body: string): HistoricalBar[] {
  const lines = body.split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];

  const header = lines[0];
  if (!header || !header.startsWith('Date,')) return [];

  const data = lines.slice(1);
  const bars: HistoricalBar[] = [];

  for (const line of data) {
    const cols = line.split(',');
    const date = cols[0];
    const closeRaw = cols[4];
    if (!date || !closeRaw) continue;
    const parsed = parseFloat(closeRaw);
    if (isNaN(parsed)) continue;
    bars.push({ date, closeCents: Math.round(parsed * 100) });
  }

  return bars;
}

export class StooqAdapter implements MarketData {
  async getLiveQuote(_symbol: string): Promise<Quote | null> {
    return null;
  }

  async getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]> {
    const norm = normalizeSymbol(symbol);
    if (!isValidSymbol(norm)) return [];

    const s = encodeURIComponent(norm.toLowerCase() + '.us');
    const d1 = toStooqDate(from);
    const d2 = toStooqDate(to);
    const url = `${STOOQ_BASE}?s=${s}&d1=${d1}&d2=${d2}&i=d`;

    const res = await fetch(url);
    const body = await res.text();
    return parseCsv(body);
  }

  async getCloseAt(symbol: string, date: string): Promise<number | null> {
    const bars = await this.getHistoricalCloses(symbol, date, date);
    const row = bars.find((b) => b.date === date);
    return row?.closeCents ?? null;
  }
}
