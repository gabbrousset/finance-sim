import { describe, it, expect, beforeEach } from 'vitest';
import { MockMarketData } from './mock';

describe('MockMarketData', () => {
  let m: MockMarketData;
  beforeEach(() => {
    m = new MockMarketData();
    m.setLive('AAPL', 19500);
    m.setHistorical('AAPL', '2024-01-02', 18000);
    m.setHistorical('AAPL', '2024-12-31', 25000);
  });

  it('returns live quotes', async () => {
    const q = await m.getLiveQuote('AAPL');
    expect(q?.priceCents).toBe(19500);
  });

  it('returns null for unknown symbols', async () => {
    expect(await m.getLiveQuote('NOPE')).toBeNull();
  });

  it('returns single historical close', async () => {
    expect(await m.getCloseAt('AAPL', '2024-01-02')).toBe(18000);
  });

  it('returns range of closes', async () => {
    const bars = await m.getHistoricalCloses('AAPL', '2024-01-01', '2024-12-31');
    expect(bars.map((b) => b.date).sort()).toEqual(['2024-01-02', '2024-12-31']);
  });
});
