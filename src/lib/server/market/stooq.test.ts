import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { StooqAdapter } from './stooq';

const fixture = readFileSync(join(__dirname, '__fixtures__/stooq-aapl.csv'), 'utf8');

describe('StooqAdapter', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(fixture, { status: 200, headers: { 'content-type': 'text/csv' } })
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('parses CSV into HistoricalBars with cents', async () => {
    const a = new StooqAdapter();
    const bars = await a.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-05');
    expect(bars.length).toBeGreaterThan(0);
    expect(bars[0]?.closeCents).toBeGreaterThan(0);
    expect(bars[0]?.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('returns empty for unknown symbol (empty CSV body)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 200 }));
    const a = new StooqAdapter();
    expect(await a.getHistoricalCloses('NOPE', '2024-01-02', '2024-01-05')).toEqual([]);
  });

  it('getCloseAt returns just one date', async () => {
    const a = new StooqAdapter();
    expect(await a.getCloseAt('AAPL', '2024-01-02')).toBeGreaterThan(0);
  });
});
