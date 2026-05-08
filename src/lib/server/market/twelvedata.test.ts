import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { TwelveDataAdapter } from './twelvedata';
import { RateLimitError } from './types';

const fixture = readFileSync(join(__dirname, '__fixtures__/twelvedata-aapl.json'), 'utf8');

describe('TwelveDataAdapter', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(fixture, { status: 200, headers: { 'content-type': 'application/json' } })
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('parses JSON values into HistoricalBars sorted ascending', async () => {
    const a = new TwelveDataAdapter('test-key');
    const bars = await a.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-04');
    expect(bars.length).toBe(3);
    expect(bars[0]?.date).toBe('2024-01-02');
    expect(bars[2]?.date).toBe('2024-01-04');
    expect(bars[0]?.closeCents).toBe(18564);  // 185.64 → 18564
    expect(bars[2]?.closeCents).toBe(18191);  // 181.91 → 18191
  });

  it('returns empty for status:error response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 400, message: 'symbol not found', status: 'error' }), { status: 200 })
    );
    const a = new TwelveDataAdapter('test-key');
    expect(await a.getHistoricalCloses('NOPE', '2024-01-02', '2024-01-04')).toEqual([]);
  });

  it('returns empty when values array is empty', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ meta: {}, values: [], status: 'ok' }), { status: 200 })
    );
    const a = new TwelveDataAdapter('test-key');
    expect(await a.getHistoricalCloses('AAPL', '2024-01-06', '2024-01-07')).toEqual([]);
  });

  it('throws RateLimitError on HTTP 429', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response('rate limit', { status: 429 })
    );
    const a = new TwelveDataAdapter('test-key');
    await expect(a.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-04')).rejects.toBeInstanceOf(RateLimitError);
  });

  it('throws RateLimitError on body code 429', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 429, message: 'rate limit', status: 'error' }), { status: 200 })
    );
    const a = new TwelveDataAdapter('test-key');
    await expect(a.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-04')).rejects.toBeInstanceOf(RateLimitError);
  });

  it('returns empty when apiKey is empty', async () => {
    const a = new TwelveDataAdapter('');
    expect(await a.getHistoricalCloses('AAPL', '2024-01-02', '2024-01-04')).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('getCloseAt returns one date', async () => {
    const a = new TwelveDataAdapter('test-key');
    expect(await a.getCloseAt('AAPL', '2024-01-02')).toBe(18564);
  });

  it('getLiveQuote returns null', async () => {
    const a = new TwelveDataAdapter('test-key');
    expect(await a.getLiveQuote('AAPL')).toBeNull();
  });
});
