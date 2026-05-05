import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FinnhubAdapter } from './finnhub';
import { RateLimitError } from './types';

const fixture = readFileSync(join(__dirname, '__fixtures__/finnhub-quote.json'), 'utf8');

describe('FinnhubAdapter', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(fixture, { status: 200, headers: { 'content-type': 'application/json' } })
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('returns a Quote with cents', async () => {
    const a = new FinnhubAdapter('test-key');
    const q = await a.getLiveQuote('AAPL');
    expect(q?.priceCents).toBeGreaterThan(0);
    expect(q?.symbol).toBe('AAPL');
  });

  it('returns null when finnhub returns c=0 (unknown symbol)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ c: 0, d: 0, dp: 0, h: 0, l: 0, o: 0, pc: 0, t: 0 }), { status: 200 })
    );
    const a = new FinnhubAdapter('test-key');
    expect(await a.getLiveQuote('NOPE')).toBeNull();
  });

  it('throws RateLimitError on 429', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response('rate limit', { status: 429, headers: { 'retry-after': '15' } })
    );
    const a = new FinnhubAdapter('test-key');
    await expect(a.getLiveQuote('AAPL')).rejects.toBeInstanceOf(RateLimitError);
  });

  it('coalesces concurrent requests for the same symbol into one fetch', async () => {
    const a = new FinnhubAdapter('test-key');
    await Promise.all([a.getLiveQuote('AAPL'), a.getLiveQuote('AAPL'), a.getLiveQuote('AAPL')]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
