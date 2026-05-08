// Singleton MarketData accessor.
//
// In test mode (NODE_ENV=test or MARKET_DATA=mock) returns a bare MockMarketData
// so unit/E2E tests run without API keys. In production wraps FinnhubAdapter
// (live quotes) + TwelveDataAdapter (historical closes) inside the caching
// MarketDataService layer.
//
// Set MARKET_DATA=mock in .env.local for keyless local dev.

import { env } from '$env/dynamic/private';
import { MarketDataService } from './service';
import { FinnhubAdapter } from './finnhub';
import { TwelveDataAdapter } from './twelvedata';
import { MockMarketData } from './mock';
import type { MarketData } from './types';
import { getDb } from '$lib/server/db/client';

let _instance: MarketData | null = null;

export function getMarketData(): MarketData {
  if (_instance) return _instance;
  if (env.NODE_ENV === 'test' || env.MARKET_DATA === 'mock') {
    const mock = new MockMarketData();
    const seedPath = env.MARKET_SEED_PATH ?? './e2e/fixtures/market-seed.json';
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const fs = require('node:fs') as typeof import('node:fs');
      if (fs.existsSync(seedPath)) {
        const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8')) as {
          live?: Record<string, number>;
          historical?: Record<string, Record<string, number>>;
        };
        for (const [sym, price] of Object.entries(seed.live ?? {})) {
          mock.setLive(sym, price);
        }
        for (const [sym, dates] of Object.entries(seed.historical ?? {})) {
          for (const [date, price] of Object.entries(dates)) {
            mock.setHistorical(sym, date, price);
          }
        }
      }
    } catch {
      // no seed file or parse error; ok — tests that need prices set them directly
    }
    _instance = mock;
  } else {
    const live = new FinnhubAdapter(env.FINNHUB_API_KEY ?? '');
    const historical = new TwelveDataAdapter(env.TWELVEDATA_API_KEY ?? '');
    _instance = new MarketDataService(getDb(), live, historical);
  }
  return _instance;
}
