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
    _instance = new MockMarketData();
  } else {
    const live = new FinnhubAdapter(env.FINNHUB_API_KEY ?? '');
    const historical = new TwelveDataAdapter(env.TWELVEDATA_API_KEY ?? '');
    _instance = new MarketDataService(getDb(), live, historical);
  }
  return _instance;
}
