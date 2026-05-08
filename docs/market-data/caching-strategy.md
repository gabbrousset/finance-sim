# caching strategy

SQLite-backed. Two tables: `quote_cache_live` and `quote_cache_eod`. Schema in [data-model.md](../data-model.md#schema).

The `MarketData` interface (`src/lib/server/market/types.ts`) is the seam — `MarketDataService` composes the cache layer over the real adapters. See [architecture.md](../architecture.md#boundary-rules).

Code paths: `src/lib/server/market/cache.ts`, `service.ts`, `market-hours.ts`.

---

## live ttl

60s during NYSE hours. Outside hours: no expiry.

`getCachedLive` (cache.ts:8) checks `isMarketOpen(now)`. If the market is open, it invalidates the cached row when `now - row.fetchedAt > LIVE_TTL_OPEN_SEC` (cache.ts:22). `LIVE_TTL_OPEN_SEC = 60` (cache.ts:6).

If the market is closed — weekend, after-hours, or holiday — the expiry check is skipped entirely. The price is not moving; serving the last fetched value until the next open is correct behavior, not a staleness risk.

`setCachedLive` upserts on the symbol primary key (cache.ts:33-39), so there's only ever one live row per symbol.

## today is never eod-cached

`getCachedEod` (cache.ts:42) short-circuits to `null` when `date === toIsoDate(now)` (cache.ts:49). There's no "today's EOD" — the bar hasn't closed.

Above that, `MarketDataService.getCloseAt` (service.ts:34) redirects today's date to the live quote path before even reaching the EOD cache (service.ts:37-41). So a caller asking for today's close gets a live Finnhub quote, not an EOD lookup.

## past eod is cached forever

`(symbol, trade_date)` rows for any date strictly before today are immutable. `setCachedEod` upserts (cache.ts:63-76), but past closing prices don't change. There's no expiry logic for EOD rows — once written, they're never re-fetched.

## bulk-fill on getHistoricalCloses

`MarketDataService.getHistoricalCloses` (service.ts:51-62) is always a remote fetch followed by a cache fill. It does not read the cache first — it calls `this.historical.getHistoricalCloses` unconditionally, then bulk-writes all returned bars via `bulkSetEod` (cache.ts:78-94).

This is the path used when a historical competition resolves: the service fetches the full window from TwelveData once per symbol and populates the cache. After that, leaderboard valuation for that window is local-only. TwelveData's free tier (8/min, 800/day) is comfortable here — bulk fill is a one-time burst per symbol per competition, and past EOD is cached forever so it never re-fetches.

The read-through behavior (check cache, fetch on miss, write back) applies to single-date lookups via `getCloseAt` (service.ts:42-47), not the bulk path.

## in-flight coalescing (live quotes)

`FinnhubAdapter` (finnhub.ts:19) keeps a `Map<string, Promise<Quote | null>>` for in-flight requests. If three concurrent callers ask for AAPL while a request is already in flight, they all await the same Promise — one HTTP call, three resolved results.

The entry is cleaned up in `.finally()` (finnhub.ts:30), so the next call after resolution starts fresh.

## market hours calendar

`isMarketOpen` (market-hours.ts:49) returns true iff the unix timestamp falls within NYSE hours: 9:30–16:00 ET, Monday–Friday, excluding full-close holidays.

The holiday list is hardcoded at `nyse-holidays.json` (2024–2030, observed full-close dates only). Early-close days (July 3, day after Thanksgiving, etc.) are intentionally absent. The only consumer of `isMarketOpen` is the cache TTL layer. Over-caching by ~30 minutes on early-close days is harmless; a separate early-close calendar would need annual maintenance for no real benefit.

The calendar covers through 2030. Past that, `isMarketOpen` will return false for holidays that should be recognized — prices will still be served from cache if they were fetched before expiry, but stale data won't be evicted on those days. Extending the JSON file is a one-time update.

## trade-offs

The rules above are intentionally coarse:

- No per-symbol TTL variation (all equities treated the same).
- No per-day-of-week adjustment (the closed-hours logic is binary open/closed).
- No cache invalidation on price correction — if Finnhub returns a bad value, it stays for 60s during hours or until the next market open otherwise.

The cost: a brief network hiccup near the 60s boundary could cause a double-fetch (row evicted, re-fetch before the cached row is replaced). Finnhub's 60 req/min budget absorbs this without hitting the rate limit at friend-group scale.

The benefit: the logic is simple enough to read in one pass. `getCachedLive` is 17 lines; `getCachedEod` is 19 lines. No TTL tables, no per-symbol state, no background eviction thread.
