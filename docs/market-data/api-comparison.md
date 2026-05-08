# api comparison

Free-tier APIs considered for market data.

## comparison table

| provider      | free rate limit     | data range                  | key required    | notes                                          | verdict               |
|---------------|---------------------|-----------------------------|-----------------|------------------------------------------------|-----------------------|
| Finnhub       | 60 req/min          | live quotes + some historical | yes (email)   | stable REST/JSON since ~2017; free /candle is unreliable in practice | **picked — live**  |
| Twelve Data   | 800 req/day (~8/min) | live + intraday + EOD      | yes (email)     | proper JSON API, real docs, stable contract    | **picked — historical** |
| Alpha Vantage | 25 req/day          | live + intraday + EOD       | yes (email)     | 25/day is unworkable for a running competition  | rejected              |
| Stooq         | no explicit cap     | decades of EOD history      | captcha only    | CSV download gated by captcha, no real API, no docs | rejected — not a real API |
| Polygon.io    | 5 req/min           | live + historical (2-yr cap) | yes (email)    | 5/min is tight; free tier capped to last 2 years | rejected              |
| yfinance      | unofficial scrape   | live + historical           | no              | scrapes Yahoo's undocumented endpoints; exactly v2's failure mode | rejected on principle |

## finnhub

Live quote source. `GET /api/v1/quote?symbol={SYMBOL}&token={KEY}`.

60 req/min on the free tier is generous for a 5-person competition — even with no caching you'd need sustained 1 quote/sec to hit it. The cache (60s TTL during hours, infinite outside) means production traffic is a small fraction of that budget.

Response is JSON with `c` (current price), `t` (unix timestamp), and supporting fields. `c === 0` means unknown symbol. 429 responses carry a `retry-after` header; the adapter surfaces those as a typed `RateLimitError` rather than silently returning null.

The `/candle` endpoint (candlestick history) exists on the free tier in docs but is unreliable in practice — some accounts get it, others hit 403. That's why Finnhub is live-only in this codebase despite advertising historical data. Historical calls go to TwelveData instead (`getHistoricalCloses` in `finnhub.ts` returns `[]` unconditionally).

Key: `FINNHUB_API_KEY`. Sign up at finnhub.io.

## twelvedata

Historical EOD source. `GET https://api.twelvedata.com/time_series?symbol={SYMBOL}&interval=1day&start_date={YYYY-MM-DD}&end_date={YYYY-MM-DD}&apikey={KEY}`.

Returns JSON with a `values` array of objects containing `datetime` and `close` (string, e.g. `"185.64000"`). The array is sorted descending by date; the adapter re-sorts ascending. Single-day window calls work — `getCloseAt` delegates to `getHistoricalCloses` with `from === to`.

Data goes back years for US equities. EOD only, which is exactly what instant-replay competitions need — no intraday granularity required.

**API key required.** Sign up at twelvedata.com (email, no card). Free tier: 800 req/day, ~8/min. Set `TWELVEDATA_API_KEY`. The adapter returns `[]` if the key is missing rather than erroring, so keyless local dev works (price lookups silently fail). Use `MARKET_DATA=mock` in `.env.local` for real keyless dev.

Decision sequence: originally chose Stooq for no-key access, then discovered the captcha gate — it's not a real API (no docs, no signup, no contract). Switched to TwelveData. Replaces v2's unofficial Yahoo CSV scrape, which broke when Yahoo changed its endpoint format.

## rejects

**Alpha Vantage.** 25 calls/day on the free tier is unworkable. A single leaderboard refresh for a 3-symbol comp could eat half the daily budget.

**Stooq.** Initially chosen for no-key access. Turned out to have a captcha-gated CSV download — not a real API. No docs, no signup flow, no rate-limit contract. Dropped in favor of TwelveData.

**Polygon.io.** 5 req/min and historical data capped to the last 2 years on the free tier. Rate limit is the blocker — 5/min is tight even with caching.

**yfinance.** Python library that scrapes Yahoo's undocumented `query2.finance.yahoo.com` endpoints. Exactly what broke v2 (Yahoo silently changed the endpoint; the library broke with no notice). Rejected on principle regardless of current availability.
