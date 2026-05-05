# api comparison

Free-tier APIs considered for market data.

## comparison table

| provider      | free rate limit     | data range                  | key required    | notes                                          | verdict               |
|---------------|---------------------|-----------------------------|-----------------|------------------------------------------------|-----------------------|
| Finnhub       | 60 req/min          | live quotes + some historical | yes (email)   | stable REST/JSON since ~2017; free /candle is unreliable in practice | **picked — live**  |
| Stooq         | no explicit cap     | decades of EOD history      | yes (captcha)   | free CSV download; no email or card; key gate added 2024–2025 | **picked — historical** |
| Alpha Vantage | 25 req/day          | live + intraday + EOD       | yes (email)     | 25/day is unworkable for a running competition  | rejected              |
| Twelve Data   | 800 req/day (~8/min) | live + intraday + EOD      | yes (email)     | comfortable at low traffic; left as a swap-in  | rejected (marginal)   |
| Polygon.io    | 5 req/min           | live + historical (2-yr cap) | yes (email)    | 5/min is tight; free tier capped to last 2 years | rejected              |
| yfinance      | unofficial scrape   | live + historical           | no              | scrapes Yahoo's undocumented endpoints; exactly v2's failure mode | rejected on principle |

## finnhub

Live quote source. `GET /api/v1/quote?symbol={SYMBOL}&token={KEY}`.

60 req/min on the free tier is generous for a 5-person competition — even with no caching you'd need sustained 1 quote/sec to hit it. The cache (60s TTL during hours, infinite outside) means production traffic is a small fraction of that budget.

Response is JSON with `c` (current price), `t` (unix timestamp), and supporting fields. `c === 0` means unknown symbol. 429 responses carry a `retry-after` header; the adapter surfaces those as a typed `RateLimitError` rather than silently returning null.

The `/candle` endpoint (candlestick history) exists on the free tier in docs but is unreliable in practice — some accounts get it, others hit 403. That's why Finnhub is live-only in this codebase despite advertising historical data. Historical calls go to Stooq instead (`getHistoricalCloses` in `finnhub.ts` returns `[]` unconditionally).

Key: `FINNHUB_API_KEY`. Sign up at finnhub.io.

## stooq

Historical EOD source. `GET https://stooq.com/q/d/l/?s={symbol}.us&d1={YYYYMMDD}&d2={YYYYMMDD}&i=d&apikey={KEY}`.

Returns a CSV with columns `Date,Open,High,Low,Close,Volume`. The close is column index 4. Single-day window calls work — `getCloseAt` delegates to `getHistoricalCloses` with `from === to`.

Data goes back decades for US equities. EOD only, which is exactly what instant-replay competitions need — no intraday granularity required.

**API key required.** Stooq gated CSV downloads behind a free captcha-acquired key in 2024–2025. One-time setup at `https://stooq.com/q/d/?s=aapl.us&get_apikey` — solve the captcha, copy the key, set `STOOQ_API_KEY`. No email, no card. Without the key, requests return an HTML-ish prompt instead of CSV; `parseCsv` silently returns `[]` (no `Date,` header match), so missing the key produces silent empty results rather than an error. Don't skip this step.

Replaces v2's unofficial Yahoo CSV scrape, which broke when Yahoo changed its endpoint format.

## rejects

**Alpha Vantage.** 25 calls/day on the free tier is unworkable. A single leaderboard refresh for a 3-symbol comp could eat half the daily budget.

**Twelve Data.** 800 req/day (~8/min). Viable at low traffic, genuinely uncomfortable once competitions overlap. Left as a documented swap-in if Finnhub or Stooq becomes unavailable.

**Polygon.io.** 5 req/min and historical data capped to the last 2 years on the free tier. Rate limit is the blocker — 5/min is tight even with caching.

**yfinance.** Python library that scrapes Yahoo's undocumented `query2.finance.yahoo.com` endpoints. Exactly what broke v2 (Yahoo silently changed the endpoint; the library broke with no notice). Rejected on principle regardless of current availability.
