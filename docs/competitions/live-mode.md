# live mode

A timed competition where players trade with live quotes over a real calendar window.

See [data-model.md](../data-model.md#schema) for the competition tables. See [architecture.md](../architecture.md) for the request flow.

---

## lifecycle

Three statuses: `open` → `running` → `finished`.

Transitions are time-driven. `tickStatuses()` (`src/lib/server/competitions/service.ts:412`) queries every `open`+`live` and every `running` competition. For each:

- if `endDate <= now`: flip to `finished` (sets `finishedAt`)
- else if `status === 'open'` and `startDate <= now`: flip to `running`

The `endDate` check runs first, so a comp that missed the `running` window goes straight from `open` to `finished` in one tick. No re-entry.

Historical competitions are excluded — the query only matches `(open AND live) OR running`, and the loop bails on any non-live row.

## when tick runs

Three call sites:

1. `hooks.server.ts:11` — every incoming request, throttled to once per 30s.
2. `competitions/[id]/+page.server.ts:14` — every dashboard load, unthrottled. This gives low-latency transitions on the page users actually watch.
3. `api/leaderboard/[id]/+server.ts:13` — every leaderboard poll. A `running → finished` transition can happen mid-poll; the response will include the updated status and leaderboard.

## what players can do

| status     | join | trade | leaderboard |
|------------|------|-------|-------------|
| `open`     | yes  | no    | read-only   |
| `running`  | no   | yes   | live (polled) |
| `finished` | no   | no    | locked      |

Joining is via invite link (`/competitions/join/[code]`). The host is auto-joined and auto-funded at creation.

## trade execution

Route: `src/routes/(app)/competitions/[id]/+page.server.ts` — `trade` action.

1. Validates symbol and share count.
2. Calls `market.getLiveQuote(symbol)` server-side. The client never sends a price. If no quote is available, the trade is rejected.
3. Passes `priceCents` to `svc.tradeInComp()` (`service.ts:199`).
4. Service verifies `status === 'running'`; rejects otherwise.
5. Within a single SQLite transaction: checks cash balance, updates `competition_holdings` (upsert or delete at zero), debits/credits `competition_cash`, appends to `competition_trades`.

`competition_trades` is append-only. See [data-model.md](../data-model.md#append-only-ledgers).

## leaderboard

Computed by `computeLeaderboard()` (`src/lib/server/competitions/leaderboard.ts`).

For a `running` comp, prices holdings at `getLiveQuote(symbol)`. Formula per member:

```
totalCents = cashCents + sum(shares × livePrice)
returnPct  = (totalCents - startingCashCents) / startingCashCents
```

Sorted descending by `totalCents`. Rank is 1-based.

The dashboard SSR renders the initial leaderboard. While status is `running`, `+page.svelte` polls `/api/leaderboard/[id]` every 5s. Polled rows override server rows; the interval is cleared when the effect re-runs (status change or navigation). No websockets.

**Why polling instead of websockets:**

Competitions are small — 5-10 friends. Five-second polling is perceptually invisible. SvelteKit's `adapter-node` doesn't ship a WS layer; adding one specifically for this is infrastructure to maintain for no real benefit at this scale. YAGNI for v3.

## cache

Live trades go through `MarketDataService`, which caches live quotes for 60s during NYSE hours (no expiry outside hours). Leaderboard polls repeatedly hit the same symbols in quick succession; the cache absorbs nearly all of those reads.

See [market-data/caching-strategy.md](../market-data/caching-strategy.md) for TTL rules and in-flight coalescing.
