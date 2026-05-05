# historical mode

A competition over a past date window. Players build a portfolio at the start-date close; resolution marks them at the end-date close. Instant replay, not stepped.

See [data-model.md](../data-model.md#schema) for the competition tables. See [architecture.md](../architecture.md) for the request flow.

---

## why instant-replay

Players commit a portfolio once, then resolution prices it at the end. No rebalancing within the window. Live comps already cover active trading over time — historical is for "what would you have picked?"

It demos well, needs no scheduler, and the mental model is simple: buy at start price, see the result at end price. The tradeoff is explicit: you can't rebalance within the simulated window.

## lifecycle

Two statuses: `open` → `finished`.

No `running`. `tickStatuses()` (`service.ts:412`) excludes historical competitions entirely — it only processes `(open AND live) OR running`. Historical transitions are manual: the host clicks "resolve now."

## what players can do

| status     | join | trade | leaderboard |
|------------|------|-------|-------------|
| `open`     | yes  | yes   | live snapshot |
| `finished` | no   | no    | locked        |

While `open`, the leaderboard prices holdings at the start-date close — it shows what everyone would be worth if the window ended right now at those prices, not all-zeros while trading is in progress.

## trade execution

Route: `src/routes/(app)/competitions/[id]/+page.server.ts` — `trade` action.

For historical comps the route doesn't fetch a price. `svc.tradeInComp()` (`service.ts:222`) handles it:

1. Verifies `status === 'open'`; rejects otherwise.
2. Calls `market.getCloseAt(symbol, toIsoDate(comp.startDate))`. Throws if Stooq returns null (non-trading day, symbol not found, etc.).
3. Any `priceCents` argument is ignored — start-date close is the only valid price.
4. Proceeds identically to live: SQLite transaction updates `competition_holdings`, `competition_cash`, appends to `competition_trades`.

The portfolio is priced as if you'd bought at the window's open. Letting users buy at today's price would defeat the purpose of picking a historical window.

## resolve

Host clicks "resolve now" on the dashboard. Calls the `resolve` action (`+page.server.ts:70`), which calls `svc.resolveHistorical(id)` (`service.ts:395`):

- Verifies `type === 'historical'` and `status !== 'finished'`.
- Flips `status` to `finished`, sets `finishedAt`.

The dashboard load immediately calls `computeLeaderboard()` after resolve returns. That's where the cache fill happens — the resolve itself only writes to `competitions`.

## leaderboard after resolve

`computeLeaderboard()` (`leaderboard.ts:64`) prices all holdings at `getCloseAt(symbol, toIsoDate(comp.endDate))` when status is `finished`.

`getCloseAt` checks `quote_cache_eod` first. On first compute after resolve, it's a cache miss: Stooq is fetched and the result written to `quote_cache_eod`. Every subsequent leaderboard view for that comp is local-only — `(symbol, trade_date)` rows for past dates are immutable and never re-fetched.

See [market-data/caching-strategy.md](../market-data/caching-strategy.md#past-eod-is-cached-forever) for the EOD cache invariant.

## public share page

Off by default. Host toggles `shareResults` from the dashboard via the `toggleShare` action — only available when `status === 'finished'`.

Public URL: `/share/[id]?code=<inviteCode>`.

The load function (`src/routes/share/[id]/+page.server.ts`) checks four conditions, in order:

1. `code` query param is present
2. `code` matches `comp.inviteCode`
3. `status === 'finished'`
4. `shareResults === 1`

Any miss returns 404 — identical response regardless of which condition failed, to avoid leaking whether the comp exists.

The page is read-only: leaderboard, final portfolio values, return percentages. No trade form. No member portfolio details beyond display name and rank.
