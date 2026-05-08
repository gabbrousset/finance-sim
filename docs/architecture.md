# architecture

## request flow

```
nginx (TLS, finance.gabbrousset.dev)
  └─> Node SvelteKit (adapter-node, 127.0.0.1:3002)
        ├─> better-sqlite3 → finance.db (WAL mode)
        ├─> Finnhub  /quote                (live, 60 req/min free)
        └─> TwelveData /time_series          (free 800/day, json)
```

One process. One deploy artifact. nginx terminates TLS and proxies to the Node process on loopback. SQLite file lives next to the build output. No message queue, no background workers — status transitions run on-request (see [competitions](./competitions/)).

## directory structure

```
src/
├── routes/
│   ├── (app)/                    # authed: layout enforces session
│   │   ├── +layout.server.ts
│   │   ├── portfolio/
│   │   ├── trade/                # unified buy/sell
│   │   ├── quote/
│   │   ├── history/
│   │   ├── competitions/
│   │   │   ├── +page.svelte      # list
│   │   │   ├── new/
│   │   │   ├── [id]/             # comp dashboard
│   │   │   └── join/[code]/
│   │   └── settings/
│   │       ├── +page.svelte
│   │       └── passkeys/
│   ├── (auth)/                   # public: signup, signin, recover
│   │   ├── signup/
│   │   ├── signin/
│   │   └── recover/
│   ├── api/                      # JSON endpoints (used by client-side fetchers)
│   │   ├── sparkline/[symbol]/
│   │   └── leaderboard/[id]/
│   ├── share/[id]/               # public read-only results (competitions.share_results)
│   ├── signout/                  # DELETE session → redirect
│   └── +page.svelte              # landing
├── lib/
│   ├── server/
│   │   ├── db/
│   │   │   ├── client.ts         # better-sqlite3 + Drizzle init
│   │   │   ├── schema.ts         # Drizzle table defs
│   │   │   └── migrations/       # generated SQL
│   │   ├── auth/
│   │   │   ├── webauthn.ts       # @simplewebauthn wrappers, RP config
│   │   │   ├── sessions.ts       # create/verify/revoke session cookies
│   │   │   ├── recovery.ts       # generate/verify/regenerate recovery codes
│   │   │   └── service.ts        # high-level: signupWithPasskey, signinWithPasskey, ...
│   │   ├── market/
│   │   │   ├── types.ts          # MarketData interface
│   │   │   ├── finnhub.ts        # live quote adapter
│   │   │   ├── twelvedata.ts     # historical EOD adapter
│   │   │   ├── cache.ts          # SQLite-backed cache, TTL logic
│   │   │   ├── market-hours.ts   # NYSE calendar
│   │   │   ├── mock.ts           # MockMarketData (test double)
│   │   │   ├── factory.ts        # production singleton accessor
│   │   │   └── service.ts        # composes finnhub + twelvedata + cache
│   │   ├── portfolio/
│   │   │   ├── service.ts        # buy, sell, valuate
│   │   │   └── equity-curve.ts   # ledger + closes → time series
│   │   └── competitions/
│   │       ├── service.ts        # create, join, trade, resolve
│   │       └── leaderboard.ts    # rank players in a comp
│   ├── components/               # Svelte components, no server imports
│   │   ├── nav/
│   │   ├── charts/               # uPlot wrappers
│   │   ├── forms/
│   │   ├── tables/
│   │   ├── Button.svelte
│   │   └── ThemeToggle.svelte
│   └── shared/                   # types/utilities used by both client and server
│       ├── money.ts              # cents <-> dollars formatting
│       ├── symbols.ts            # validation
│       └── dates.ts              # YYYY-MM-DD helpers
├── hooks.server.ts               # session resolution, RP ID config
└── app.d.ts                      # locals: user, session
```

## boundary rules

**Components never import from `lib/server/`.**  
SvelteKit's server-only convention enforced by the `$lib/server/` path prefix. Any accidental import surfaces as a build error.

**Routes are thin.**  
A route file validates input, calls a service function, returns data. No business logic in `+page.server.ts` or `+server.ts` files.

**Services are the unit-testable layer.**  
Each `lib/server/*/service.ts` takes a DB handle and a `MarketData` instance as parameters. Tests swap in an in-memory SQLite DB and `MockMarketData` — no network, no process setup.

**`MarketData` is the seam for external HTTP.**  
We never mock at the `fetch` level. The interface is the contract; `MockMarketData` is the test double. See [`market-data/`](./market-data/) for the caching strategy.

## why this shape

SvelteKit's file-system routing handles the web layer. Everything interesting lives in `lib/server/*/service.ts`. The `(app)` route group's `+layout.server.ts` centralises session enforcement — every authed page inherits it automatically. The `(auth)` group is public; the landing page is standalone.

SQLite + WAL mode handles concurrency well at friend-group scale. One file, zero infrastructure. See [tech-choices.md](./tech-choices.md) for the DB decision and [data-model.md](./data-model.md) for the schema.
