# finance-sim v3 — Design

**Status:** Approved 2026-05-05
**Predecessor:** v2 (Flask + cs50 stub + Yahoo CSV — to be tagged on `main` HEAD before any v3 work begins)

## 1. Goal

Rebuild finance-sim from scratch as a SvelteKit fullstack app: passkey auth, personal paper-trading portfolio, live and historical "instant replay" competitions, free-tier market data, polished UI, full test coverage. Public-facing portfolio piece with friend-group use as the primary use case.

## 2. Non-goals (v3.0)

- No watchlists, alerts, sector breakdowns, dividends, fractional shares, options, forex, crypto.
- No social features beyond invite-code competitions (no public profiles, no following, no comments).
- No "step-by-step" historical competitions (instant-replay only).
- No mobile app or PWA shell. (PWA is v3.1, immediate follow-up — v3.0 architecture must not block it.)
- No password fallback. Passkeys + recovery codes only.
- No email infrastructure.

## 3. Stack

- **Runtime:** Node 24 LTS (already on droplet).
- **Framework:** SvelteKit 2 + Svelte 5 runes, TypeScript strict.
- **Adapter:** `@sveltejs/adapter-node` — single Node process behind nginx, mirroring `budget-webapp`.
- **DB:** SQLite via `better-sqlite3`. Drizzle ORM + Drizzle Kit migrations.
- **Auth:** `@simplewebauthn/server` + `@simplewebauthn/browser`. Sessions are opaque cookies, hashed at rest.
- **UI:** Tailwind v4, `mode-watcher` for theme, `lucide-svelte` icons, `uPlot` for charts.
- **Forms:** `sveltekit-superforms` + `zod` for typed form actions and validation.
- **Tests:** `vitest` (unit + integration), `@testing-library/svelte` (components), `playwright` (E2E incl. WebAuthn virtual authenticator via CDP).
- **Lint/format:** `eslint` (flat config) + `prettier` + `tsc --noEmit` in CI.
- **Package manager:** pnpm.

## 4. Architecture

```
nginx (TLS, finance.gabbrousset.dev)
  └─> Node SvelteKit (adapter-node, 127.0.0.1:3002)
        ├─> better-sqlite3 → finance.db (WAL mode)
        ├─> Finnhub  /quote                (live, 60 req/min free)
        └─> TwelveData /time_series          (free 800/day, json)
```

One process, one deploy artifact. nginx terminates TLS and proxies. SQLite file lives next to the Node binary.

### 4.1 Module boundaries

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
│   │   ├── quote/[symbol]/
│   │   └── leaderboard/[id]/
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
│   │   │   └── service.ts        # composes finnhub + twelvedata + cache, exports default MarketData impl
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
│   │   └── tables/
│   └── shared/                   # types/utilities used by both client and server
│       ├── money.ts              # cents <-> dollars formatting
│       ├── symbols.ts            # validation
│       └── dates.ts              # YYYY-MM-DD helpers
├── hooks.server.ts               # session resolution, RP ID config
└── app.d.ts                      # locals: user, session
```

**Boundary rules:**
- Components never import from `lib/server/`.
- Routes are thin: validate input, call into a service, return data.
- Each `lib/server/*/service.ts` is a unit testable in isolation against an in-memory SQLite DB and a `MockMarketData`.
- The `MarketData` interface is the seam where external HTTP is mocked. We never mock at the `fetch` level.

## 5. Data model

SQLite. IDs are `cuid2`. Timestamps are UTC unix seconds (INTEGER). Money is INTEGER cents — never floats anywhere in the system.

```sql
-- users
users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  cash_cents INTEGER NOT NULL DEFAULT 1000000,   -- $10,000.00
  created_at INTEGER NOT NULL
)

-- passkey credentials (many per user)
passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT UNIQUE NOT NULL,           -- base64url
  public_key BLOB NOT NULL,                     -- CBOR
  counter INTEGER NOT NULL,
  transports TEXT NOT NULL,                     -- JSON: ["internal","hybrid",...]
  device_name TEXT NOT NULL,
  aaguid TEXT NOT NULL,
  backup_eligible INTEGER NOT NULL,             -- 0/1
  backup_state INTEGER NOT NULL,                -- 0/1
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL
)

-- recovery codes (8 per account, hashed, one-shot)
recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,                      -- argon2id
  used_at INTEGER,                              -- NULL = unused
  created_at INTEGER NOT NULL
)

-- sessions (opaque cookie)
sessions (
  id TEXT PRIMARY KEY,                          -- cookie value, hashed
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  user_agent TEXT NOT NULL
)

-- WebAuthn challenges (single-use, short-lived)
auth_challenges (
  id TEXT PRIMARY KEY,                          -- cookie value, hashed
  challenge TEXT NOT NULL,                      -- base64url
  purpose TEXT NOT NULL,                        -- 'register' | 'authenticate'
  user_id TEXT,                                 -- NULL for sign-in (resident credentials)
  expires_at INTEGER NOT NULL
)

-- personal portfolio (current holdings; rows deleted at 0 shares)
holdings (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  symbol TEXT NOT NULL,
  shares INTEGER NOT NULL CHECK (shares > 0),
  PRIMARY KEY (user_id, symbol)
)

-- personal trade ledger (append-only)
transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  symbol TEXT NOT NULL,
  shares INTEGER NOT NULL,                      -- negative = sell
  price_cents INTEGER NOT NULL,
  executed_at INTEGER NOT NULL
)

-- competitions
competitions (
  id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('live','historical')),
  status TEXT NOT NULL CHECK (status IN ('open','running','finished')),
  invite_code TEXT UNIQUE NOT NULL,
  starting_cash_cents INTEGER NOT NULL,
  start_date INTEGER NOT NULL,
  end_date INTEGER NOT NULL,
  share_results INTEGER NOT NULL DEFAULT 0,     -- 0/1: public read-only results page
  created_at INTEGER NOT NULL,
  finished_at INTEGER
)

competition_members (
  competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (competition_id, user_id)
)

competition_holdings (
  competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  symbol TEXT NOT NULL,
  shares INTEGER NOT NULL CHECK (shares > 0),
  PRIMARY KEY (competition_id, user_id, symbol)
)

competition_cash (
  competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cash_cents INTEGER NOT NULL,
  PRIMARY KEY (competition_id, user_id)
)

competition_trades (
  id TEXT PRIMARY KEY,
  competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  symbol TEXT NOT NULL,
  shares INTEGER NOT NULL,                      -- negative = sell
  price_cents INTEGER NOT NULL,
  executed_at INTEGER NOT NULL
)

-- caches
quote_cache_live (
  symbol TEXT PRIMARY KEY,
  price_cents INTEGER NOT NULL,
  fetched_at INTEGER NOT NULL
)

quote_cache_eod (
  symbol TEXT NOT NULL,
  trade_date TEXT NOT NULL,                     -- 'YYYY-MM-DD' NYSE date
  close_cents INTEGER NOT NULL,
  PRIMARY KEY (symbol, trade_date)
)
```

### 5.1 Invariants

1. **Money is integer cents end-to-end.** Display layer formats. No floats in arithmetic.
2. **Append-only ledgers.** `transactions` and `competition_trades` are immutable history. `holdings` and `competition_holdings` are derivable snapshots.
3. **Personal vs. competition state is fully separated.** Joining a comp does not touch personal cash/holdings.
4. **Holdings rows deleted at 0 shares.** Existence in `holdings` ⇒ `shares > 0` (enforced by CHECK).
5. **Single source of truth for sessions:** the `sessions` table. Cookies are opaque; the cookie value is hashed before lookup.

## 6. Authentication

### 6.1 Flow summary

- **Sign-up:** username → WebAuthn create credential → store passkey → generate 8 recovery codes → display once → require explicit "I saved them" confirm → log in.
- **Sign-in:** WebAuthn get assertion (resident credential, no username needed) → verify → create session → redirect.
- **Cross-device sign-in:** browser handles via WebAuthn `hybrid` transport; we don't implement anything — `@simplewebauthn` and the platform do it.
- **Multi-device add:** logged-in user goes to `/settings/passkeys` → "add passkey" → WebAuthn create credential → device name auto-filled from AAGUID lookup → editable → save.
- **Recovery:** `/recover` → enter recovery code → server invalidates code, creates session → forces user to register a new passkey before doing anything else.
- **Lose everything:** account is unrecoverable. Documented as a tradeoff in `docs/auth/threat-model.md`.

### 6.2 Why this is the v3 auth posture

- **No email.** Eliminates an entire class of data we'd otherwise have to protect, plus phishing/SMTP infrastructure complexity.
- **Recovery codes are the *only* fallback.** Forces the user to take their auth seriously; matches the "minimum viable identity" goal.
- **Synced passkeys** mean most users won't notice they don't have a password — Keychain / Google Password Manager / Bitwarden do the work.
- **CDA** handles the cross-ecosystem case at the platform level for free.
- **The implementation surface is well-scoped.** `@simplewebauthn/server` does the cryptography; we own the storage, the device-naming UX, and the recovery flow.

### 6.3 Research-first

Before any auth code is written, the implementation produces `docs/auth/webauthn-primer.md` from primary sources:
- W3C WebAuthn Level 3 spec
- `passkeys.dev` (joint Apple/Google/Microsoft)
- `@simplewebauthn` library docs and source
- FIDO Alliance certification docs

This doc covers: credential anatomy (public key + counter + transports), registration ceremony, authentication ceremony, RP ID rules, `backup_eligible` / `backup_state` semantics, AAGUID, synced vs. device-bound credentials, `hybrid` transport, attack surface.

## 7. Market data

### 7.1 Interface

```ts
export interface MarketData {
  getLiveQuote(symbol: string): Promise<Quote | null>
  getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]>
  getCloseAt(symbol: string, date: string): Promise<number | null>
}
```

### 7.2 Adapters

- **`FinnhubLiveAdapter`** — `https://finnhub.io/api/v1/quote?symbol={SYMBOL}&token={KEY}`. JSON. Free 60 req/min.
- **`TwelveDataAdapter`** — `https://api.twelvedata.com/time_series?symbol={SYMBOL}&interval=1day&start_date={YYYY-MM-DD}&end_date={YYYY-MM-DD}&apikey={KEY}`. JSON. Free 800 req/day, proper docs, real signup. Key supplied via `TWELVEDATA_API_KEY`. `status:'error'` body ⇒ unknown symbol or bad key. HTTP 429 or body `code:429` ⇒ `RateLimitError`.
- **`MockMarketData`** — deterministic in-memory prices for tests. Never touches network.
- **`CachedMarketData`** — wraps a real adapter, reads/writes `quote_cache_live` and `quote_cache_eod`, applies TTL logic.

### 7.3 Caching policy

- **Live:** TTL 60 seconds during NYSE hours (9:30–16:00 ET, weekdays, NYSE holiday calendar). Outside hours: TTL effectively infinite until next open.
- **EOD:** dates strictly before today are cached forever (immutable). Today's date is never EOD-cached — falls through to live quote path.
- **Bulk:** when a comp resolves, batch-fetch the full window for each symbol once and populate the cache.
- **In-flight coalescing:** per-symbol Promise map prevents thundering-herd on a leaderboard load.

### 7.4 Failure semantics

- "Symbol unknown / quote temporarily unavailable" ⇒ `null` (or empty array). Routes translate to user-facing apologies.
- "Successful HTTP but malformed body" ⇒ throw. Surfaces as a 500 we can investigate.
- 429 from Finnhub ⇒ typed `RateLimitError`. The route shows "rate-limited, try in a minute"; cache absorbs most of the load.

### 7.5 Why Finnhub + TwelveData

- Finnhub free: 60 req/min, REST/JSON, stable for years. Alpha Vantage's 25/day is unworkable; Polygon free is intraday-only with delays.
- TwelveData: free 800/day, JSON, proper docs, real signup. Replaces v2's broken Yahoo CSV scrape and our initial choice of Stooq (which turned out to be a captcha-gated CSV download, not a real API).

## 8. Competitions

### 8.1 Live competitions

- Host creates with `start_date` and `end_date` in the future, plus `starting_cash_cents`, name.
- Status: `open` → at `start_date` flips to `running` → at `end_date` flips to `finished`.
- During `open`: anyone with the invite code can join. No trades.
- During `running`: members trade using `MarketData.getLiveQuote`. Trades go into `competition_trades`; `competition_holdings` and `competition_cash` are kept in sync.
- During `finished`: leaderboard locks. Final values shown; share-link respected if enabled.

### 8.2 Historical (instant replay) competitions

- Host picks a past `start_date` and `end_date`, plus `starting_cash_cents`, name.
- Status: `open` → host clicks "resolve" → `finished`. (`running` is skipped.)
- During `open`: members join, build a portfolio. Each "trade" inserts into `competition_trades` with `executed_at = start_date` and `price_cents = close_at(start_date)`. Members can buy/sell freely until resolve.
- On resolve: server fetches `close_at(end_date)` for every held symbol, computes each member's `(sum holdings * end_close) + cash`. Leaderboard ranked by total. Status flips to `finished`.

### 8.3 Status transitions

Implemented as a single function `competitions.tickStatuses()` that runs on every authed request (cheap query). No background scheduler in v3.0.

### 8.4 Public results page

- Host can toggle `share_results` on a finished comp.
- When on, `/competitions/[id]?share=<invite_code>` is reachable without a session — read-only, no trade UI, no member personal data beyond display name + final value + return %.
- Off by default.

## 9. UI

### 9.1 Aesthetic

- Type: Inter (body), JetBrains Mono (numerics, tabular).
- Color: zinc/slate neutrals; green/red reserved exclusively for gain/loss signal — never for buttons or accents.
- Dark + light, system default, manual toggle in header.
- Density: comfortable, table-led where appropriate. No card-everywhere.
- Charts: uPlot only. ~30KB, fast, no virtual DOM. Sparklines per row, equity curves on portfolio + comp pages.

### 9.2 Navigation

- Desktop: left rail (Portfolio, Trade, Quote, History, Competitions, Settings).
- Mobile: bottom tab bar with the same destinations.
- Header: brand, theme toggle, sign-out.

### 9.3 Pages

| Route | Purpose |
|-------|---------|
| `/` | Landing (signed-out) or redirect to `/portfolio` (signed-in) |
| `/signup` | Passkey creation + recovery code flow |
| `/signin` | Passkey assertion + "use recovery code" link |
| `/recover` | Recovery code entry → forced new-passkey registration |
| `/portfolio` | Cash + holdings table + total + equity curve |
| `/trade` | Unified buy/sell form |
| `/quote` | Symbol → price card + 30-day sparkline |
| `/history` | Personal trade ledger |
| `/competitions` | List: hosting, joined, with status badges |
| `/competitions/new` | Create form |
| `/competitions/[id]` | Comp dashboard: leaderboard, my comp portfolio, trade button (live only or until-resolve historical) |
| `/competitions/join/[code]` | Join confirmation page |
| `/settings` | Display name, delete account |
| `/settings/passkeys` | Passkey list (device, last used), add/rename/revoke, regenerate recovery codes |

## 10. Testing

### 10.1 Layers

- **Unit:** `vitest`, in-memory SQLite, `MockMarketData`. Tests `lib/server/*/` services. Goal: 95%+ branch coverage of service modules.
- **Integration:** `vitest`, real Drizzle migrations applied to in-memory SQLite, `MockMarketData`. Tests cross-module flows: signup → trade → resolve a comp.
- **Component:** `@testing-library/svelte`. Tests components that have non-trivial logic (forms, charts).
- **E2E:** `playwright`. Critical paths: signup with virtual authenticator → trade → create comp → join → resolve. WebAuthn driven via Chromium DevTools Protocol's `WebAuthn` domain.

### 10.2 Fixtures and recording

- `MockMarketData` is the canonical test seam.
- For the production adapters, we keep a small set of recorded fixtures (one Finnhub quote JSON, one TwelveData time_series JSON) for parsing tests. No live API calls in CI.

### 10.3 What we don't test

- We don't unit-test `+page.svelte` files that are pure presentation. Component tests cover anything with logic.
- We don't test `@simplewebauthn` internals; we test our wrappers + DB persistence.

## 11. Deployment

- Same droplet as today. The existing `projects/finance-sim/` config in `droplet-config` is updated to match `budget-webapp`'s pattern: Node + pnpm + better-sqlite3.
- `setup.sh`: clone/pull, `pnpm install`, `pnpm -r rebuild` (native modules), `pnpm build`, apply migrations.
- `service.conf`: `ExecStart=/usr/bin/node build` from `~/finance-sim/build` (adapter-node output).
- `nginx.conf`: drop `uwsgi_pass`, use `proxy_pass http://127.0.0.1:3002`. Keep certbot config.
- `.env`: `DATABASE_URL`, `FINNHUB_API_KEY`, `TWELVEDATA_API_KEY`, `RP_ID`, `ORIGIN`. Documented in `.env.example`.
- Auto-deploy: existing GitHub Actions workflow stays, allowlist already includes `finance-sim`.
- Concurrency note: 1 GB RAM + 2 GB swap. SvelteKit/vite build is OK; we monitor.

## 12. Documentation deliverable

The `docs/` folder is part of v3.0's definition of done. Empty docs ⇒ v3 not shipped.

```
docs/
├── README.md                        # index
├── architecture.md                  # high-level shape, request flow, boundaries
├── tech-choices.md                  # stack decisions and tradeoffs
├── data-model.md                    # schema + invariants, why integer cents
├── auth/
│   ├── overview.md
│   ├── webauthn-primer.md           # research output, written first
│   ├── passkey-flows.md
│   ├── threat-model.md
│   └── implementation-notes.md
├── market-data/
│   ├── api-comparison.md
│   └── caching-strategy.md
├── competitions/
│   ├── live-mode.md
│   └── historical-mode.md
├── testing.md
└── deployment.md
```

Docs are written *during* their corresponding implementation phase, not at the end. Each implementation task that warrants documentation lists the doc as part of its deliverable.

## 13. Versioning + release

- Tag current `main` HEAD as `v2` *before* any v3 work.
- Create `v3` branch from `main`. All v3 work happens here.
- v3.0 ships when: every page works manually + all tests pass + droplet deploy verified + `docs/` complete.
- Merge `v3` → `main` and tag `v3.0`.
- v3.1 (PWA shell) immediately follows on a new branch.

## 14. Out-of-scope risks (acknowledged)

- **TwelveData rate-limit (8/min, 800/day).** Cache absorbs steady state — past EOD is cached forever, so steady-state is near zero requests. Bulk leaderboard resolutions (one symbol batch per comp) stay well under the daily budget.
- **Finnhub policy change.** Mitigation: adapter is one file; swappable. Threshold for switching: any pricing-page change.
- **1 GB droplet OOM during build.** Mitigation: 2 GB swap exists; CI builds elsewhere if it becomes a problem.
- **Passkey ecosystem shift.** Mitigation: the primer doc is dated; we re-read W3C spec + passkeys.dev before any future auth change.
