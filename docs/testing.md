# testing

## layers

**unit tests** — vitest, node environment. Each `lib/server/*/service.ts` module tested in isolation. DB is in-memory SQLite (`createDb(':memory:')`), market data is `MockMarketData`. No network, no filesystem, no process setup.

**integration tests** — same vitest runner, same node environment. Multi-module flows (e.g. `MarketDataService` coordinating `FinnhubAdapter` + `TwelveDataAdapter` + cache) use an in-memory DB. "Integration" in the sense that multiple modules run together, not that we hit external services.

**component tests** — vitest, jsdom environment, `@testing-library/svelte`. Components that have conditional rendering or non-trivial logic. File pattern: `*.svelte.test.ts`. Currently: `DataTable.svelte.test.ts`.

**e2e** — Playwright, Chromium. Critical user flows (signup, signin, trade). Uses a real built server (`pnpm build && node build`) pointed at a test DB and seeded `MockMarketData`. WebAuthn via CDP virtual authenticator.

## running tests

```bash
pnpm test:unit --run          # vitest only, one-shot
pnpm test:unit                # vitest, watch mode
pnpm test:e2e                 # playwright only
pnpm test                     # both (unit --run, then e2e)
```

To run a specific file or pattern:
```bash
pnpm test:unit --run src/lib/server/portfolio/service.test.ts
pnpm test:unit --run -t "buy"
```

165 tests pass as of the initial implementation (20 test files).

## vitest projects

`vite.config.ts` defines two projects:

| project | environment | picks up |
|---------|-------------|----------|
| `server` | `node` | `src/**/*.{test,spec}.{js,ts}` (excluding `.svelte.test.*`) |
| `client` | `jsdom` | `src/**/*.svelte.{test,spec}.{js,ts}` |

The split exists because server tests need real DB access and filesystem (SQLite WAL, migration runner), while component tests need a DOM. Mixing them in one environment causes problems — jsdom breaks `better-sqlite3`, and node has no `document`.

## what's mocked, what's real

**DB is real, in-memory.** Tests call `createDb(':memory:')` and `applyMigrations(db)`. Every test gets a fresh schema. No mocking of Drizzle or SQL. If a query is wrong, the test fails.

**`MockMarketData` is the seam for HTTP.** The `MarketData` interface (`getLiveQuote`, `getHistoricalCloses`, `getCloseAt`) is the boundary. Service-layer tests instantiate `MockMarketData` directly and call `setLive` / `setHistorical`:

```ts
mkt.setHistorical('AAPL', '2024-01-02', 19000);
// → "AAPL closed at $190.00 on 2024-01-02"
```

This expresses domain concepts, not HTTP details. No URL, no response status, no JSON structure to maintain.

**Adapter tests do mock fetch.** `finnhub.test.ts` and `twelvedata.test.ts` use `vi.spyOn(globalThis, 'fetch')` — that's intentional. Their job is parsing HTTP responses, so we feed them a canned response (fixture JSON) and verify the output cents. The fetch spy is confined to those two files.

## fixture strategy

Adapter parsing tests use recorded JSON samples:

```
src/lib/server/market/__fixtures__/finnhub-quote.json
src/lib/server/market/__fixtures__/twelvedata-aapl.json
```

These are a single real API response captured once. Tests assert on parsed values (e.g. `closeCents === 18564` for `$185.64`). If the upstream API changes its shape, the fixture and parser both need updating.

Service-layer tests don't use fixture files. They call `MockMarketData.setLive` / `setHistorical` inline. This keeps test setup local and readable.

## e2e: webauthn approach

Playwright's `BrowserContext.cdpSession()` exposes the Chromium DevTools Protocol `WebAuthn` domain. Tests call `WebAuthn.addVirtualAuthenticator` with `automaticPresenceSimulation: true` — this creates a software credential store inside the browser process. Biometric prompts auto-confirm without real hardware.

The server runs with `MARKET_DATA=mock` and `MARKET_SEED_PATH=./e2e/fixtures/market-seed.json`. At startup, `factory.ts` reads the seed file and calls `MockMarketData.setLive` / `setHistorical` for each entry. This makes dollar amounts in assertions stable across runs. Without the seed, market-dependent assertions would be non-deterministic.

No iCloud Keychain, no real Touch ID, no cross-device ceremony.

## what's not tested

- **pure-presentational pages** — `+page.svelte` files that just render data from the load function without conditional logic. Testing them would be asserting that Svelte renders HTML correctly, which isn't useful.
- `lib/server/auth/aaguid.ts` — one-line AAGUID-to-vendor-name lookup. No branching.
- UI components without conditional rendering (`Button.svelte`, `FormError.svelte`, etc.).

Coverage target is every code path with a decision, not line coverage for its own sake.

## tdd discipline

Every service module was written test-first. Tests were committed before or alongside implementation. The `lib/shared/` utilities (`money.ts`, `dates.ts`, `symbols.ts`) also have full unit coverage as they are depended on by the service layer.
