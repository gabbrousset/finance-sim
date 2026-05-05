# finance-sim

paper-trading + live and historical competitions, built with sveltekit + passkeys.

v3 is a full rewrite — see [docs/](./docs/) for design, architecture, and implementation notes. v2 (flask) is preserved at the `v2` git tag.

## status

work in progress on the `v3` branch.

## live

`https://finance.gabbrousset.dev`

## docs

- [`docs/architecture.md`](./docs/architecture.md) — high-level shape
- [`docs/tech-choices.md`](./docs/tech-choices.md) — why this stack
- [`docs/data-model.md`](./docs/data-model.md) — schema + invariants
- [`docs/auth/`](./docs/auth/) — passkeys end-to-end
- [`docs/market-data/`](./docs/market-data/) — finnhub + stooq + caching
- [`docs/competitions/`](./docs/competitions/) — live + instant-replay
- [`docs/testing.md`](./docs/testing.md), [`docs/deployment.md`](./docs/deployment.md)
