# finance-sim docs

Implementation notes and design rationale for v3.

## start here

- [`architecture.md`](./architecture.md) — high-level shape
- [`tech-choices.md`](./tech-choices.md) — stack and tradeoffs
- [`data-model.md`](./data-model.md) — schema + invariants

## subsystems

- [`auth/`](./auth/) — passkey-only auth
- [`market-data/`](./market-data/) — finnhub + stooq + caching
- [`competitions/`](./competitions/) — live + instant-replay

## ops

- [`testing.md`](./testing.md)
- [`deployment.md`](./deployment.md)

design spec: [`superpowers/specs/2026-05-05-finance-sim-v3-design.md`](./superpowers/specs/2026-05-05-finance-sim-v3-design.md).
