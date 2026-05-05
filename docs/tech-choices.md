# tech choices

## sveltekit 2 + svelte 5 runes

SvelteKit handles routing, SSR, form actions, and the server/client split in a single framework. The alternative was a separate API + React SPA, which doubles the surface area for a solo project. Svelte 5 runes are the current programming model — more explicit reactivity, no magic `$:` inference.

TypeScript strict throughout.

## drizzle orm + drizzle kit

Drizzle gives us typed queries and schema-as-code without hiding SQL. Migrations are plain SQL files (Drizzle Kit generates them) — readable, version-controlled, and easy to inspect when something goes wrong.

Prisma was the other candidate. Prisma's query engine is a separate Rust binary; on a 1 GB droplet that's real overhead. Drizzle runs in-process. SQLite support is also more mature in Drizzle.

## better-sqlite3

Synchronous API. That's the main point — no async ceremony for queries that are sub-millisecond. Works naturally in SvelteKit server code where you're already writing synchronous `load` functions. WAL mode handles concurrent reads fine.

`better-sqlite3` is consistently the fastest Node SQLite binding in benchmarks and has been stable for years.

## @simplewebauthn

The WebAuthn spec is dense. `@simplewebauthn/server` handles the ceremony correctly — challenge generation, credential verification, counter checks, backup-state flags. We own the storage layer (users, passkeys, sessions tables), device-naming UX, and recovery flow. We don't reimplement the cryptography.

See [`auth/`](./auth/) for flows and threat model. The primer (`auth/webauthn-primer.md`) covers the protocol in depth before any code was written.

## passkey-only auth (no passwords, no email)

No email means no SMTP infrastructure, no inbox scraping attack surface, and no phishing vector via "reset your password" links. Recovery codes are the single fallback — 8 one-shot codes, argon2id-hashed, displayed once at signup.

This forces users to take their credentials seriously. Synced passkeys (Keychain, Google Password Manager, Bitwarden) mean most users don't feel the friction. Cross-device auth is handled by the platform via WebAuthn's `hybrid` transport — we implement nothing extra for it.

## tailwind v4

CSS-first config (no `tailwind.config.js`). v4 is a rewrite with significantly faster builds and a cleaner mental model for custom properties. Lucide-svelte for icons — consistent, tree-shakeable.

Green/red are reserved exclusively for gain/loss signal. Never used for buttons or accents.

## uplot

~30 KB, no virtual DOM, extremely fast for time-series data. The alternative (Chart.js, Recharts, etc.) would add 10–20× the bundle size for capabilities we don't need. We need sparklines on table rows and equity curves — uPlot handles both. Wrapped in thin Svelte components in `lib/components/charts/`.

## sveltekit-superforms + zod

Superforms handles progressive enhancement for form actions: type-safe form data, server-side validation errors piped back to the form, no manual error-field plumbing. Zod schemas define the validation rules and double as the TypeScript types.

## pnpm

Faster installs, strict dependency isolation (phantom dependencies surface as errors rather than silent mismatch). Used across the other projects on the droplet.

## testing stack

- **vitest** — unit + integration tests. Fast, ESM-native, works with the SvelteKit project structure without extra config.
- **@testing-library/svelte** — component tests. Tests what the user sees, not implementation details.
- **playwright** — E2E, including WebAuthn via Chromium DevTools Protocol's `WebAuthn` domain (virtual authenticator). No real hardware needed for auth tests.

CI runs lint (`eslint` flat config + `prettier` + `tsc --noEmit`) before tests.

## money representation

Integer cents everywhere. `1000000` is `$10,000.00`. See [data-model.md](./data-model.md#money-is-integer-cents) for the full rationale. The display layer (`lib/shared/money.ts`) handles formatting; nothing else touches floats.
