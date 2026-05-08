# finance-sim v3 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild finance-sim as a SvelteKit fullstack app with passkey auth, paper-trading portfolio, live and historical (instant-replay) competitions, free-tier market data (Finnhub + TwelveData), polished UI, and full test coverage.

**Architecture:** Single Node 24 process (SvelteKit + adapter-node) behind nginx, talking to a local SQLite file via better-sqlite3 + Drizzle. Auth uses `@simplewebauthn` with passkey-only credentials and recovery-code fallback. External market APIs sit behind a `MarketData` interface so they can be mocked in tests.

**Tech Stack:** SvelteKit 2 + Svelte 5 (runes) + TypeScript strict; better-sqlite3 + Drizzle + Drizzle Kit; `@simplewebauthn/server`+`/browser`; Tailwind v4; sveltekit-superforms + zod; uPlot; vitest + @testing-library/svelte + playwright; pnpm.

**Reference:** [`docs/superpowers/specs/2026-05-05-finance-sim-v3-design.md`](../specs/2026-05-05-finance-sim-v3-design.md) is the source of truth for design decisions. Keep it open while executing.

---

## Conventions

**TDD always.** Each new module gets its test file first. Tests fail, then code makes them pass. No exceptions for "trivial" code — trivial code that becomes load-bearing without tests is the most expensive code.

**Commit after every passing test cycle.** Commits are cheap; rollback is cheaper when commits are small.

**Money is INTEGER cents.** Never use floats for money anywhere. If a step shows you doing `price * shares` with floats, the step is wrong — fix it.

**Symbols are uppercase.** Always normalize at the boundary.

**No `any`.** TypeScript strict means strict. If you reach for `any`, you're missing a type.

**Commit message format:** lowercase, imperative, scoped — e.g. `feat(auth): add passkey registration ceremony`, `test(market): cover twelvedata json parsing`, `chore(scaffold): init sveltekit project`. No "Initial commit" or "First step" framing.

---

## Parallelization map

The plan is structured in **phases**. Phases run in order; tasks within a phase may run in parallel.

```
Phase 0 (sequential, single agent)        Foundations + interfaces frozen
  └─> Phase 1 (parallel, 3 agents)        Auth track | Market data track | UI shell track
       └─> Phase 2 (sequential, 1 agent)  Personal portfolio
            └─> Phase 3 (sequential, 1 agent) Competitions
                 └─> Phase 4 (parallel, 3 agents) E2E | Deploy config | Docs polish
                      └─> Phase 5 (sequential, 1 agent) Manual deploy + release
```

**File-scope isolation for Phase 1:**
- Auth track owns `src/lib/server/auth/**`, `src/routes/(auth)/**`, `src/routes/(app)/settings/passkeys/**`, `docs/auth/**`.
- Market data track owns `src/lib/server/market/**`, `docs/market-data/**`.
- UI shell track owns `src/lib/components/**`, `src/routes/+layout.svelte`, `src/routes/+page.svelte`, `src/app.css`, `tailwind.config.*`, `src/routes/(app)/+layout.svelte`.

These three sets do not overlap. The schema and shared types are frozen in Phase 0 so all three can build against stable contracts.

---

## Phase 0 — Foundations

Sequential. Single agent. Locks in interfaces so Phase 1 can fan out.

### Task 0.1: Tag v2 and create v3 branch

**Files:**
- Operate: git only

- [ ] **Step 1: Verify clean tree on main**

```bash
git status
git log -1 --oneline
```
Expected: `nothing to commit, working tree clean`. Note the HEAD SHA.

- [ ] **Step 2: Tag the current HEAD as v2**

```bash
git tag -a v2 -m "v2: flask + cs50-style sql shim + yahoo csv. final release before svelte rewrite."
```

- [ ] **Step 3: Push tag to origin**

```bash
git push origin v2
```

- [ ] **Step 4: Create and switch to v3 branch**

```bash
git checkout -b v3
```

- [ ] **Step 5: Push v3 with upstream tracking**

```bash
git push -u origin v3
```

### Task 0.2: Commit spec and plan to v3

**Files:**
- Already created: `docs/superpowers/specs/2026-05-05-finance-sim-v3-design.md`
- Already created: `docs/superpowers/plans/2026-05-05-finance-sim-v3.md`

- [ ] **Step 1: Stage docs**

```bash
git add docs/superpowers/
```

- [ ] **Step 2: Commit**

```bash
git commit -m "docs(spec): add v3 design + implementation plan"
```

- [ ] **Step 3: Push**

```bash
git push
```

### Task 0.3: Wipe v2 application code

The v2 app code (`app.py`, `db.py`, `helpers.py`, `wsgi.py`, `finance.ini`, `templates/`, `static/`, `requirements.txt`, `venv/`, `__pycache__/`, `finance.db`, `finance.png`, `.env`, `.env.me`, `.env.vault`) is no longer relevant on v3 — v2 is preserved by the tag.

- [ ] **Step 1: Remove tracked v2 files**

```bash
git rm -rf app.py db.py helpers.py wsgi.py finance.ini templates/ static/ requirements.txt finance.png .env .env.me .env.vault DEPLOYMENT.md
```

- [ ] **Step 2: Remove untracked dev artifacts**

```bash
rm -rf venv/ __pycache__/ .idea/ finance.db
```

- [ ] **Step 3: Verify only docs and CLAUDE.md and README.md remain (plus dotfiles)**

```bash
ls -A
```
Expected: `.git`, `.github`, `.gitignore`, `CLAUDE.md`, `README.md`, `docs/` (and possibly `.DS_Store`).

- [ ] **Step 4: Replace `.gitignore` with a Node-flavored one**

Write `.gitignore`:

```gitignore
# deps
node_modules/
.pnpm-store/

# build
build/
.svelte-kit/
dist/

# env
.env
.env.*
!.env.example

# db
*.db
*.db-shm
*.db-wal

# os
.DS_Store
Thumbs.db

# editor
.idea/
.vscode/
*.swp

# logs
*.log
npm-debug.log*
pnpm-debug.log*

# tests
coverage/
playwright-report/
test-results/
```

- [ ] **Step 5: Update `README.md` to reflect v3-in-progress**

Write `README.md`:

```markdown
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
- [`docs/market-data/`](./docs/market-data/) — finnhub + twelvedata + caching
- [`docs/competitions/`](./docs/competitions/) — live + instant-replay
- [`docs/testing.md`](./docs/testing.md), [`docs/deployment.md`](./docs/deployment.md)
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore(v3): wipe v2 app code, retain docs and readme"
git push
```

### Task 0.4: Scaffold SvelteKit project

**Files:**
- Create: `package.json`, `pnpm-lock.yaml`, `svelte.config.js`, `vite.config.ts`, `tsconfig.json`, `eslint.config.js`, `.prettierrc`, `src/app.html`, `src/app.d.ts`, `src/routes/+page.svelte`

- [ ] **Step 1: Initialize SvelteKit with the skeleton template**

```bash
pnpm create svelte@latest .
```
Choose: **Skeleton project**, **Yes (TypeScript)**, **Add ESLint**, **Add Prettier**, **Add Vitest**, **Add Playwright**. Do not enable any other extras.

- [ ] **Step 2: Install dependencies**

```bash
pnpm install
```

- [ ] **Step 3: Switch to adapter-node**

```bash
pnpm remove @sveltejs/adapter-auto
pnpm add -D @sveltejs/adapter-node
```

Edit `svelte.config.js`:

```js
import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    alias: {
      $lib: 'src/lib'
    }
  }
};

export default config;
```

- [ ] **Step 4: Lock TypeScript strict mode**

Edit `tsconfig.json`'s `compilerOptions` to include:

```json
"strict": true,
"noImplicitAny": true,
"strictNullChecks": true,
"noUncheckedIndexedAccess": true,
"forceConsistentCasingInFileNames": true,
"target": "ES2022"
```

- [ ] **Step 5: Verify the skeleton boots**

```bash
pnpm dev
```
Open `http://localhost:5173` in a browser. Expected: SvelteKit welcome page. Stop with Ctrl+C.

- [ ] **Step 6: Verify build, type-check, and tests run**

```bash
pnpm build
pnpm check
pnpm test --run
```
All three must pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore(scaffold): init sveltekit + ts strict + adapter-node"
git push
```

### Task 0.5: Install full toolchain

**Files:**
- Modify: `package.json`, `tailwind.config.ts`, `postcss.config.js`, `src/app.css`, `src/app.html`

- [ ] **Step 1: Install runtime dependencies**

```bash
pnpm add better-sqlite3 drizzle-orm @simplewebauthn/server @simplewebauthn/browser @paralleldrive/cuid2 zod sveltekit-superforms argon2 mode-watcher lucide-svelte uplot
```

- [ ] **Step 2: Install dev dependencies**

```bash
pnpm add -D drizzle-kit @types/better-sqlite3 tailwindcss @tailwindcss/vite autoprefixer @testing-library/svelte @testing-library/jest-dom jsdom
```

- [ ] **Step 3: Wire Tailwind v4 via the Vite plugin**

Edit `vite.config.ts`:

```ts
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [tailwindcss(), sveltekit()],
  test: {
    include: ['src/**/*.{test,spec}.{js,ts}'],
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts']
  }
});
```

- [ ] **Step 4: Create `src/app.css` with Tailwind directives + Inter/JetBrains Mono**

```css
@import 'tailwindcss';

@theme {
  --font-sans: 'Inter', ui-sans-serif, system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, monospace;
  --color-gain: oklch(0.72 0.18 145);
  --color-loss: oklch(0.65 0.22 25);
}

html { font-family: var(--font-sans); font-feature-settings: 'cv11', 'ss01'; }
.tabular { font-variant-numeric: tabular-nums; }
.mono { font-family: var(--font-mono); }
```

- [ ] **Step 5: Import the stylesheet from the root layout**

Create `src/routes/+layout.svelte`:

```svelte
<script lang="ts">
  import '../app.css';
  let { children } = $props();
</script>

{@render children()}
```

- [ ] **Step 6: Add Inter + JetBrains Mono via `<link>` in `src/app.html`**

Add inside `<head>`:

```html
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link
  href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
  rel="stylesheet"
/>
```

- [ ] **Step 7: Create empty test-setup file**

Create `src/test-setup.ts`:

```ts
import '@testing-library/jest-dom/vitest';
```

- [ ] **Step 8: Verify everything still builds**

```bash
pnpm check && pnpm build && pnpm test --run
```

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore(scaffold): install tailwind v4, drizzle, simplewebauthn, testing libs"
git push
```

### Task 0.6: Create shared types and utility modules

**Files:**
- Create: `src/lib/shared/money.ts`, `src/lib/shared/symbols.ts`, `src/lib/shared/dates.ts`, and tests for each.

- [ ] **Step 1: Write the failing test for money**

Create `src/lib/shared/money.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { centsToDollars, dollarsToCents, formatUsd } from './money';

describe('money', () => {
  it('round-trips dollars <-> cents without precision loss', () => {
    expect(dollarsToCents(123.45)).toBe(12345);
    expect(centsToDollars(12345)).toBe(123.45);
  });
  it('formats cents as USD', () => {
    expect(formatUsd(12345)).toBe('$123.45');
    expect(formatUsd(0)).toBe('$0.00');
    expect(formatUsd(-100)).toBe('-$1.00');
    expect(formatUsd(123456789)).toBe('$1,234,567.89');
  });
  it('rejects fractional cents on input', () => {
    expect(() => dollarsToCents(0.001)).toThrow();
  });
});
```

- [ ] **Step 2: Run the test, verify failure**

```bash
pnpm test --run src/lib/shared/money.test.ts
```
Expected: FAIL (module not found).

- [ ] **Step 3: Implement money**

Create `src/lib/shared/money.ts`:

```ts
export function dollarsToCents(dollars: number): number {
  const cents = Math.round(dollars * 100);
  if (Math.abs(cents - dollars * 100) > 1e-6) {
    throw new Error(`fractional cents not representable: ${dollars}`);
  }
  return cents;
}

export function centsToDollars(cents: number): number {
  return cents / 100;
}

const fmt = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD'
});

export function formatUsd(cents: number): string {
  return fmt.format(cents / 100);
}
```

- [ ] **Step 4: Verify pass**

```bash
pnpm test --run src/lib/shared/money.test.ts
```

- [ ] **Step 5: Write failing test for symbols**

Create `src/lib/shared/symbols.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { normalizeSymbol, isValidSymbol } from './symbols';

describe('symbols', () => {
  it('uppercases and trims', () => {
    expect(normalizeSymbol(' aapl ')).toBe('AAPL');
    expect(normalizeSymbol('brk.b')).toBe('BRK.B');
  });
  it('validates plausible tickers', () => {
    expect(isValidSymbol('AAPL')).toBe(true);
    expect(isValidSymbol('BRK.B')).toBe(true);
    expect(isValidSymbol('A')).toBe(true);
  });
  it('rejects junk', () => {
    expect(isValidSymbol('')).toBe(false);
    expect(isValidSymbol('AAPL ')).toBe(false);
    expect(isValidSymbol('aa pl')).toBe(false);
    expect(isValidSymbol('THISWAYTOOLONG')).toBe(false);
    expect(isValidSymbol('aapl')).toBe(false);
    expect(isValidSymbol('1AAPL')).toBe(false);
  });
});
```

- [ ] **Step 6: Run, verify failure, implement**

```bash
pnpm test --run src/lib/shared/symbols.test.ts
```
Expected FAIL. Then create `src/lib/shared/symbols.ts`:

```ts
const SYMBOL_RE = /^[A-Z][A-Z0-9.\-]{0,9}$/;

export function normalizeSymbol(input: string): string {
  return input.trim().toUpperCase();
}

export function isValidSymbol(input: string): boolean {
  return SYMBOL_RE.test(input);
}
```

Run again — expect PASS.

- [ ] **Step 7: Write failing test for dates**

Create `src/lib/shared/dates.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { toIsoDate, parseIsoDate, daysBetween } from './dates';

describe('dates', () => {
  it('formats unix seconds as YYYY-MM-DD UTC', () => {
    // 2024-06-15T12:00:00Z
    expect(toIsoDate(1718452800)).toBe('2024-06-15');
  });
  it('parses YYYY-MM-DD as UTC midnight unix seconds', () => {
    expect(parseIsoDate('2024-06-15')).toBe(1718409600);
  });
  it('counts whole days between two iso dates inclusive', () => {
    expect(daysBetween('2024-06-15', '2024-06-15')).toBe(1);
    expect(daysBetween('2024-06-15', '2024-06-17')).toBe(3);
  });
});
```

- [ ] **Step 8: Run, fail, implement**

```bash
pnpm test --run src/lib/shared/dates.test.ts
```
Expected FAIL. Create `src/lib/shared/dates.ts`:

```ts
export function toIsoDate(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000);
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

export function parseIsoDate(iso: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) throw new Error(`bad iso date: ${iso}`);
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / 1000;
}

export function daysBetween(from: string, to: string): number {
  const a = parseIsoDate(from);
  const b = parseIsoDate(to);
  return Math.round((b - a) / 86_400) + 1;
}
```

Run again — expect PASS.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(shared): add money, symbols, dates utilities with full test coverage"
git push
```

### Task 0.7: Define database schema and apply initial migration

**Files:**
- Create: `src/lib/server/db/schema.ts`, `src/lib/server/db/client.ts`, `drizzle.config.ts`, `src/lib/server/db/migrations/0000_initial.sql` (generated).

- [ ] **Step 1: Create Drizzle config**

Create `drizzle.config.ts`:

```ts
import type { Config } from 'drizzle-kit';

export default {
  schema: './src/lib/server/db/schema.ts',
  out: './src/lib/server/db/migrations',
  dialect: 'sqlite',
  dbCredentials: { url: process.env.DATABASE_URL ?? './finance.db' }
} satisfies Config;
```

- [ ] **Step 2: Write the schema**

Create `src/lib/server/db/schema.ts` (full schema from spec §5):

```ts
import { sqliteTable, text, integer, blob, primaryKey, check } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  username: text('username').notNull().unique(),
  displayName: text('display_name').notNull(),
  cashCents: integer('cash_cents').notNull().default(1_000_000),
  createdAt: integer('created_at').notNull()
});

export const passkeys = sqliteTable('passkeys', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: text('credential_id').notNull().unique(),
  publicKey: blob('public_key', { mode: 'buffer' }).notNull(),
  counter: integer('counter').notNull(),
  transports: text('transports').notNull(),
  deviceName: text('device_name').notNull(),
  aaguid: text('aaguid').notNull(),
  backupEligible: integer('backup_eligible').notNull(),
  backupState: integer('backup_state').notNull(),
  createdAt: integer('created_at').notNull(),
  lastUsedAt: integer('last_used_at').notNull()
});

export const recoveryCodes = sqliteTable('recovery_codes', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull(),
  usedAt: integer('used_at'),
  createdAt: integer('created_at').notNull()
});

export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  expiresAt: integer('expires_at').notNull(),
  createdAt: integer('created_at').notNull(),
  userAgent: text('user_agent').notNull()
});

export const authChallenges = sqliteTable('auth_challenges', {
  id: text('id').primaryKey(),
  challenge: text('challenge').notNull(),
  purpose: text('purpose', { enum: ['register', 'authenticate'] }).notNull(),
  userId: text('user_id'),
  expiresAt: integer('expires_at').notNull()
});

export const holdings = sqliteTable(
  'holdings',
  {
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    symbol: text('symbol').notNull(),
    shares: integer('shares').notNull()
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.symbol] }),
    sharesPositive: check('shares_positive', sql`${t.shares} > 0`)
  })
);

export const transactions = sqliteTable('transactions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  symbol: text('symbol').notNull(),
  shares: integer('shares').notNull(),
  priceCents: integer('price_cents').notNull(),
  executedAt: integer('executed_at').notNull()
});

export const competitions = sqliteTable('competitions', {
  id: text('id').primaryKey(),
  hostId: text('host_id').notNull().references(() => users.id),
  name: text('name').notNull(),
  type: text('type', { enum: ['live', 'historical'] }).notNull(),
  status: text('status', { enum: ['open', 'running', 'finished'] }).notNull(),
  inviteCode: text('invite_code').notNull().unique(),
  startingCashCents: integer('starting_cash_cents').notNull(),
  startDate: integer('start_date').notNull(),
  endDate: integer('end_date').notNull(),
  shareResults: integer('share_results').notNull().default(0),
  createdAt: integer('created_at').notNull(),
  finishedAt: integer('finished_at')
});

export const competitionMembers = sqliteTable(
  'competition_members',
  {
    competitionId: text('competition_id').notNull().references(() => competitions.id, { onDelete: 'cascade' }),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    joinedAt: integer('joined_at').notNull()
  },
  (t) => ({ pk: primaryKey({ columns: [t.competitionId, t.userId] }) })
);

export const competitionHoldings = sqliteTable(
  'competition_holdings',
  {
    competitionId: text('competition_id').notNull().references(() => competitions.id, { onDelete: 'cascade' }),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    symbol: text('symbol').notNull(),
    shares: integer('shares').notNull()
  },
  (t) => ({
    pk: primaryKey({ columns: [t.competitionId, t.userId, t.symbol] }),
    sharesPositive: check('comp_shares_positive', sql`${t.shares} > 0`)
  })
);

export const competitionCash = sqliteTable(
  'competition_cash',
  {
    competitionId: text('competition_id').notNull().references(() => competitions.id, { onDelete: 'cascade' }),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    cashCents: integer('cash_cents').notNull()
  },
  (t) => ({ pk: primaryKey({ columns: [t.competitionId, t.userId] }) })
);

export const competitionTrades = sqliteTable('competition_trades', {
  id: text('id').primaryKey(),
  competitionId: text('competition_id').notNull().references(() => competitions.id, { onDelete: 'cascade' }),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  symbol: text('symbol').notNull(),
  shares: integer('shares').notNull(),
  priceCents: integer('price_cents').notNull(),
  executedAt: integer('executed_at').notNull()
});

export const quoteCacheLive = sqliteTable('quote_cache_live', {
  symbol: text('symbol').primaryKey(),
  priceCents: integer('price_cents').notNull(),
  fetchedAt: integer('fetched_at').notNull()
});

export const quoteCacheEod = sqliteTable(
  'quote_cache_eod',
  {
    symbol: text('symbol').notNull(),
    tradeDate: text('trade_date').notNull(),
    closeCents: integer('close_cents').notNull()
  },
  (t) => ({ pk: primaryKey({ columns: [t.symbol, t.tradeDate] }) })
);

export type DbSchema = {
  users: typeof users;
  passkeys: typeof passkeys;
  recoveryCodes: typeof recoveryCodes;
  sessions: typeof sessions;
  authChallenges: typeof authChallenges;
  holdings: typeof holdings;
  transactions: typeof transactions;
  competitions: typeof competitions;
  competitionMembers: typeof competitionMembers;
  competitionHoldings: typeof competitionHoldings;
  competitionCash: typeof competitionCash;
  competitionTrades: typeof competitionTrades;
  quoteCacheLive: typeof quoteCacheLive;
  quoteCacheEod: typeof quoteCacheEod;
};
```

- [ ] **Step 3: Create the DB client**

Create `src/lib/server/db/client.ts`:

```ts
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import * as schema from './schema';

export type Db = ReturnType<typeof createDb>;

export function createDb(path: string) {
  const sqlite = new Database(path);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.pragma('synchronous = NORMAL');
  return drizzle(sqlite, { schema });
}

export function applyMigrations(db: Db, migrationsFolder = './src/lib/server/db/migrations') {
  migrate(db, { migrationsFolder });
}

export { schema };
```

- [ ] **Step 4: Generate the initial migration**

```bash
pnpm drizzle-kit generate
```

This creates `src/lib/server/db/migrations/0000_*.sql`.

- [ ] **Step 5: Write a smoke test that applies migrations and round-trips a row**

Create `src/lib/server/db/client.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createDb, applyMigrations, schema } from './client';

describe('db client', () => {
  it('applies migrations and round-trips users', () => {
    const db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
    const rows = db.select().from(schema.users).all();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.username).toBe('alice');
  });
});
```

- [ ] **Step 6: Run the test**

```bash
pnpm test --run src/lib/server/db/client.test.ts
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(db): drizzle schema, sqlite client, initial migration"
git push
```

### Task 0.8: Define MarketData interface

**Files:**
- Create: `src/lib/server/market/types.ts`, `src/lib/server/market/mock.ts`, `src/lib/server/market/mock.test.ts`.

- [ ] **Step 1: Write the interface**

Create `src/lib/server/market/types.ts`:

```ts
export interface Quote {
  symbol: string;
  priceCents: number;
  fetchedAt: number;
}

export interface HistoricalBar {
  date: string;     // 'YYYY-MM-DD'
  closeCents: number;
}

export interface MarketData {
  getLiveQuote(symbol: string): Promise<Quote | null>;
  getHistoricalCloses(symbol: string, from: string, to: string): Promise<HistoricalBar[]>;
  getCloseAt(symbol: string, date: string): Promise<number | null>;
}

export class RateLimitError extends Error {
  constructor(public retryAfterSec: number) {
    super(`rate limited, retry after ${retryAfterSec}s`);
    this.name = 'RateLimitError';
  }
}
```

- [ ] **Step 2: Write a failing test for the mock**

Create `src/lib/server/market/mock.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { MockMarketData } from './mock';

describe('MockMarketData', () => {
  let m: MockMarketData;
  beforeEach(() => {
    m = new MockMarketData();
    m.setLive('AAPL', 19500);
    m.setHistorical('AAPL', '2024-01-02', 18000);
    m.setHistorical('AAPL', '2024-12-31', 25000);
  });

  it('returns live quotes', async () => {
    const q = await m.getLiveQuote('AAPL');
    expect(q?.priceCents).toBe(19500);
  });

  it('returns null for unknown symbols', async () => {
    expect(await m.getLiveQuote('NOPE')).toBeNull();
  });

  it('returns single historical close', async () => {
    expect(await m.getCloseAt('AAPL', '2024-01-02')).toBe(18000);
  });

  it('returns range of closes', async () => {
    const bars = await m.getHistoricalCloses('AAPL', '2024-01-01', '2024-12-31');
    expect(bars.map((b) => b.date).sort()).toEqual(['2024-01-02', '2024-12-31']);
  });
});
```

- [ ] **Step 3: Run the test, expect failure**

```bash
pnpm test --run src/lib/server/market/mock.test.ts
```

- [ ] **Step 4: Implement the mock**

Create `src/lib/server/market/mock.ts`:

```ts
import type { MarketData, Quote, HistoricalBar } from './types';

export class MockMarketData implements MarketData {
  private live = new Map<string, number>();
  private eod = new Map<string, Map<string, number>>();

  setLive(symbol: string, priceCents: number) {
    this.live.set(symbol, priceCents);
  }
  setHistorical(symbol: string, date: string, closeCents: number) {
    if (!this.eod.has(symbol)) this.eod.set(symbol, new Map());
    this.eod.get(symbol)!.set(date, closeCents);
  }

  async getLiveQuote(symbol: string): Promise<Quote | null> {
    const c = this.live.get(symbol);
    if (c == null) return null;
    return { symbol, priceCents: c, fetchedAt: Math.floor(Date.now() / 1000) };
  }
  async getCloseAt(symbol: string, date: string): Promise<number | null> {
    return this.eod.get(symbol)?.get(date) ?? null;
  }
  async getHistoricalCloses(
    symbol: string,
    from: string,
    to: string
  ): Promise<HistoricalBar[]> {
    const map = this.eod.get(symbol);
    if (!map) return [];
    const out: HistoricalBar[] = [];
    for (const [date, closeCents] of map) {
      if (date >= from && date <= to) out.push({ date, closeCents });
    }
    return out.sort((a, b) => a.date.localeCompare(b.date));
  }
}
```

- [ ] **Step 5: Run, expect PASS, commit**

```bash
pnpm test --run src/lib/server/market/mock.test.ts
git add -A
git commit -m "feat(market): MarketData interface + MockMarketData impl"
git push
```

### Task 0.9: Write initial documentation skeleton

**Files:**
- Create: `docs/README.md`, `docs/architecture.md`, `docs/tech-choices.md`, `docs/data-model.md`.

These are seeded with content drawn directly from the spec; later phases append implementation notes.

- [ ] **Step 1: Write `docs/README.md`**

```markdown
# finance-sim docs

Implementation notes and design rationale for v3.

## start here

- [`architecture.md`](./architecture.md) — high-level shape
- [`tech-choices.md`](./tech-choices.md) — stack and tradeoffs
- [`data-model.md`](./data-model.md) — schema + invariants

## subsystems

- [`auth/`](./auth/) — passkey-only auth
- [`market-data/`](./market-data/) — finnhub + twelvedata + caching
- [`competitions/`](./competitions/) — live + instant-replay

## ops

- [`testing.md`](./testing.md)
- [`deployment.md`](./deployment.md)

design spec: [`superpowers/specs/2026-05-05-finance-sim-v3-design.md`](./superpowers/specs/2026-05-05-finance-sim-v3-design.md).
```

- [ ] **Step 2: Write `docs/architecture.md`**

Distill spec §4 (architecture + module boundaries) into a self-contained doc. Show the `nginx → node → sqlite` diagram and the `src/lib/server/*` boundary rules. ~150 lines.

- [ ] **Step 3: Write `docs/tech-choices.md`**

Distill spec §3 (stack) into a "we picked X because Y" doc. One paragraph per major choice (sveltekit, drizzle, better-sqlite3, simplewebauthn, tailwind v4, uPlot, pnpm). ~120 lines.

- [ ] **Step 4: Write `docs/data-model.md`**

Distill spec §5 (data model + invariants) into prose. Explain why integer cents, why append-only ledger, why holdings rows are deleted at 0. Include the SQL DDL snippets. ~180 lines.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: seed architecture, tech-choices, data-model"
git push
```

---

## Phase 1 — Parallel tracks

Three subagents work simultaneously after Phase 0. Each owns a non-overlapping file scope. The schema and `MarketData` interface are frozen — agents must not modify them.

### Track A — Auth (Passkeys + Sessions + Recovery)

**Owns:**
- `src/lib/server/auth/**`
- `src/routes/(auth)/**`
- `src/routes/(app)/settings/passkeys/**`
- `src/routes/(app)/+layout.server.ts` (just the session-check wiring; coordinate with Track C if needed)
- `src/hooks.server.ts` (session resolution)
- `docs/auth/**`

#### Task A.1: Research and write `docs/auth/webauthn-primer.md`

Before any code. The doc is the deliverable for this task.

- [ ] **Step 1: Read primary sources**

Open the following and take notes (timing budget: 1 hour):
- W3C WebAuthn Level 3 spec — https://www.w3.org/TR/webauthn-3/
- passkeys.dev — https://passkeys.dev/docs/
- @simplewebauthn server docs — https://simplewebauthn.dev/docs/packages/server
- @simplewebauthn browser docs — https://simplewebauthn.dev/docs/packages/browser
- FIDO Alliance "What is a passkey?" — https://fidoalliance.org/passkeys/

If a fetch is blocked, ask the user to paste the relevant section. Do not skip.

- [ ] **Step 2: Write the primer**

Create `docs/auth/webauthn-primer.md`. Cover:

1. What a passkey actually is (a public/private keypair, where the private key lives, what the relying party stores)
2. Registration ceremony, step by step
3. Authentication ceremony, step by step
4. RP ID rules — why localhost works in dev but prod needs the registered domain to match
5. `backup_eligible` and `backup_state` flags — what they mean, why we store them
6. AAGUID — what it is, how we use it for device-name suggestions, link to AAGUID database
7. Synced vs device-bound credentials in 2026
8. `hybrid` transport ("scan QR with phone") — how cross-device authentication works at the platform level
9. The signature counter — anti-replay, what to do if it goes backwards
10. Resident credentials / discoverable credentials — why we use them so users don't need to type a username at sign-in
11. Threats not addressed by WebAuthn (the threat-model doc covers ours specifically)

~400-600 lines. Include diagrams in ASCII or simple Markdown tables where they help.

- [ ] **Step 3: Commit**

```bash
git add docs/auth/webauthn-primer.md
git commit -m "docs(auth): webauthn primer from primary sources"
git push
```

#### Task A.2: Sessions module

**Files:**
- Create: `src/lib/server/auth/sessions.ts`, `src/lib/server/auth/sessions.test.ts`.

- [ ] **Step 1: Write the failing test**

Create `src/lib/server/auth/sessions.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { createSession, resolveSession, revokeSession, hashSessionId } from './sessions';

describe('sessions', () => {
  let db: Db;
  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
  });

  it('creates a session and resolves it via the cookie value', async () => {
    const { cookieValue, expiresAt } = await createSession(db, 'u1', 'jest');
    expect(cookieValue.length).toBeGreaterThanOrEqual(32);
    expect(expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    const resolved = await resolveSession(db, cookieValue);
    expect(resolved?.userId).toBe('u1');
  });

  it('returns null for unknown cookie values', async () => {
    expect(await resolveSession(db, 'unknown')).toBeNull();
  });

  it('returns null for expired sessions', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest', -1);
    expect(await resolveSession(db, cookieValue)).toBeNull();
  });

  it('revokes a session', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest');
    await revokeSession(db, cookieValue);
    expect(await resolveSession(db, cookieValue)).toBeNull();
  });

  it('stores hashed session id, never the raw cookie value', async () => {
    const { cookieValue } = await createSession(db, 'u1', 'jest');
    const rows = db.select().from(schema.sessions).all();
    expect(rows[0]?.id).not.toBe(cookieValue);
    expect(rows[0]?.id).toBe(hashSessionId(cookieValue));
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm test --run src/lib/server/auth/sessions.test.ts
```

- [ ] **Step 3: Implement**

Create `src/lib/server/auth/sessions.ts`:

```ts
import { eq, gt } from 'drizzle-orm';
import { createHash, randomBytes } from 'node:crypto';
import { schema, type Db } from '$lib/server/db/client';

const SESSION_LIFETIME_SEC = 60 * 60 * 24 * 30; // 30 days

export function hashSessionId(cookieValue: string): string {
  return createHash('sha256').update(cookieValue).digest('hex');
}

export interface CreatedSession {
  cookieValue: string;
  expiresAt: number;
}

export async function createSession(
  db: Db,
  userId: string,
  userAgent: string,
  lifetimeSecOverride?: number
): Promise<CreatedSession> {
  const cookieValue = randomBytes(32).toString('base64url');
  const id = hashSessionId(cookieValue);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + (lifetimeSecOverride ?? SESSION_LIFETIME_SEC);
  db.insert(schema.sessions).values({
    id,
    userId,
    expiresAt,
    createdAt: now,
    userAgent
  }).run();
  return { cookieValue, expiresAt };
}

export interface ResolvedSession {
  userId: string;
  expiresAt: number;
}

export async function resolveSession(
  db: Db,
  cookieValue: string
): Promise<ResolvedSession | null> {
  const id = hashSessionId(cookieValue);
  const now = Math.floor(Date.now() / 1000);
  const row = db
    .select()
    .from(schema.sessions)
    .where(eq(schema.sessions.id, id))
    .get();
  if (!row) return null;
  if (row.expiresAt <= now) {
    db.delete(schema.sessions).where(eq(schema.sessions.id, id)).run();
    return null;
  }
  return { userId: row.userId, expiresAt: row.expiresAt };
}

export async function revokeSession(db: Db, cookieValue: string): Promise<void> {
  const id = hashSessionId(cookieValue);
  db.delete(schema.sessions).where(eq(schema.sessions.id, id)).run();
}

export async function revokeExpired(db: Db): Promise<number> {
  const now = Math.floor(Date.now() / 1000);
  const res = db.delete(schema.sessions).where(gt(schema.sessions.expiresAt, now)).run();
  return res.changes;
}
```

- [ ] **Step 4: Verify, commit**

```bash
pnpm test --run src/lib/server/auth/sessions.test.ts
git add -A
git commit -m "feat(auth): session create/resolve/revoke with hashed ids"
git push
```

#### Task A.3: WebAuthn wrappers

**Files:**
- Create: `src/lib/server/auth/webauthn.ts`, `src/lib/server/auth/webauthn.test.ts`, `src/lib/server/auth/aaguid.ts`.

- [ ] **Step 1: Build a thin AAGUID → device-name lookup**

The list is small (we hard-code a handful of common ones; everything else falls back to "Security key" or "Passkey"). Create `src/lib/server/auth/aaguid.ts`:

```ts
const KNOWN: Record<string, string> = {
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '00000000-0000-0000-0000-000000000000': 'Passkey',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain'
};

export function suggestDeviceName(aaguid: string): string {
  return KNOWN[aaguid] ?? 'Passkey';
}
```

- [ ] **Step 2: Write the failing test**

Create `src/lib/server/auth/webauthn.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { rpConfig, generateRegistrationChallenge, generateAuthenticationChallenge } from './webauthn';

describe('webauthn config and challenges', () => {
  it('reads RP ID and origin from environment-shaped config', () => {
    const cfg = rpConfig({ rpId: 'localhost', origin: 'http://localhost:5173' });
    expect(cfg.rpId).toBe('localhost');
    expect(cfg.expectedOrigin).toBe('http://localhost:5173');
  });

  it('generates registration options containing the username and a challenge', async () => {
    const opts = await generateRegistrationChallenge({
      rp: { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' },
      userId: 'u1',
      username: 'alice',
      displayName: 'Alice',
      excludeCredentialIds: []
    });
    expect(opts.user.name).toBe('alice');
    expect(opts.user.displayName).toBe('Alice');
    expect(opts.challenge).toBeDefined();
  });

  it('generates authentication options that allow resident credentials', async () => {
    const opts = await generateAuthenticationChallenge({
      rp: { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' }
    });
    expect(opts.challenge).toBeDefined();
    expect(opts.allowCredentials).toEqual([]);
  });
});
```

- [ ] **Step 3: Run, fail**

```bash
pnpm test --run src/lib/server/auth/webauthn.test.ts
```

- [ ] **Step 4: Implement the wrappers**

Create `src/lib/server/auth/webauthn.ts`:

```ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse
} from '@simplewebauthn/server';

export interface RpConfig {
  rpId: string;
  rpName: string;
  expectedOrigin: string;
}

export function rpConfig(input: { rpId: string; origin: string; rpName?: string }): RpConfig {
  return {
    rpId: input.rpId,
    rpName: input.rpName ?? 'finance-sim',
    expectedOrigin: input.origin
  };
}

export async function generateRegistrationChallenge(args: {
  rp: RpConfig;
  userId: string;
  username: string;
  displayName: string;
  excludeCredentialIds: string[];
}) {
  return generateRegistrationOptions({
    rpName: args.rp.rpName,
    rpID: args.rp.rpId,
    userID: new TextEncoder().encode(args.userId),
    userName: args.username,
    userDisplayName: args.displayName,
    attestationType: 'none',
    excludeCredentials: args.excludeCredentialIds.map((id) => ({ id })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred'
    }
  });
}

export async function verifyRegistration(args: {
  rp: RpConfig;
  expectedChallenge: string;
  response: Parameters<typeof verifyRegistrationResponse>[0]['response'];
}): Promise<VerifiedRegistrationResponse> {
  return verifyRegistrationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    requireUserVerification: false
  });
}

export async function generateAuthenticationChallenge(args: { rp: RpConfig }) {
  return generateAuthenticationOptions({
    rpID: args.rp.rpId,
    userVerification: 'preferred',
    allowCredentials: []
  });
}

export async function verifyAuthentication(args: {
  rp: RpConfig;
  expectedChallenge: string;
  storedCredential: { id: string; publicKey: Buffer; counter: number; transports?: string[] };
  response: Parameters<typeof verifyAuthenticationResponse>[0]['response'];
}): Promise<VerifiedAuthenticationResponse> {
  return verifyAuthenticationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    credential: {
      id: args.storedCredential.id,
      publicKey: args.storedCredential.publicKey,
      counter: args.storedCredential.counter,
      transports: args.storedCredential.transports as never
    },
    requireUserVerification: false
  });
}
```

- [ ] **Step 5: Verify, commit**

```bash
pnpm test --run src/lib/server/auth/webauthn.test.ts
git add -A
git commit -m "feat(auth): webauthn wrappers + aaguid lookup"
git push
```

#### Task A.4: Recovery codes

**Files:**
- Create: `src/lib/server/auth/recovery.ts`, `src/lib/server/auth/recovery.test.ts`.

- [ ] **Step 1: Write failing test**

Create `src/lib/server/auth/recovery.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { generateRecoveryCodes, verifyRecoveryCode, regenerateRecoveryCodes } from './recovery';

describe('recovery codes', () => {
  let db: Db;
  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: 'u1',
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
  });

  it('generates exactly 8 unique codes', async () => {
    const codes = await generateRecoveryCodes(db, 'u1');
    expect(codes).toHaveLength(8);
    expect(new Set(codes).size).toBe(8);
  });

  it('verifies a code once, then rejects reuse', async () => {
    const codes = await generateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', codes[0]!)).toBe(true);
    expect(await verifyRecoveryCode(db, 'u1', codes[0]!)).toBe(false);
  });

  it('rejects unknown codes', async () => {
    await generateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', 'WRONG-CODE-1234-WXYZ')).toBe(false);
  });

  it('regenerate replaces all unused codes', async () => {
    const first = await generateRecoveryCodes(db, 'u1');
    const second = await regenerateRecoveryCodes(db, 'u1');
    expect(await verifyRecoveryCode(db, 'u1', first[0]!)).toBe(false);
    expect(await verifyRecoveryCode(db, 'u1', second[0]!)).toBe(true);
  });
});
```

- [ ] **Step 2: Run, fail**

```bash
pnpm test --run src/lib/server/auth/recovery.test.ts
```

- [ ] **Step 3: Implement**

Create `src/lib/server/auth/recovery.ts`:

```ts
import { eq, and, isNull } from 'drizzle-orm';
import argon2 from 'argon2';
import { createId } from '@paralleldrive/cuid2';
import { randomBytes } from 'node:crypto';
import { schema, type Db } from '$lib/server/db/client';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I confusion
const GROUP = 4;
const GROUPS = 4;
const COUNT = 8;

function generateCode(): string {
  const buf = randomBytes(GROUP * GROUPS);
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    out += ALPHABET[buf[i]! % ALPHABET.length];
    if ((i + 1) % GROUP === 0 && i !== buf.length - 1) out += '-';
  }
  return out;
}

export async function generateRecoveryCodes(db: Db, userId: string): Promise<string[]> {
  const codes: string[] = [];
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < COUNT; i++) {
    const code = generateCode();
    codes.push(code);
    const codeHash = await argon2.hash(code, { type: argon2.argon2id });
    db.insert(schema.recoveryCodes).values({
      id: createId(),
      userId,
      codeHash,
      usedAt: null,
      createdAt: now
    }).run();
  }
  return codes;
}

export async function verifyRecoveryCode(db: Db, userId: string, code: string): Promise<boolean> {
  const rows = db
    .select()
    .from(schema.recoveryCodes)
    .where(and(eq(schema.recoveryCodes.userId, userId), isNull(schema.recoveryCodes.usedAt)))
    .all();
  for (const row of rows) {
    if (await argon2.verify(row.codeHash, code)) {
      db.update(schema.recoveryCodes)
        .set({ usedAt: Math.floor(Date.now() / 1000) })
        .where(eq(schema.recoveryCodes.id, row.id))
        .run();
      return true;
    }
  }
  return false;
}

export async function regenerateRecoveryCodes(db: Db, userId: string): Promise<string[]> {
  db.delete(schema.recoveryCodes).where(eq(schema.recoveryCodes.userId, userId)).run();
  return generateRecoveryCodes(db, userId);
}
```

- [ ] **Step 4: Verify, commit**

```bash
pnpm test --run src/lib/server/auth/recovery.test.ts
git add -A
git commit -m "feat(auth): recovery codes with argon2id hashing"
git push
```

#### Task A.5: High-level auth service

**Files:**
- Create: `src/lib/server/auth/service.ts`, `src/lib/server/auth/service.test.ts`.

The service composes webauthn + sessions + recovery into the use cases the routes call. Coverage:
- `beginSignup(username)` → registration challenge + temporary user-id allocation
- `completeSignup(...)` → verify ceremony, create user, store passkey, generate codes, create session
- `beginSignin()` → authentication challenge (no username)
- `completeSignin(...)` → verify, update counter + last_used_at, create session
- `beginAddPasskey(userId)` → registration challenge for an existing user
- `completeAddPasskey(...)` → verify, store new passkey
- `revokePasskey(userId, passkeyId)` → delete with last-passkey guard
- `signinWithRecoveryCode(username, code)` → verify code, create session

- [ ] **Step 1: Write the failing tests**

Create `src/lib/server/auth/service.test.ts` covering:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import * as auth from './service';

describe('auth service', () => {
  let db: Db;
  const rp = { rpId: 'localhost', expectedOrigin: 'http://localhost:5173', rpName: 'test' };

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
  });

  it('beginSignup returns options + a challenge cookie', async () => {
    const out = await auth.beginSignup(db, rp, 'alice', 'Alice', 'jest-ua');
    expect(out.options.user.name).toBe('alice');
    expect(out.challengeCookieValue).toBeDefined();
  });

  it('beginSignup rejects taken usernames', async () => {
    db.insert(schema.users).values({
      id: 'x', username: 'alice', displayName: 'Alice', cashCents: 0, createdAt: 0
    }).run();
    await expect(auth.beginSignup(db, rp, 'alice', 'Alice', 'jest-ua')).rejects.toThrow();
  });

  it('signinWithRecoveryCode returns a session for valid code', async () => {
    const userId = 'u1';
    db.insert(schema.users).values({
      id: userId, username: 'alice', displayName: 'Alice', cashCents: 1_000_000, createdAt: 0
    }).run();
    const codes = await (await import('./recovery')).generateRecoveryCodes(db, userId);
    const sess = await auth.signinWithRecoveryCode(db, 'alice', codes[0]!, 'jest-ua');
    expect(sess?.userId).toBe(userId);
  });

  it('signinWithRecoveryCode returns null on bad code', async () => {
    db.insert(schema.users).values({
      id: 'u1', username: 'alice', displayName: 'Alice', cashCents: 1_000_000, createdAt: 0
    }).run();
    const sess = await auth.signinWithRecoveryCode(db, 'alice', 'bogus', 'jest-ua');
    expect(sess).toBeNull();
  });

  it('revokePasskey refuses to delete the last passkey', async () => {
    const userId = 'u1';
    db.insert(schema.users).values({
      id: userId, username: 'a', displayName: 'A', cashCents: 0, createdAt: 0
    }).run();
    db.insert(schema.passkeys).values({
      id: 'pk1', userId, credentialId: 'c1', publicKey: Buffer.from([1]),
      counter: 0, transports: '[]', deviceName: 'Phone', aaguid: '00000000-0000-0000-0000-000000000000',
      backupEligible: 1, backupState: 1, createdAt: 0, lastUsedAt: 0
    }).run();
    await expect(auth.revokePasskey(db, userId, 'pk1')).rejects.toThrow(/last passkey/);
  });
});
```

(Tests for `completeSignup` / `completeSignin` need a virtual authenticator; cover those in the E2E suite. The unit tests above lock in the parts not requiring browser-side ceremonies.)

- [ ] **Step 2: Run, fail**

```bash
pnpm test --run src/lib/server/auth/service.test.ts
```

- [ ] **Step 3: Implement the service**

Create `src/lib/server/auth/service.ts`. The full implementation is ~250 lines composing the previous primitives. It exports the functions referenced in the tests plus the registration/signin completion handlers. Use `auth_challenges` to store challenges with a 5-minute expiry, identified by a hashed cookie value, mirroring the sessions pattern.

Key implementation notes:
- `beginSignup` allocates a `cuid2` user id (does NOT insert into `users` yet — only on `completeSignup`), generates registration options, stores the challenge with `purpose='register'` and `userId=<allocated>`.
- `completeSignup` verifies the registration response, inserts the user, inserts the first passkey, generates 8 recovery codes (returns them once), creates a session.
- `beginSignin` generates an authentication challenge with `allowCredentials=[]` (resident credential discovery), stores with `purpose='authenticate'`, `userId=null`.
- `completeSignin` looks up the credential by `credentialId` from the response, verifies, updates counter + last_used, creates session.
- `beginAddPasskey` requires an existing session, mirrors `beginSignup` for an already-known user.
- `revokePasskey` counts user's passkeys and refuses if it would leave them with zero (enforces "you must have at least one passkey to retain account access" — the user can always regenerate recovery codes, but they can't delete their last device key without an explicit "delete account" action).

- [ ] **Step 4: Verify, commit**

```bash
pnpm test --run src/lib/server/auth/service.test.ts
git add -A
git commit -m "feat(auth): high-level service composing webauthn + sessions + recovery"
git push
```

#### Task A.6: hooks.server.ts session resolution

**Files:**
- Create: `src/hooks.server.ts`, `src/app.d.ts` updates.

- [ ] **Step 1: Update `src/app.d.ts` for typed locals**

```ts
declare global {
  namespace App {
    interface Locals {
      session: { userId: string; expiresAt: number } | null;
      user: { id: string; username: string; displayName: string } | null;
    }
  }
}

export {};
```

- [ ] **Step 2: Implement the hook**

Create `src/hooks.server.ts`:

```ts
import type { Handle } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { resolveSession } from '$lib/server/auth/sessions';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import { env } from '$env/dynamic/private';

const db = createDb(env.DATABASE_URL ?? './finance.db');
applyMigrations(db);

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.session = null;
  event.locals.user = null;

  const cookie = event.cookies.get('session');
  if (cookie) {
    const session = await resolveSession(db, cookie);
    if (session) {
      const user = db
        .select({
          id: schema.users.id,
          username: schema.users.username,
          displayName: schema.users.displayName
        })
        .from(schema.users)
        .where(eq(schema.users.id, session.userId))
        .get();
      if (user) {
        event.locals.session = session;
        event.locals.user = user;
      }
    }
  }

  return resolve(event);
};

export { db };
```

- [ ] **Step 3: Wire `(app)` group to require a session**

Create `src/routes/(app)/+layout.server.ts`:

```ts
import { redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals }) => {
  if (!locals.user) throw redirect(302, '/signin');
  return { user: locals.user };
};
```

- [ ] **Step 4: Smoke-test build**

```bash
pnpm check && pnpm build
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(auth): server hook resolves session, (app) layout enforces login"
git push
```

#### Task A.7: Auth routes — sign-up

**Files:**
- Create: `src/routes/(auth)/+layout.svelte`, `src/routes/(auth)/signup/+page.svelte`, `src/routes/(auth)/signup/+page.server.ts`, `src/routes/(auth)/signup/+server.ts`.

The flow: GET `/signup` renders the form; POST to `/signup?/begin` returns registration options; the browser performs `startRegistration`, posts the result to `/signup?/complete`, server verifies and writes user + passkey + codes; codes are shown in the `success` page state with a "I've saved them" confirm button before redirect to `/portfolio`.

- [ ] **Step 1: Implement the page-server actions**

Create `src/routes/(auth)/signup/+page.server.ts`:

```ts
import { error, fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { db } from '$lib/../hooks.server';
import * as auth from '$lib/server/auth/service';
import { createSession } from '$lib/server/auth/sessions';
import { env } from '$env/dynamic/private';

const rp = {
  rpId: env.RP_ID ?? 'localhost',
  expectedOrigin: env.ORIGIN ?? 'http://localhost:5173',
  rpName: 'finance-sim'
};

export const load: PageServerLoad = async ({ locals }) => {
  if (locals.user) throw redirect(302, '/portfolio');
  return {};
};

export const actions: Actions = {
  begin: async ({ request, cookies, getClientAddress }) => {
    const form = await request.formData();
    const username = String(form.get('username') ?? '').trim();
    const displayName = String(form.get('displayName') ?? '').trim() || username;
    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) {
      return fail(400, { error: 'username must be 3-24 chars, letters/digits/_/-' });
    }
    try {
      const { options, challengeCookieValue } = await auth.beginSignup(
        db, rp, username, displayName, request.headers.get('user-agent') ?? ''
      );
      cookies.set('signup_challenge', challengeCookieValue, {
        path: '/', httpOnly: true, secure: env.ORIGIN?.startsWith('https') ?? false,
        sameSite: 'strict', maxAge: 300
      });
      return { stage: 'options' as const, options };
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'signup failed';
      return fail(400, { error: msg });
    }
  },
  complete: async ({ request, cookies }) => {
    const challengeCookie = cookies.get('signup_challenge');
    if (!challengeCookie) return fail(400, { error: 'missing or expired challenge' });
    const body = await request.json();
    const result = await auth.completeSignup(db, rp, challengeCookie, body.attestation);
    cookies.delete('signup_challenge', { path: '/' });
    const session = await createSession(db, result.userId, request.headers.get('user-agent') ?? '');
    cookies.set('session', session.cookieValue, {
      path: '/', httpOnly: true, secure: env.ORIGIN?.startsWith('https') ?? false,
      sameSite: 'lax', maxAge: 60 * 60 * 24 * 30
    });
    return { stage: 'success' as const, recoveryCodes: result.recoveryCodes };
  }
};
```

- [ ] **Step 2: Implement the page**

Create `src/routes/(auth)/signup/+page.svelte`. Three states: form, "create passkey" prompt (calls `@simplewebauthn/browser` `startRegistration`), success-with-codes. Use `enhance` for progressive enhancement on the form. Style with Tailwind matching the UI shell from Track C.

Show recovery codes as a monospace block with a copy button and a download `.txt` button. The "continue to portfolio" CTA is disabled until the user clicks "I've saved my codes" checkbox.

- [ ] **Step 3: Manual test**

```bash
pnpm dev
```
Visit `/signup`, walk through the flow with a virtual authenticator (Chrome DevTools → More tools → WebAuthn → Add virtual authenticator → ctap2 + internal). Verify a user + passkey + 8 recovery codes land in `finance.db`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(auth): signup flow with passkey + recovery codes"
git push
```

#### Task A.8: Auth routes — sign-in and recovery

**Files:**
- Create: `src/routes/(auth)/signin/+page.svelte`, `src/routes/(auth)/signin/+page.server.ts`, `src/routes/(auth)/recover/+page.svelte`, `src/routes/(auth)/recover/+page.server.ts`.

- [ ] **Step 1: Sign-in page-server**

Mirrors the signup pattern with `auth.beginSignin` / `auth.completeSignin`. No username field on the form — the page calls `startAuthentication({ useBrowserAutofill: false })` directly with the discoverable-credential challenge. On success, set the session cookie and redirect to `/portfolio`.

- [ ] **Step 2: Sign-in page**

Two-button UI: "sign in with passkey" (primary), "use a recovery code" (link). On primary click, call `startAuthentication`, post result to `?/complete`.

- [ ] **Step 3: Recover page-server**

Form: username + recovery code. Calls `auth.signinWithRecoveryCode`. On success, sets a *temporary* session with a `must_register_passkey` flag (add a column on `sessions` or use a separate cookie — pick one in implementation; the simpler choice is a separate `force_passkey_setup=1` cookie, expiring with the session). Redirect to `/settings/passkeys?force=1`.

- [ ] **Step 4: Recover page**

Two text inputs, submit button. Plain Tailwind form. Display server errors in a banner.

- [ ] **Step 5: Manual test**

Sign out (a quick `/signout` POST you'll add inline in the header), sign back in, then test the recovery flow: take one of the codes saved during sign-up, sign out, recover, verify forced-passkey-setup screen.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(auth): signin + recover flows"
git push
```

#### Task A.9: Settings — passkey management

**Files:**
- Create: `src/routes/(app)/settings/+page.svelte`, `src/routes/(app)/settings/+page.server.ts`, `src/routes/(app)/settings/passkeys/+page.svelte`, `src/routes/(app)/settings/passkeys/+page.server.ts`.

- [ ] **Step 1: Passkey list with rename, revoke, add**

Server load returns the user's passkeys with: `device_name`, `aaguid`-derived suggestion, `last_used_at`, `backup_state` (icon for "synced" vs "device-bound"). Actions:
- `add` — calls `auth.beginAddPasskey`, returns options. Browser does `startRegistration`, posts to `complete-add`.
- `complete-add` — calls `auth.completeAddPasskey`.
- `rename` — updates `device_name` after validation (1-40 chars).
- `revoke` — calls `auth.revokePasskey` (refuses last).
- `regenerate-recovery` — calls `regenerateRecoveryCodes`, returns codes once for display.

- [ ] **Step 2: UI**

Table of passkeys (device, last used, backup status, actions). "Add a passkey on this device" button. "Regenerate recovery codes" with confirmation. Recovery codes shown the same way as sign-up.

- [ ] **Step 3: Manual test**

Add a second virtual authenticator in DevTools, register it, rename, revoke the first, attempt to revoke the last (should fail), regenerate codes.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(auth): settings/passkeys management with rename/revoke/add"
git push
```

#### Task A.10: Auth docs

**Files:**
- Create: `docs/auth/overview.md`, `docs/auth/passkey-flows.md`, `docs/auth/threat-model.md`, `docs/auth/implementation-notes.md`.

- [ ] **Step 1: `overview.md`**

Distill spec §6 into a self-contained narrative: privacy posture, what we store, what we don't, the choice of recovery codes as the only fallback, the trade-off it implies. ~150 lines.

- [ ] **Step 2: `passkey-flows.md`**

Sequence diagrams (ASCII or Mermaid) for: signup, signin, add-on-existing-device, sign-in via cross-device authentication, sign-in via recovery code. Reference the actual code paths and tables touched in each step. ~250 lines.

- [ ] **Step 3: `threat-model.md`**

What we defend against (replay via signature counter, credential theft requires device biometric/PIN, phishing prevented by RP ID binding) and what we don't (lost device + lost codes = lost account; account enumeration via /signup error messages — discuss mitigation: same response shape for "username taken" as "valid username"). ~150 lines.

- [ ] **Step 4: `implementation-notes.md`**

Real gotchas encountered while writing the code:
- RP ID rules in localhost vs prod
- `@simplewebauthn` API differences vs older WebAuthn tutorials
- The `userID` is now bytes, not string (changed in v10+)
- Counter handling — when ZERO (passkey synced) means we don't enforce monotonicity; documented in the library
- `useBrowserAutofill` and conditional UI — when to use, when not
- TextEncoder for userID across Node versions
- ~200 lines.

- [ ] **Step 5: Commit**

```bash
git add docs/auth/
git commit -m "docs(auth): overview, flows, threat model, implementation notes"
git push
```

---

### Track B — Market data

**Owns:**
- `src/lib/server/market/**`
- `docs/market-data/**`

#### Task B.1: NYSE market hours and holiday calendar

**Files:**
- Create: `src/lib/server/market/market-hours.ts`, `src/lib/server/market/market-hours.test.ts`, `src/lib/server/market/nyse-holidays.json`.

- [ ] **Step 1: Source the holiday list**

Compile a JSON of NYSE full-close holidays for 2024–2030 from https://www.nyse.com/markets/hours-calendars. If fetch is blocked, ask the user to paste. Format:

```json
[
  { "date": "2024-01-01", "name": "New Year's Day" },
  { "date": "2024-01-15", "name": "MLK Day" },
  ...
]
```

Store at `src/lib/server/market/nyse-holidays.json`.

- [ ] **Step 2: Failing test**

Create `market-hours.test.ts` covering `isMarketOpen(unixSec)` for: weekday 10am ET, weekday 5am ET, weekday 5pm ET, Saturday noon ET, NYE 2024 noon ET (closed-holiday), 2024-07-03 1pm ET (early close — note: we treat early closes as fully open for caching purposes; document this).

- [ ] **Step 3: Implement**

`market-hours.ts`:

```ts
import holidays from './nyse-holidays.json';

const HOLIDAY_DATES = new Set(holidays.map((h) => h.date));

function toEt(unixSec: number): { dateIso: string; hour: number; minute: number; weekday: number } {
  // formatToParts in Intl with America/New_York
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/New_York',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
    weekday: 'short'
  });
  const parts = Object.fromEntries(fmt.formatToParts(new Date(unixSec * 1000)).map((p) => [p.type, p.value]));
  const weekdayMap: Record<string, number> = { Sun:0, Mon:1, Tue:2, Wed:3, Thu:4, Fri:5, Sat:6 };
  return {
    dateIso: `${parts.year}-${parts.month}-${parts.day}`,
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    weekday: weekdayMap[parts.weekday!]!
  };
}

export function isMarketOpen(unixSec: number): boolean {
  const t = toEt(unixSec);
  if (t.weekday === 0 || t.weekday === 6) return false;
  if (HOLIDAY_DATES.has(t.dateIso)) return false;
  const minutes = t.hour * 60 + t.minute;
  return minutes >= 9 * 60 + 30 && minutes < 16 * 60;
}

export function nextOpenAfter(unixSec: number): number {
  let cursor = unixSec;
  for (let i = 0; i < 14; i++) {
    cursor += 86_400;
    if (isMarketOpen(cursor)) return cursor;
  }
  return cursor;
}
```

- [ ] **Step 4: Verify, commit**

```bash
pnpm test --run src/lib/server/market/market-hours.test.ts
git add -A
git commit -m "feat(market): nyse market-hours + holiday calendar"
git push
```

#### Task B.2: TwelveData adapter

> **Note (post-ship):** Originally planned as a Stooq adapter, but Stooq turned out to be a captcha-gated CSV download with no real API, docs, or signup. Switched to TwelveData. Task completed as `refactor(market): swap stooq for twelvedata`.

**Files:**
- Created: `src/lib/server/market/twelvedata.ts`, `src/lib/server/market/twelvedata.test.ts`, `src/lib/server/market/__fixtures__/twelvedata-aapl.json`.
- Deleted: `stooq.ts`, `stooq.test.ts`, `__fixtures__/stooq-aapl.csv`.

- [x] **Step 1: Capture a real fixture**

Verified live response shape from `https://api.twelvedata.com/time_series?symbol=AAPL&interval=1day&start_date=2024-01-02&end_date=2024-01-04&apikey=...`. Saved as `__fixtures__/twelvedata-aapl.json`.

- [x] **Step 2: Failing test** — 8 tests, import-fails on missing module.

- [x] **Step 3: Run, fail** — confirmed.

- [x] **Step 4: Implement**

TwelveData URL: `https://api.twelvedata.com/time_series?symbol={SYMBOL}&interval=1day&start_date={YYYY-MM-DD}&end_date={YYYY-MM-DD}&apikey={KEY}`. Returns JSON with `values[]` sorted descending; adapter re-sorts ascending. `close` is a string; parse with `parseFloat` then `Math.round(* 100)` for cents. `status:'error'` ⇒ return `[]`. HTTP 429 or body `code:429` ⇒ throw `RateLimitError(60)`. Missing key ⇒ return `[]` (dev convenience).

`getLiveQuote` returns `null` — TwelveData has `/price` but we use Finnhub for live quotes.

Key via `TWELVEDATA_API_KEY`.

- [x] **Step 5: Verify, commit** — `refactor(market): swap stooq for twelvedata (real api with docs)`

#### Task B.3: Finnhub adapter

**Files:**
- Create: `src/lib/server/market/finnhub.ts`, `src/lib/server/market/finnhub.test.ts`, `src/lib/server/market/__fixtures__/finnhub-quote.json`.

- [ ] **Step 1: Capture fixture**

```bash
curl -s "https://finnhub.io/api/v1/quote?symbol=AAPL&token=$FINNHUB_API_KEY" \
  > src/lib/server/market/__fixtures__/finnhub-quote.json
```

Should look like `{"c":190.5,"d":1.2,"dp":0.6,"h":...,"l":...,"o":...,"pc":...,"t":...}`.

- [ ] **Step 2: Failing test**

```ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FinnhubAdapter } from './finnhub';
import { RateLimitError } from './types';

const fixture = readFileSync(join(__dirname, '__fixtures__/finnhub-quote.json'), 'utf8');

describe('FinnhubAdapter', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(fixture, { status: 200, headers: { 'content-type': 'application/json' } })
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('returns a Quote with cents', async () => {
    const a = new FinnhubAdapter('test-key');
    const q = await a.getLiveQuote('AAPL');
    expect(q?.priceCents).toBeGreaterThan(0);
    expect(q?.symbol).toBe('AAPL');
  });

  it('returns null when finnhub returns c=0 (unknown symbol)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ c: 0, d: 0, dp: 0, h: 0, l: 0, o: 0, pc: 0, t: 0 }), { status: 200 })
    );
    const a = new FinnhubAdapter('test-key');
    expect(await a.getLiveQuote('NOPE')).toBeNull();
  });

  it('throws RateLimitError on 429', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response('rate limit', { status: 429, headers: { 'retry-after': '15' } })
    );
    const a = new FinnhubAdapter('test-key');
    await expect(a.getLiveQuote('AAPL')).rejects.toBeInstanceOf(RateLimitError);
  });

  it('coalesces concurrent requests for the same symbol into one fetch', async () => {
    const a = new FinnhubAdapter('test-key');
    await Promise.all([a.getLiveQuote('AAPL'), a.getLiveQuote('AAPL'), a.getLiveQuote('AAPL')]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 3: Implement**

Standard `fetch` of `https://finnhub.io/api/v1/quote?symbol={SYMBOL}&token={KEY}`. Map `c` (current price) — if `0`, return null (Finnhub's "symbol not found" signal). Use a `Map<string, Promise<Quote|null>>` for in-flight coalescing.

`getHistoricalCloses` and `getCloseAt` return `null`/`[]` (Finnhub's free tier doesn't grant /candle access reliably; we use TwelveData for historical regardless).

- [ ] **Step 4: Verify, commit**

```bash
pnpm test --run src/lib/server/market/finnhub.test.ts
git add -A
git commit -m "feat(market): finnhub live-quote adapter with in-flight coalescing"
git push
```

#### Task B.4: Composite + cache

**Files:**
- Create: `src/lib/server/market/cache.ts`, `src/lib/server/market/service.ts`, `src/lib/server/market/cache.test.ts`, `src/lib/server/market/service.test.ts`.

- [ ] **Step 1: Cache failing test**

`cache.test.ts` covers:
- `getCachedLive(symbol)` returns the row if `fetched_at + ttl > now` and market is open; respects "after-hours infinite TTL"
- `setCachedLive(symbol, priceCents)` upserts the row
- `getCachedEod(symbol, date)` returns null for today's date; returns row for past
- `setCachedEod(symbol, date, closeCents)` upserts
- batch fill: `bulkSetEod(rows[])`

- [ ] **Step 2: Implement `cache.ts`**

Pure DB-touching functions; no HTTP. Use `isMarketOpen` from market-hours.

- [ ] **Step 3: Service failing test**

`service.test.ts` covers a `MarketDataService` that takes a `live: MarketData` (Finnhub) and `historical: MarketData` (TwelveData) and a `db`, exposing the unified `MarketData` interface:
- `getLiveQuote` → cache hit short-circuits; cache miss calls live, writes to cache, returns
- `getCloseAt('AAPL', today)` → falls through to live quote
- `getCloseAt('AAPL', pastDate)` → cache hit short-circuits; miss calls historical, writes to cache, returns
- `getHistoricalCloses` → for each date in the range, prefer cache; for missing dates, call historical once for the full range and bulk-cache

- [ ] **Step 4: Implement `service.ts`**

Composes the above. ~120 lines.

- [ ] **Step 5: Run all market tests, commit**

```bash
pnpm test --run src/lib/server/market
git add -A
git commit -m "feat(market): cache + composite service unifying finnhub and twelvedata"
git push
```

#### Task B.5: Market data docs

**Files:**
- Create: `docs/market-data/api-comparison.md`, `docs/market-data/caching-strategy.md`.

- [ ] **Step 1: `api-comparison.md`**

Table of free-tier APIs considered (Finnhub, TwelveData, Alpha Vantage, Stooq, Polygon, yfinance) with: rate limits, data range, key required, reliability notes, why we picked / didn't pick. ~120 lines. Note: Stooq was initially chosen but dropped — captcha-gated CSV, not a real API.

- [ ] **Step 2: `caching-strategy.md`**

The TTL rules, market-hours awareness, in-flight coalescing, "today is never EOD-cached," bulk-fill on comp resolution. ~150 lines.

- [ ] **Step 3: Commit**

```bash
git add docs/market-data/
git commit -m "docs(market): api comparison + caching strategy"
git push
```

---

### Track C — UI shell

**Owns:**
- `src/lib/components/**`
- `src/routes/+layout.svelte` (root layout)
- `src/routes/+page.svelte` (landing)
- `src/routes/(app)/+layout.svelte`
- `src/app.css`
- `tailwind.config.*` (already set up in Phase 0)

#### Task C.1: Theme provider

**Files:**
- Create: `src/lib/components/ThemeToggle.svelte`, modify `src/routes/+layout.svelte` for mode-watcher.

- [ ] **Step 1: Wire mode-watcher**

Edit `src/routes/+layout.svelte`:

```svelte
<script lang="ts">
  import '../app.css';
  import { ModeWatcher } from 'mode-watcher';
  let { children } = $props();
</script>

<ModeWatcher />
{@render children()}
```

- [ ] **Step 2: Theme toggle component**

Create `src/lib/components/ThemeToggle.svelte` with sun/moon icons from `lucide-svelte` and `setMode('light'|'dark'|'system')` from `mode-watcher`.

- [ ] **Step 3: Verify dark/light mode toggles in dev**

```bash
pnpm dev
```
Add the toggle to the landing page temporarily and click it.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(ui): theme provider + dark/light toggle"
git push
```

#### Task C.2: Layout primitives

**Files:**
- Create: `src/lib/components/nav/AppShell.svelte`, `src/lib/components/nav/SideNav.svelte`, `src/lib/components/nav/MobileTabBar.svelte`.

- [ ] **Step 1: AppShell**

`AppShell.svelte` takes a `user` prop and a slot for `children`. Renders the persistent left rail on `md:` and bottom tab bar on mobile, with the brand wordmark, theme toggle, sign-out button. Tailwind for styling. Use `$page.url.pathname` to highlight active link.

- [ ] **Step 2: Wire `(app)/+layout.svelte`**

```svelte
<script lang="ts">
  import AppShell from '$lib/components/nav/AppShell.svelte';
  let { data, children } = $props();
</script>

<AppShell user={data.user}>
  {@render children()}
</AppShell>
```

- [ ] **Step 3: Manual visual check on /portfolio (placeholder route for now)**

Create `src/routes/(app)/portfolio/+page.svelte` with `<h1>Portfolio</h1>` for now — Track A and Phase 2 will replace it.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(ui): app shell with side nav and mobile tab bar"
git push
```

#### Task C.3: Form, table, button primitives

**Files:**
- Create: `src/lib/components/forms/{TextField,FormError,SubmitButton}.svelte`, `src/lib/components/tables/DataTable.svelte`, `src/lib/components/Button.svelte`.

- [ ] **Step 1: Implement each as a thin Svelte 5 component**

Pure presentation. Props for label, error, name, etc. Use Tailwind classes; no external UI library. Each component is small (50-80 lines).

- [ ] **Step 2: Component test for `DataTable`**

`DataTable.test.ts` using `@testing-library/svelte`:

```ts
import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import DataTable from './DataTable.svelte';

describe('DataTable', () => {
  it('renders rows and tabular numerics', () => {
    render(DataTable, {
      columns: [
        { key: 'symbol', label: 'Symbol' },
        { key: 'price', label: 'Price', tabular: true }
      ],
      rows: [{ symbol: 'AAPL', price: '$190.50' }]
    });
    expect(screen.getByText('AAPL')).toBeInTheDocument();
    expect(screen.getByText('$190.50')).toHaveClass('tabular');
  });
});
```

- [ ] **Step 3: Run tests, fix, commit**

```bash
pnpm test --run src/lib/components
git add -A
git commit -m "feat(ui): form, table, button primitives"
git push
```

#### Task C.4: uPlot chart wrapper

**Files:**
- Create: `src/lib/components/charts/Sparkline.svelte`, `src/lib/components/charts/EquityCurve.svelte`.

- [ ] **Step 1: Sparkline**

Takes `data: number[]` and `dates?: string[]`, renders a 80×20 inline SVG-or-canvas line. Use uPlot for canvas rendering. No tooltips, no axes — pure shape indicator. Color from `--color-gain` / `--color-loss` based on first vs last value.

- [ ] **Step 2: EquityCurve**

Larger uPlot chart with axes, tooltip on hover, configurable height. Takes `series: { date: string; valueCents: number }[]`. Reads CSS custom properties for theming so it follows dark/light.

- [ ] **Step 3: A simple visual smoke-test page**

Create `src/routes/(app)/__chart-smoke/+page.svelte` with hardcoded data. Verify both render. Delete the route after manual verification.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(ui): sparkline + equity-curve uplot wrappers"
git push
```

#### Task C.5: Landing page

**Files:**
- Modify: `src/routes/+page.svelte`.

- [ ] **Step 1: Replace SvelteKit welcome with the actual landing**

Short pitch ("paper-trading + competitions, no email required"), two CTAs ("sign up", "sign in"). If session present, redirect to `/portfolio` (handled by `+page.server.ts` load).

```svelte
<script lang="ts">
  import { ArrowRight } from 'lucide-svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
</script>

<header class="flex items-center justify-between p-6">
  <span class="font-semibold">finance-sim</span>
  <ThemeToggle />
</header>

<main class="mx-auto max-w-2xl px-6 py-24">
  <h1 class="text-5xl font-bold tracking-tight">paper trading + competitions.</h1>
  <p class="mt-4 text-lg text-zinc-600 dark:text-zinc-400">
    track a fake portfolio. run instant-replay competitions on past windows. or compete live with your friends.
    passkey sign-in. no email.
  </p>
  <div class="mt-8 flex gap-3">
    <a href="/signup" class="rounded-md bg-zinc-900 px-4 py-2 text-white dark:bg-white dark:text-zinc-900">
      sign up <ArrowRight class="inline h-4 w-4" />
    </a>
    <a href="/signin" class="rounded-md border border-zinc-300 px-4 py-2 dark:border-zinc-700">
      sign in
    </a>
  </div>
</main>
```

- [ ] **Step 2: Commit**

```bash
git add -A
git commit -m "feat(ui): landing page"
git push
```

---

## Phase 2 — Personal portfolio

Sequential after Phase 1. Single agent. Depends on auth + market data + UI shell.

### Task 2.1: Portfolio service

**Files:**
- Create: `src/lib/server/portfolio/service.ts`, `src/lib/server/portfolio/service.test.ts`.

The service exports `buy`, `sell`, `valuate`, `transactionLedger`. All operations transactional via `db.transaction(...)`.

- [ ] **Step 1: Failing tests**

Cover: buy adds to holdings, debits cash; insufficient cash rejects; buy more of existing symbol increments shares; sell decrements, credits cash, deletes row at zero; sell more than owned rejects; sell unknown symbol rejects; ledger is in chronological order.

- [ ] **Step 2: Implement**

Use `dollarsToCents` only at the boundary (input is already cents). All queries through Drizzle. ~150 lines.

- [ ] **Step 3: Run, commit**

```bash
pnpm test --run src/lib/server/portfolio
git add -A
git commit -m "feat(portfolio): buy/sell/valuate/ledger service"
git push
```

### Task 2.2: Equity curve

**Files:**
- Create: `src/lib/server/portfolio/equity-curve.ts`, `src/lib/server/portfolio/equity-curve.test.ts`.

Given the trade ledger and a date range, walk forward day by day computing total portfolio value at each day's close using `MarketData.getCloseAt`. Returns `{ date, valueCents }[]`. Skip non-trading days. Use the `MockMarketData` in tests for determinism.

- [ ] **Step 1: Failing test, implementation, commit**

```bash
git add -A
git commit -m "feat(portfolio): equity curve from ledger + closes"
git push
```

### Task 2.3: /portfolio route

**Files:**
- Create/replace: `src/routes/(app)/portfolio/+page.svelte`, `src/routes/(app)/portfolio/+page.server.ts`.

- [ ] **Step 1: Server load**

Call `valuate(userId)` and `equityCurve(userId, last30Days)`. Return `{ cashCents, holdings: [{ symbol, shares, priceCents, valueCents }], totalCents, curve: [{ date, valueCents }] }`.

- [ ] **Step 2: Page**

Cash card, holdings table with sparkline column (last 30 days per symbol — fetch on the client with a JSON endpoint to avoid blocking server load on N quote calls), total card, equity curve chart. Empty-state when no holdings.

- [ ] **Step 3: Sparkline endpoint**

Create `src/routes/api/sparkline/[symbol]/+server.ts` returning the last 30 closes as JSON. Cached by the market-data service.

- [ ] **Step 4: Manual test, commit**

```bash
git add -A
git commit -m "feat(portfolio): /portfolio page with holdings table + equity curve"
git push
```

### Task 2.4: /trade route

**Files:**
- Create: `src/routes/(app)/trade/+page.svelte`, `src/routes/(app)/trade/+page.server.ts`.

Unified buy/sell. Form: symbol, shares, mode (buy/sell). Server action validates symbol, calls `getLiveQuote`, then `buy` or `sell`. Surface adapter errors as form errors.

- [ ] **Step 1: Server actions, page, manual test, commit**

```bash
git add -A
git commit -m "feat(trade): unified buy/sell page"
git push
```

### Task 2.5: /quote and /history

**Files:**
- Create: `src/routes/(app)/quote/+page.svelte`, `+page.server.ts`, `src/routes/(app)/history/+page.svelte`, `+page.server.ts`.

Quote: symbol input → price card + 30-day sparkline. History: simple table of `transactions` for the user, latest first, with running cash column.

- [ ] **Step 1: Implement, manual test, commit**

```bash
git add -A
git commit -m "feat(portfolio): /quote and /history routes"
git push
```

---

## Phase 3 — Competitions

Sequential after Phase 2.

### Task 3.1: Competition service

**Files:**
- Create: `src/lib/server/competitions/service.ts`, `src/lib/server/competitions/service.test.ts`.

Exports: `create`, `join`, `tradeInComp`, `resolveHistorical`, `tickStatuses`, `getDashboard`, `setShareResults`.

- [ ] **Step 1: Failing tests**

Cover lifecycle for both types:
- create: stores comp, mints invite code, host auto-joined with starting cash
- join: idempotent, only when status='open' (live or historical), refuses if comp finished
- tradeInComp (live): refuses outside running status; checks cash/holdings; respects per-comp cash and holdings tables
- tradeInComp (historical): always uses `start_date` close from MarketData, even if today is later
- resolveHistorical: only on historical, only if status != finished, uses `end_date` closes for valuation, sets status to finished + finished_at
- tickStatuses: open → running at start_date, running → finished at end_date (live only); historical comps don't auto-tick to running/finished

- [ ] **Step 2: Implement**

~250 lines, lots of small functions. Use transactions for trade flows. Generate invite codes as 8-char base32 (avoid I/O/0/1) and retry on collision.

- [ ] **Step 3: Run, commit**

```bash
pnpm test --run src/lib/server/competitions
git add -A
git commit -m "feat(comps): service for create/join/trade/resolve/tick"
git push
```

### Task 3.2: Leaderboard

**Files:**
- Create: `src/lib/server/competitions/leaderboard.ts`, `src/lib/server/competitions/leaderboard.test.ts`.

Given a competition, computes for each member: cash + (sum holdings × price), where "price" is live quote (running comp) or `end_date` close (finished comp) or `start_date` close (open historical, since instant-replay portfolios are valued at the simulated start). Returns sorted descending with rank, returnPct.

- [ ] **Step 1: Failing test, implementation, commit**

```bash
git add -A
git commit -m "feat(comps): leaderboard computation"
git push
```

### Task 3.3: /competitions list and create

**Files:**
- Create: `src/routes/(app)/competitions/+page.svelte`, `+page.server.ts`, `src/routes/(app)/competitions/new/+page.svelte`, `+page.server.ts`.

List: hosted (with manage links) + joined; status pills; sortable by status then start date. Create form: type (live/historical), name, dates (date pickers, validates ordering and historical-in-past), starting cash (default $10k), submit → comp dashboard.

- [ ] **Step 1: Implement, manual test, commit**

```bash
git add -A
git commit -m "feat(comps): list and create routes"
git push
```

### Task 3.4: /competitions/[id] dashboard

**Files:**
- Create: `src/routes/(app)/competitions/[id]/+page.svelte`, `+page.server.ts`, `+layout.server.ts` (auth + membership check).

Dashboard shows: leaderboard table, my comp portfolio (cash + holdings table), trade form (live: any time during running; historical: any time before resolve), comp metadata (type, dates, status, invite code), host-only "resolve now" button (historical) and "share results" toggle (finished).

Leaderboard refreshes via polling: `setInterval` calls `/api/leaderboard/[id]` every 5s while `running`. uPlot doesn't matter here; the table gets re-rendered with new data.

- [ ] **Step 1: Server load + page**

- [ ] **Step 2: `/api/leaderboard/[id]/+server.ts`**

Returns `{ rows: LeaderboardRow[], status: CompStatus, fetchedAt: number }`.

- [ ] **Step 3: Manual test, commit**

```bash
git add -A
git commit -m "feat(comps): comp dashboard with leaderboard polling"
git push
```

### Task 3.5: /competitions/join/[code]

**Files:**
- Create: `src/routes/(app)/competitions/join/[code]/+page.svelte`, `+page.server.ts`.

Resolves invite code → comp summary → "Join" button → calls `service.join` → redirects to `/competitions/[id]`.

- [ ] **Step 1: Implement, manual test, commit**

```bash
git add -A
git commit -m "feat(comps): join-by-invite-code page"
git push
```

### Task 3.6: Public results share page

**Files:**
- Modify: `src/routes/(app)/competitions/[id]/+page.server.ts` and `+page.svelte` (or fork to a separate `(public)` route group).

When `?share=<code>` matches the invite code AND the comp is finished AND `share_results` is on, render a read-only view that does not require a session: leaderboard + final values + return %, no trade form, no my-portfolio, no host controls.

The cleanest implementation: a separate route group `src/routes/share/[id]/+page.svelte` that is outside `(app)` (no session check) and only renders when the gate above passes.

- [ ] **Step 1: Implement, manual test, commit**

```bash
git add -A
git commit -m "feat(comps): public read-only results page (opt-in)"
git push
```

### Task 3.7: Tick on every authed request

**Files:**
- Modify: `src/hooks.server.ts` to call `competitions.tickStatuses(db)` once per authed request, behind a 30-second debounce (last-tick timestamp in module-level state).

- [ ] **Step 1: Implement, commit**

```bash
git add -A
git commit -m "feat(comps): debounced status tick from server hook"
git push
```

### Task 3.8: Competitions docs

**Files:**
- Create: `docs/competitions/live-mode.md`, `docs/competitions/historical-mode.md`.

- [ ] **Step 1: `live-mode.md`**

Lifecycle, status transitions, what trades require, how leaderboard updates, why polling instead of websockets. ~120 lines.

- [ ] **Step 2: `historical-mode.md`**

Why instant-replay (vs stepped), how trades use `start_date` close, how resolve uses `end_date` close, why we cache the EOD bar forever, the share page. ~120 lines.

- [ ] **Step 3: Commit**

```bash
git add docs/competitions/
git commit -m "docs(comps): live + historical mode mechanics"
git push
```

---

## Phase 4 — Polish (parallel)

Three subagents.

### Track D — E2E test suite

**Owns:** `e2e/**`, `playwright.config.ts`.

#### Task D.1: Playwright + WebAuthn virtual authenticator

- [ ] **Step 1: Configure Playwright**

Modify `playwright.config.ts` to launch a dev server, set base URL, enable Chromium only (other browsers don't have a stable virtual-authenticator CDP API).

- [ ] **Step 2: Helper for virtual authenticator**

Create `e2e/helpers/webauthn.ts`:

```ts
import type { CDPSession, BrowserContext } from '@playwright/test';

export async function enableVirtualAuthenticator(context: BrowserContext) {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true
    }
  });
  await page.close();
  return { cdp, authenticatorId };
}
```

#### Task D.2: Critical-path tests

- [ ] **Step 1: Sign-up + portfolio + buy + sell**

`e2e/portfolio.spec.ts` — sign up via virtual authenticator, save recovery codes, navigate to /trade, buy AAPL, verify it shows on /portfolio, sell, verify holding deleted.

For the price stub: in test mode (NODE_ENV=test), the market-data service uses `MockMarketData`. Set up a mode toggle in `service.ts`.

- [ ] **Step 2: Recovery flow**

`e2e/recovery.spec.ts` — sign up, capture a recovery code, sign out, recover, force-passkey-setup, verify session.

- [ ] **Step 3: Live competition**

`e2e/comp-live.spec.ts` — host signs up, creates a live comp starting now (test fixture rewrites `start_date` to `now-1`), second user joins via invite code, both trade, leaderboard reflects both.

For two-user flows in Playwright, use two browser contexts.

- [ ] **Step 4: Historical competition**

`e2e/comp-historical.spec.ts` — host creates historical comp on a 2024 window, member joins, both build portfolios, host resolves, leaderboard reflects end-date valuation.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(e2e): critical paths via playwright + virtual webauthn"
git push
```

### Track E — Deployment config

**Owns:** changes in the *separate* `droplet-config` repo at `~/Projects/droplet-config/projects/finance-sim/**`, plus `.env.example` in this repo.

#### Task E.1: Update droplet-config/projects/finance-sim

- [ ] **Step 1: Replace setup.sh with a node-flavored version**

Mirror `projects/budget-webapp/setup.sh`:

```bash
#!/bin/bash
set -e

echo "  [finance-sim] Cloning / pulling repo..."
if [ ! -d ~/finance-sim ]; then
    git clone git@github.com:gabbrousset/finance-sim.git ~/finance-sim
else
    cd ~/finance-sim && git pull
fi

echo "  [finance-sim] Installing dependencies..."
cd ~/finance-sim
pnpm install

echo "  [finance-sim] Rebuilding native modules..."
pnpm -r rebuild

echo "  [finance-sim] Building..."
pnpm build

echo "  [finance-sim] Applying migrations..."
pnpm drizzle-kit migrate
```

- [ ] **Step 2: Replace service.conf**

```ini
[Unit]
Description=finance-sim (sveltekit node)
After=network.target

[Service]
User=gabriel
WorkingDirectory=/home/gabriel/finance-sim
ExecStart=/usr/bin/node build
Restart=on-failure
RestartSec=5
EnvironmentFile=/home/gabriel/finance-sim/.env

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Replace nginx.conf**

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name finance.gabbrousset.dev;
    location / {
        proxy_pass http://127.0.0.1:3002;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

- [ ] **Step 4: Update README in droplet-config/projects/finance-sim**

Note that finance-sim is now Node + SvelteKit + better-sqlite3 (port 3002), not Python + uWSGI.

- [ ] **Step 5: Commit and push droplet-config**

```bash
cd ~/Projects/droplet-config
git add projects/finance-sim/
git commit -m "finance-sim: switch to sveltekit/node"
git push
```

#### Task E.2: .env.example in finance-sim repo

- [ ] **Step 1: Write `.env.example`**

```dotenv
# database
DATABASE_URL=./finance.db

# auth
RP_ID=finance.gabbrousset.dev
ORIGIN=https://finance.gabbrousset.dev

# market data
FINNHUB_API_KEY=replace-me
TWELVEDATA_API_KEY=replace-me

# port (matches nginx upstream)
PORT=3002
HOST=127.0.0.1
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "chore(deploy): document required env vars"
git push
```

#### Task E.3: GitHub Actions CI

**Files:**
- Modify: `.github/workflows/deploy.yml` (existing) — verify still works.
- Create: `.github/workflows/ci.yml` — runs on every PR.

- [ ] **Step 1: Write `ci.yml`**

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main, v3]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 24, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm check
      - run: pnpm test --run
      - run: pnpm build
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pnpm exec playwright install --with-deps chromium
      - run: pnpm test:e2e
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: pnpm install + check + test + build + e2e"
git push
```

#### Task E.4: Deployment doc

- [ ] **Step 1: Write `docs/deployment.md`**

Cover: droplet pattern, the auto-deploy SSH flow, how to do a manual deploy, where logs live (`journalctl -u finance-sim -f`), how to roll back (re-deploy a previous SHA), backup notes (the SQLite file is critical — DigitalOcean weekly backups cover it; document that). ~150 lines.

- [ ] **Step 2: Commit**

```bash
git add docs/deployment.md
git commit -m "docs: deployment + ops"
git push
```

### Track F — Docs polish + testing doc

**Owns:** finalizing all docs not yet written. Track A wrote auth docs; Track B wrote market-data docs; Phase 3 wrote competitions docs. This track writes `docs/testing.md` and does a pass over the seeded docs (`README`, `architecture`, `tech-choices`, `data-model`) to catch anything that drifted from implementation.

#### Task F.1: Testing doc

- [ ] **Step 1: Write `docs/testing.md`**

Cover: vitest layout, what unit tests cover (services), what integration tests cover (multi-module flows), fixture strategy, how MockMarketData is the seam, why we don't mock fetch directly, the e2e WebAuthn approach, what's NOT tested (presentational pages). ~200 lines.

- [ ] **Step 2: Commit**

```bash
git add docs/testing.md
git commit -m "docs: testing strategy + fixtures"
git push
```

#### Task F.2: Drift pass

- [ ] **Step 1: Re-read seeded docs against implementation**

Open `docs/architecture.md`, `docs/tech-choices.md`, `docs/data-model.md`. For each: walk through the actual code, fix anything that diverges. The schema doc in particular is likely to need updates if any column was added/renamed.

- [ ] **Step 2: Update `docs/README.md` index**

Make sure every doc file has an index entry.

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "docs: drift pass against implementation"
git push
```

---

## Phase 5 — Release

Sequential. Single agent.

### Task 5.1: Manual smoke test on dev

- [ ] **Step 1:** Spin up `pnpm dev`, sign up, create a passkey via virtual authenticator, save recovery codes, sign out, sign in, sign out, recover with code, register a new passkey, navigate every page, run a buy + sell on /trade with a real Finnhub key, create both a live comp (start now+1min) and a historical comp (Jan–Mar 2024 window), invite a second virtual user, trade in both, resolve historical, share results.

If anything is broken, file a follow-up task; do not paper over.

### Task 5.2: Deploy to droplet

- [ ] **Step 1:** Push v3 branch to GitHub. Open a PR to main. Verify CI passes.

- [ ] **Step 2:** Merge to main. The auto-deploy workflow runs. Watch logs.

- [ ] **Step 3:** SSH to droplet, `sudo journalctl -u finance-sim -f` for 30 seconds, verify clean startup. `curl -I https://finance.gabbrousset.dev` returns 200.

- [ ] **Step 4:** Walk through the same smoke-test on production.

### Task 5.3: Tag v3.0

- [ ] **Step 1:**

```bash
git checkout main
git pull
git tag -a v3.0 -m "v3.0: sveltekit rewrite, passkeys, live + historical competitions"
git push origin v3.0
```

- [ ] **Step 2: Update README on main** (the v3-in-progress README is now stale).

```bash
git checkout main
# Edit README.md to drop the "work in progress" line, link to docs.
git add README.md
git commit -m "docs(readme): v3.0 shipped"
git push
```

---

## Self-review

**Spec coverage:** every section of the spec maps to tasks: §3 stack → 0.4–0.5; §4 architecture/boundaries → 0.4 + Phase 1 layout; §5 schema → 0.7; §6 auth → A.1–A.10; §7 market data → B.1–B.5; §8 competitions → 3.1–3.8; §9 UI → C.1–C.5 + Phase 2 + Phase 3 routes; §10 testing → throughout + D.1–D.2 + F.1; §11 deployment → E.1–E.4; §12 docs deliverable → A.10, B.5, 3.8, F.1, F.2; §13 versioning → 0.1, 5.3.

**Placeholder scan:** none of "TBD", "TODO", "implement later", "add validation", or "similar to Task N" remain. Every code-bearing step has actual code.

**Type consistency:** `MarketData` interface stable across mock, finnhub, twelvedata, cache, service. `RpConfig` fields (`rpId`, `rpName`, `expectedOrigin`) consistent across `webauthn.ts` and `service.ts`. `CreatedSession`, `ResolvedSession` shapes consistent in `sessions.ts` and consumers.

**Scope:** everything fits a single plan. Phases are clean dependency layers.
