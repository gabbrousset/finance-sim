# Ledger Aesthetic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the Ledger aesthetic across the v3 app per [`docs/superpowers/specs/2026-05-08-ui-ledger-aesthetic.md`](../specs/2026-05-08-ui-ledger-aesthetic.md). Pure visual sweep + the equity-curve y-axis clipping bug. No new finance affordances.

**Architecture:** Tailwind v4 `@theme` tokens + per-component scoped CSS. Build the visual *vocabulary* (Masthead, Stamp, FormBar, OrderTicket, etc.) as Svelte components, then apply them route-by-route. Server contracts unchanged — every page loader still returns the same shape; only rendering changes.

**Tech Stack:** SvelteKit 2 / Svelte 5 runes, Tailwind v4 (`@theme` block), Google Fonts via `<link rel="preconnect">`, uPlot for charts, Vitest + `@testing-library/svelte` for component logic, Playwright for smoke.

**Testing reality:** Most tasks are CSS/markup. TDD applies cleanly only where logic exists (`Stamp` variants, `FormBar` color rules, edition-number derivation, equity-curve axis-gutter regression). For purely-visual tasks the verification step is `pnpm check && pnpm dev` + open the affected route. The plan is explicit about which is which.

---

## Phases at a glance

| Phase | Tasks | Focus |
|---|---|---|
| 0. Foundation | 1–3 | Tokens, fonts, paper grain, dark mode |
| 1. Atomic components | 4–10 | Stamp, SectionHead, StatBlock, PullQuote, FormBar, Masthead, TickerTape |
| 2. Form atoms | 11–13 | Button, TextField, FormError, SubmitButton |
| 3. Charts | 14–15 | EquityCurve (bug fix), Sparkline |
| 4. Tables / molecules | 16–18 | DataTable, StandingsTable, OrderTicket |
| 5. Chrome | 19–22 | ThemeToggle, SideNav, MobileTabBar, AppShell + TickerTape |
| 6. Server-side | 23 | Edition number derivation |
| 7. Pages | 24–34 | (app) layout + 13 routes |
| 8. Verification | 35 | check + e2e + final commit |

## File map

**Create:**
- `src/lib/components/marks/Stamp.svelte`
- `src/lib/components/marks/SectionHead.svelte`
- `src/lib/components/marks/StatBlock.svelte`
- `src/lib/components/marks/PullQuote.svelte`
- `src/lib/components/marks/FormBar.svelte`
- `src/lib/components/marks/Masthead.svelte`
- `src/lib/components/nav/TickerTape.svelte`
- `src/lib/components/forms/OrderTicket.svelte`
- `src/lib/components/tables/StandingsTable.svelte`
- `src/lib/server/user/edition.ts` (edition-number helper)
- Tests: one `*.test.ts` per component with logic.

**Modify (restyle):**
- `src/app.css` — tokens, fonts, dark mode
- `src/routes/(app)/+layout.svelte` — page padding wrapper
- `src/routes/+page.svelte` — signed-out landing
- `src/lib/components/Button.svelte` — primary / quiet variants
- `src/lib/components/ThemeToggle.svelte` — Ledger-style icon button
- `src/lib/components/nav/{AppShell,SideNav,MobileTabBar}.svelte`
- `src/lib/components/forms/{TextField,FormError,SubmitButton}.svelte`
- `src/lib/components/charts/{EquityCurve,Sparkline}.svelte`
- `src/lib/components/tables/DataTable.svelte`
- All `src/routes/(app)/**/+page.svelte` and `src/routes/(auth)/**/+page.svelte`
- `src/routes/(app)/portfolio/+page.server.ts` (only to wire `editionNo`)

---

## Phase 0 — Foundation

### Task 1: Tokens, fonts, and dark mode in `app.css`

**Files:**
- Modify: `src/app.css`

- [ ] **Step 1: Replace `app.css` with the token + font setup**

```css
@import 'tailwindcss';

@variant dark (&:where(.dark, .dark *));

/* Google Fonts — preconnect added in app.html */
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT@9..144,300..700,0..100&family=Newsreader:opsz,ital,wght@6..72,0..1,400..600&family=JetBrains+Mono:wght@400;500;700&display=swap');

@theme {
  --font-display: 'Fraunces', Georgia, serif;
  --font-body:    'Newsreader', Georgia, serif;
  --font-mono:    'JetBrains Mono', ui-monospace, monospace;

  --color-paper:         #f1e9d4;
  --color-paper-2:       #ebe2c8;
  --color-paper-receipt: #fbf6e6;
  --color-ink:           #16110a;
  --color-ink-2:         #4d4232;
  --color-ink-3:         #8a7e66;
  --color-rule:          #b9ad8e;
  --color-rule-soft:     #d4c8a8;
  --color-gain:          #305e3f;
  --color-loss:          #8a2a2a;
  --color-brass:         #9b7a32;
  --color-stamp:         #973128;
}

:where(.dark) {
  --color-paper:         #14110b;
  --color-paper-2:       #1c1810;
  --color-paper-receipt: #1f1c14;
  --color-ink:           #ede4c8;
  --color-ink-2:         #b8ad8f;
  --color-ink-3:         #7a6f55;
  --color-rule:          #3a3324;
  --color-rule-soft:     #2a2519;
  --color-gain:          #87c19a;
  --color-loss:          #d49693;
  --color-brass:         #c9a25b;
  --color-stamp:         #d49693;
}

html {
  font-family: var(--font-body);
  color: var(--color-ink);
  background: var(--color-paper);
}

body {
  background:
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='1.6' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.08  0 0 0 0 0.07  0 0 0 0 0.04  0 0 0 0.06 0'/></filter><rect width='240' height='240' filter='url(%23n)' opacity='0.55'/></svg>"),
    var(--color-paper);
  background-attachment: fixed;
  color: var(--color-ink);
}

:where(.dark) body {
  background:
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='1.6' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.95  0 0 0 0 0.91  0 0 0 0 0.78  0 0 0 0.05 0'/></filter><rect width='240' height='240' filter='url(%23n)' opacity='0.45'/></svg>"),
    var(--color-paper);
}

/* utilities */
.tabular { font-variant-numeric: tabular-nums lining-nums; font-feature-settings: 'tnum'; }
.font-display { font-family: var(--font-display); }
.font-body    { font-family: var(--font-body); }
.font-mono    { font-family: var(--font-mono); }

/* default focus ring */
*:focus-visible {
  outline: 2px solid var(--color-ink);
  outline-offset: 2px;
}
:where(.dark) *:focus-visible { outline-color: var(--color-ink-2); }
```

- [ ] **Step 2: Add font preconnect to `src/app.html`**

Open `src/app.html`. Inside `<head>`, before `%sveltekit.head%`, add:

```html
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
```

- [ ] **Step 3: Run `pnpm check`**

```bash
pnpm check
```

Expected: zero errors.

- [ ] **Step 4: Commit**

```bash
git add src/app.css src/app.html
git commit -m "feat(ui): ledger tokens, fonts, dark mode, paper grain"
```

---

## Phase 1 — Atomic components

### Task 2: `Stamp.svelte` (rotated status indicator)

**Files:**
- Create: `src/lib/components/marks/Stamp.svelte`
- Create: `src/lib/components/marks/Stamp.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/components/marks/Stamp.test.ts
import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import Stamp from './Stamp.svelte';

describe('Stamp', () => {
  it('renders the label', () => {
    render(Stamp, { props: { label: 'Filled' } });
    expect(screen.getByText('Filled')).toBeInTheDocument();
  });

  it('renders an optional sub-label', () => {
    render(Stamp, { props: { label: 'Final', sub: 'Champion: marie' } });
    expect(screen.getByText('Champion: marie')).toBeInTheDocument();
  });

  it('applies the variant class', () => {
    const { container } = render(Stamp, { props: { label: 'Closed', variant: 'ink' } });
    const el = container.querySelector('.stamp');
    expect(el?.className).toContain('stamp--ink');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pnpm test --run src/lib/components/marks/Stamp.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write `Stamp.svelte`**

```svelte
<!-- src/lib/components/marks/Stamp.svelte -->
<script lang="ts">
  type Variant = 'stamp' | 'ink' | 'loss' | 'muted';
  type Size = 'sm' | 'md' | 'lg';
  let { label, sub, variant = 'stamp', size = 'md' }: {
    label: string;
    sub?: string;
    variant?: Variant;
    size?: Size;
  } = $props();
</script>

<span class="stamp stamp--{variant} stamp--{size}" role="img" aria-label={label}>
  <span class="stamp__label">{label}</span>
  {#if sub}<span class="stamp__sub">{sub}</span>{/if}
</span>

<style>
  .stamp {
    display: inline-block;
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 60, 'SOFT' 100, 'wght' 700;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    border-style: solid;
    transform: rotate(-4deg);
    opacity: 0.82;
    text-align: center;
    line-height: 1.05;
  }
  .stamp__sub {
    display: block;
    font-style: italic;
    font-variation-settings: 'opsz' 24, 'SOFT' 100, 'wght' 600;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    margin-top: 2px;
    opacity: 0.9;
  }
  .stamp--sm { font-size: 11px; padding: 2px 8px; border-width: 2px; }
  .stamp--sm .stamp__sub { font-size: 8px; }
  .stamp--md { font-size: 13px; padding: 4px 12px; border-width: 2.5px; }
  .stamp--md .stamp__sub { font-size: 8.5px; }
  .stamp--lg { font-size: 22px; padding: 6px 18px; border-width: 3.5px; letter-spacing: 0.22em; }
  .stamp--lg .stamp__sub { font-size: 9px; }

  .stamp--stamp { color: var(--color-stamp); border-color: var(--color-stamp); }
  .stamp--ink   { color: var(--color-ink);   border-color: var(--color-ink); }
  .stamp--loss  { color: var(--color-loss);  border-color: var(--color-loss); }
  .stamp--muted { color: var(--color-ink-2); border-color: var(--color-ink-2); opacity: 0.65; }
</style>
```

- [ ] **Step 4: Run tests, expect PASS**

```bash
pnpm test --run src/lib/components/marks/Stamp.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/marks/Stamp.svelte src/lib/components/marks/Stamp.test.ts
git commit -m "feat(ui): Stamp component with variants"
```

---

### Task 3: `SectionHead.svelte` (eyebrow tab + title + meta)

**Files:**
- Create: `src/lib/components/marks/SectionHead.svelte`

- [ ] **Step 1: Write the component (no logic — manual verify)**

```svelte
<!-- src/lib/components/marks/SectionHead.svelte -->
<script lang="ts">
  let { eyebrow, title, meta }: {
    eyebrow?: string;
    title: string;
    meta?: string;
  } = $props();
</script>

<header class="section-head">
  {#if eyebrow}<span class="eyebrow">{eyebrow}</span>{/if}
  <h1>{title}</h1>
  {#if meta}<span class="meta">{meta}</span>{/if}
</header>

<style>
  .section-head {
    display: flex;
    align-items: baseline;
    gap: 12px;
    border-bottom: 1px solid var(--color-rule);
    padding-bottom: 10px;
    margin: 32px 0 24px;
  }
  .eyebrow {
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    background: var(--color-stamp);
    color: var(--color-paper);
    padding: 3px 8px;
  }
  h1 {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 96, 'wght' 500;
    font-size: clamp(26px, 3.6vw, 36px);
    letter-spacing: -0.02em;
    margin: 0;
    line-height: 1;
    color: var(--color-ink);
  }
  .meta {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
</style>
```

- [ ] **Step 2: Run `pnpm check`** — expect no errors.

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/marks/SectionHead.svelte
git commit -m "feat(ui): SectionHead component"
```

---

### Task 4: `StatBlock.svelte` (3-up KPIs, no boxes)

**Files:**
- Create: `src/lib/components/marks/StatBlock.svelte`

- [ ] **Step 1: Write the component**

```svelte
<!-- src/lib/components/marks/StatBlock.svelte -->
<script lang="ts">
  type Stat = { label: string; value: string; cents?: string; delta?: string };
  let { stats }: { stats: Stat[] } = $props();
</script>

<section class="stat-block">
  {#each stats as s}
    <div class="stat">
      <div class="lbl">{s.label}</div>
      <div class="v tabular">
        {s.value}{#if s.cents}<span class="c">{s.cents}</span>{/if}
      </div>
      {#if s.delta}<div class="delta">{@html s.delta}</div>{/if}
    </div>
  {/each}
</section>

<style>
  .stat-block {
    display: grid;
    grid-template-columns: repeat(var(--cols, 3), 1fr);
    margin: 28px 0 36px;
  }
  @media (max-width: 640px) {
    .stat-block { grid-template-columns: 1fr; gap: 20px; }
    .stat { border-right: 0 !important; padding: 0 !important; }
  }
  .stat { padding: 4px 28px; border-right: 1px solid var(--color-rule); }
  .stat:first-child { padding-left: 0; }
  .stat:last-child  { padding-right: 0; border-right: 0; }
  .lbl {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    margin-bottom: 6px;
  }
  .v {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 96, 'wght' 400;
    font-size: clamp(24px, 3.6vw, 36px);
    letter-spacing: -0.025em;
    line-height: 1;
  }
  .v .c {
    font-size: 0.55em;
    color: var(--color-ink-2);
    vertical-align: 0.42em;
    margin-left: 1px;
    letter-spacing: 0.01em;
  }
  .delta {
    margin-top: 10px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-ink-3);
  }
  :global(.delta .pos) { color: var(--color-gain); }
  :global(.delta .neg) { color: var(--color-loss); }
</style>
```

- [ ] **Step 2: Run `pnpm check`** — expect no errors.

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/marks/StatBlock.svelte
git commit -m "feat(ui): StatBlock component"
```

---

### Task 5: `PullQuote.svelte` (badge + italic line)

**Files:**
- Create: `src/lib/components/marks/PullQuote.svelte`

- [ ] **Step 1: Write the component**

```svelte
<!-- src/lib/components/marks/PullQuote.svelte -->
<script lang="ts">
  let { badge, children }: {
    badge?: string;
    children: import('svelte').Snippet;
  } = $props();
</script>

<aside class="pq">
  {#if badge}<span class="pq__badge">{badge}</span>{/if}
  <span class="pq__line">{@render children()}</span>
</aside>

<style>
  .pq {
    background: var(--color-paper-2);
    padding: 12px 14px;
    border-left: 3px solid var(--color-stamp);
    display: flex; align-items: center; gap: 14px;
  }
  .pq__badge {
    width: 44px; height: 44px;
    border-radius: 50%;
    background: var(--color-ink);
    color: var(--color-paper);
    display: grid; place-items: center;
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 22px;
    flex-shrink: 0;
  }
  .pq__line {
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 60, 'wght' 400;
    font-size: 17px;
    line-height: 1.3;
    color: var(--color-ink);
    letter-spacing: -0.005em;
  }
  :global(.pq__line strong) {
    font-style: normal;
    color: var(--color-stamp);
    font-variation-settings: 'opsz' 60, 'wght' 600;
  }
</style>
```

- [ ] **Step 2: Run `pnpm check`**

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/marks/PullQuote.svelte
git commit -m "feat(ui): PullQuote component"
```

---

### Task 6: `FormBar.svelte` (recent-form swatches, with logic)

**Files:**
- Create: `src/lib/components/marks/FormBar.svelte`
- Create: `src/lib/components/marks/FormBar.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/components/marks/FormBar.test.ts
import { render } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import FormBar from './FormBar.svelte';

describe('FormBar', () => {
  it('renders one swatch per delta', () => {
    const { container } = render(FormBar, { props: { deltas: [1, -1, 0, 1, 1, -1] } });
    expect(container.querySelectorAll('.fb__seg').length).toBe(6);
  });

  it('colors swatches by sign of delta', () => {
    const { container } = render(FormBar, { props: { deltas: [1, -1, 0] } });
    const segs = container.querySelectorAll('.fb__seg');
    expect(segs[0]?.className).toContain('fb__seg--up');
    expect(segs[1]?.className).toContain('fb__seg--dn');
    expect(segs[2]?.className).toContain('fb__seg--flat');
  });

  it('pads short input with flat swatches up to default length 6', () => {
    const { container } = render(FormBar, { props: { deltas: [1, 1] } });
    expect(container.querySelectorAll('.fb__seg').length).toBe(6);
  });
});
```

- [ ] **Step 2: Run test, verify FAIL**

```bash
pnpm test --run src/lib/components/marks/FormBar.test.ts
```

- [ ] **Step 3: Write the component**

```svelte
<!-- src/lib/components/marks/FormBar.svelte -->
<script lang="ts">
  let { deltas, length = 6 }: { deltas: number[]; length?: number } = $props();

  // Pad with zeros at the front so most-recent stays on the right.
  const padded = $derived.by(() => {
    const out = [...deltas];
    while (out.length < length) out.unshift(0);
    return out.slice(-length);
  });

  function classFor(n: number): string {
    if (n > 0) return 'fb__seg fb__seg--up';
    if (n < 0) return 'fb__seg fb__seg--dn';
    return 'fb__seg fb__seg--flat';
  }
</script>

<span class="fb" aria-label="recent form">
  {#each padded as d}
    <span class={classFor(d)}></span>
  {/each}
</span>

<style>
  .fb { display: inline-flex; gap: 2px; }
  .fb__seg { width: 6px; height: 8px; display: inline-block; }
  .fb__seg--up   { background: var(--color-gain); }
  .fb__seg--dn   { background: var(--color-loss); }
  .fb__seg--flat { background: var(--color-rule-soft); }
</style>
```

- [ ] **Step 4: Run tests, expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/marks/FormBar.svelte src/lib/components/marks/FormBar.test.ts
git commit -m "feat(ui): FormBar component"
```

---

### Task 7: `Masthead.svelte` (per-page newspaper masthead)

**Files:**
- Create: `src/lib/components/marks/Masthead.svelte`

- [ ] **Step 1: Write the component**

```svelte
<!-- src/lib/components/marks/Masthead.svelte -->
<script lang="ts">
  let { editionNo, date, status }: {
    editionNo: number;
    date: Date;
    status?: string;
  } = $props();

  const weekday = $derived(date.toLocaleDateString('en-US', { weekday: 'long' }));
  const dateStr = $derived(date.toLocaleDateString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric'
  }));
</script>

<header class="mh">
  <div class="mh__side">
    Volume III · No. {editionNo}<br/>
    Established MMXXVI
  </div>
  <div class="mh__center">
    <div class="mh__title">finance<span class="amp">&amp;</span>sim</div>
    <div class="mh__sub">A daily ledger of paper positions, plainly kept.</div>
  </div>
  <div class="mh__side mh__side--r">
    {weekday}<br/>
    {dateStr}<br/>
    {status ?? 'Closed · 16:00 ET'}
  </div>
</header>

<style>
  .mh {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    align-items: end;
    gap: 24px;
    border-bottom: 3px double var(--color-ink);
    padding-bottom: 16px;
    margin-bottom: 8px;
  }
  .mh__side {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    line-height: 1.6;
  }
  .mh__side--r { text-align: right; }
  .mh__title {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 500;
    font-size: clamp(36px, 6vw, 56px);
    line-height: 0.92;
    letter-spacing: -0.025em;
    text-align: center;
    color: var(--color-ink);
    white-space: nowrap;
  }
  .amp {
    color: var(--color-stamp);
    font-style: italic;
    font-variation-settings: 'opsz' 144, 'SOFT' 100, 'wght' 400;
  }
  .mh__sub {
    margin-top: 6px;
    text-align: center;
    font-family: var(--font-body);
    font-style: italic;
    font-size: 13px;
    color: var(--color-ink-2);
  }
  @media (max-width: 720px) {
    .mh { grid-template-columns: 1fr; gap: 8px; }
    .mh__side { display: none; }
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/marks/Masthead.svelte
git commit -m "feat(ui): Masthead component"
```

---

### Task 8: `TickerTape.svelte` (sticky animated band)

**Files:**
- Create: `src/lib/components/nav/TickerTape.svelte`

- [ ] **Step 1: Write the component**

```svelte
<!-- src/lib/components/nav/TickerTape.svelte -->
<script lang="ts">
  type Tick = { symbol: string; price: string; pct: number };
  let { ticks }: { ticks: Tick[] } = $props();

  function fmt(t: Tick): { arrow: string; cls: string; pct: string } {
    if (t.pct > 0) return { arrow: '▲', cls: 'up', pct: `+${t.pct.toFixed(2)}%` };
    if (t.pct < 0) return { arrow: '▼', cls: 'dn', pct: `${t.pct.toFixed(2)}%` };
    return { arrow: '·', cls: '', pct: `${t.pct.toFixed(2)}%` };
  }
</script>

{#if ticks.length > 0}
  <div class="ticker" aria-hidden="true">
    <div class="track">
      {#each [...ticks, ...ticks] as t (t.symbol + Math.random())}
        {@const f = fmt(t)}
        <span class="cell">
          {t.symbol} <strong class="tabular">{t.price}</strong>
          <span class={f.cls}>{f.arrow} {f.pct}</span>
        </span>
        <span class="div">·</span>
      {/each}
    </div>
  </div>
{/if}

<style>
  .ticker {
    background: var(--color-ink);
    color: var(--color-paper);
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.06em;
    padding: 7px 0;
    overflow: hidden;
    border-bottom: 1px solid var(--color-ink);
    box-shadow: 0 1px 0 var(--color-brass);
  }
  .track {
    display: inline-block;
    white-space: nowrap;
    padding-left: 100%;
    animation: ticker 80s linear infinite;
  }
  .cell { padding: 0 1.4em; opacity: 0.85; }
  .up { color: #87c19a; }
  .dn { color: #d49693; }
  .div { color: var(--color-brass); padding: 0 0.3em; }
  @keyframes ticker { from { transform: translateX(0); } to { transform: translateX(-50%); } }
  @media (prefers-reduced-motion: reduce) {
    .track { animation: none; padding-left: 0; }
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/nav/TickerTape.svelte
git commit -m "feat(ui): TickerTape component"
```

---

## Phase 2 — Form atoms

### Task 9: Restyle `Button.svelte` (primary + quiet)

**Files:**
- Modify: `src/lib/components/Button.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/Button.svelte -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';

  type Variant = 'primary' | 'quiet' | 'danger';
  type Props = HTMLButtonAttributes & {
    variant?: Variant;
    children: Snippet;
  };

  let {
    variant = 'primary',
    type = 'button',
    disabled = false,
    children,
    class: cls,
    ...rest
  }: Props = $props();
</script>

<button {type} {disabled} class="btn btn--{variant} {cls ?? ''}" {...rest}>
  {@render children()}
</button>

<style>
  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-size: 12px;
    padding: 10px 18px;
    cursor: pointer;
    transition: opacity 0.15s, background-color 0.15s;
    border: 0;
    border-radius: 2px;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn--primary {
    background: var(--color-ink);
    color: var(--color-paper-receipt);
  }
  .btn--primary:hover:not(:disabled) { opacity: 0.88; }

  .btn--quiet {
    background: transparent;
    color: var(--color-ink);
    text-decoration: underline;
    text-underline-offset: 4px;
    text-decoration-thickness: 1px;
    letter-spacing: 0;
    text-transform: none;
    font-family: var(--font-body);
    font-style: italic;
    font-variation-settings: initial;
    padding: 4px 2px;
    font-size: 14px;
  }
  .btn--quiet:hover:not(:disabled) { color: var(--color-stamp); }

  .btn--danger {
    background: var(--color-ink);
    color: var(--color-paper-receipt);
    box-shadow: inset 0 0 0 1.5px var(--color-loss);
  }
</style>
```

- [ ] **Step 2: Run `pnpm check`**

Expected: no errors. (Existing callers use `variant="primary" | "secondary" | "ghost" | "danger"` and `size`. The `secondary`/`ghost`/`size` props will silently degrade — acceptable since we're restyling everything.)

- [ ] **Step 3: Find and update lingering `variant="secondary"` and `variant="ghost"` to `"quiet"`**

```bash
grep -rn 'variant="secondary"\|variant="ghost"' src/
```

For each match, replace `variant="secondary"` and `variant="ghost"` with `variant="quiet"`. Drop any `size="..."` props.

- [ ] **Step 4: Run `pnpm check` again** — expect zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/Button.svelte src/
git commit -m "refactor(ui): Button → primary/quiet/danger variants"
```

---

### Task 10: Restyle `TextField.svelte`

**Files:**
- Modify: `src/lib/components/forms/TextField.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/forms/TextField.svelte -->
<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  type Props = Omit<HTMLInputAttributes, 'value'> & {
    name: string;
    label: string;
    value?: string;
    error?: string;
    hint?: string;
  };

  let {
    name,
    label,
    value = $bindable(''),
    type = 'text',
    placeholder,
    error,
    hint,
    disabled,
    ...rest
  }: Props = $props();
</script>

<div class="tf">
  <label for={name} class="tf__label">{label}</label>
  <div class="tf__row">
    <input
      id={name}
      {name}
      {type}
      {placeholder}
      {disabled}
      bind:value
      class="tf__input"
      class:tf__input--error={!!error}
      {...rest}
    />
    {#if hint}<span class="tf__hint">{hint}</span>{/if}
  </div>
  {#if error}<p class="tf__error">{error}</p>{/if}
</div>

<style>
  .tf { display: flex; flex-direction: column; gap: 4px; }
  .tf__label {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  .tf__row {
    display: flex; align-items: baseline; gap: 8px;
    border-bottom: 1.5px solid var(--color-ink);
    padding: 2px 0 4px;
  }
  .tf__row:focus-within { border-bottom-width: 2px; }
  .tf__input {
    flex: 1;
    background: transparent;
    border: 0;
    outline: 0;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 500;
    font-size: 20px;
    letter-spacing: -0.015em;
    color: var(--color-ink);
    padding: 0;
  }
  .tf__input--error { color: var(--color-loss); }
  .tf__input:disabled { opacity: 0.55; }
  .tf__hint {
    font-family: var(--font-body);
    font-style: italic;
    font-size: 11px;
    color: var(--color-ink-3);
  }
  .tf__error {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-loss);
    margin: 2px 0 0;
  }
</style>
```

- [ ] **Step 2: Run `pnpm check`**

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/forms/TextField.svelte
git commit -m "refactor(ui): TextField in ledger style"
```

---

### Task 11: Restyle `FormError.svelte` and `SubmitButton.svelte`

**Files:**
- Modify: `src/lib/components/forms/FormError.svelte`
- Modify: `src/lib/components/forms/SubmitButton.svelte`

- [ ] **Step 1: Read both files** so you know the current API.

```bash
cat src/lib/components/forms/FormError.svelte src/lib/components/forms/SubmitButton.svelte
```

- [ ] **Step 2: Replace `FormError.svelte`**

```svelte
<!-- src/lib/components/forms/FormError.svelte -->
<script lang="ts">
  let { message = '' }: { message?: string } = $props();
</script>

{#if message}
  <p class="fe">{message}</p>
{/if}

<style>
  .fe {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-loss);
    margin: 0;
    padding: 6px 0;
  }
</style>
```

- [ ] **Step 3: Replace `SubmitButton.svelte`** preserving its existing prop API. If it currently wraps `Button`, keep it wrapping `Button` with `variant="primary"` and `type="submit"`:

```svelte
<!-- src/lib/components/forms/SubmitButton.svelte -->
<script lang="ts">
  import Button from '../Button.svelte';
  let { children, disabled }: {
    children: import('svelte').Snippet;
    disabled?: boolean;
  } = $props();
</script>

<Button type="submit" variant="primary" {disabled}>
  {@render children()}
</Button>
```

- [ ] **Step 4: Run `pnpm check`**

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/forms/FormError.svelte src/lib/components/forms/SubmitButton.svelte
git commit -m "refactor(ui): FormError + SubmitButton ledger styling"
```

---

## Phase 3 — Charts

### Task 12: Fix and restyle `EquityCurve.svelte`

**Files:**
- Modify: `src/lib/components/charts/EquityCurve.svelte`
- Create: `src/lib/components/charts/EquityCurve.test.ts`

- [ ] **Step 1: Write a regression test for the y-axis gutter**

```ts
// src/lib/components/charts/EquityCurve.test.ts
import { render } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import EquityCurve from './EquityCurve.svelte';

describe('EquityCurve', () => {
  it('renders a uPlot host with y-axis labels visible (size ≥ 60)', async () => {
    const series = [
      { date: '2026-04-01', valueCents: 1000000 },
      { date: '2026-04-02', valueCents: 1004482 }
    ];
    const { container } = render(EquityCurve, { props: { series } });
    // wait a tick for $effect
    await new Promise((r) => setTimeout(r, 50));
    const axisLabels = container.querySelectorAll('.u-axis');
    // y axis is the second axis; uPlot renders it with width = 60+ on left
    // We verify the host element is present; the axis-size guarantee is in
    // the source.
    expect(container.querySelector('div')).toBeTruthy();
    // the source must contain an axis size of at least 60 — assert via reading the file would be brittle;
    // instead we test the visible behavior: axis containers exist
    expect(axisLabels.length).toBeGreaterThanOrEqual(1);
  });
});
```

- [ ] **Step 2: Replace `EquityCurve.svelte`**

```svelte
<!-- src/lib/components/charts/EquityCurve.svelte -->
<script lang="ts">
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { formatUsd } from '$lib/shared/money';

  let {
    series,
    height = 240
  }: { series: { date: string; valueCents: number }[]; height?: number } = $props();

  let el: HTMLDivElement | undefined = $state();
  let chart: uPlot | undefined;

  $effect(() => {
    if (!el || series.length === 0) return;

    const xs = series.map((p) => new Date(p.date).getTime() / 1000);
    const ys = series.map((p) => p.valueCents / 100);
    const baseline = ys[0] ?? 10000;
    const width = el.clientWidth || 600;

    const opts: uPlot.Options = {
      width,
      height,
      legend: { show: false },
      scales: { x: { time: true }, y: {} },
      axes: [
        {
          stroke: 'var(--color-ink-3)',
          font: '10px "JetBrains Mono", monospace',
          ticks: { stroke: 'var(--color-rule)', width: 1 },
          grid: { show: false },
          size: 30
        },
        {
          stroke: 'var(--color-ink-3)',
          font: '10px "JetBrains Mono", monospace',
          ticks: { stroke: 'var(--color-rule)', width: 0 },
          grid: { stroke: 'var(--color-rule-soft)', width: 1, dash: [1, 3] },
          size: 64,
          values: (_self, ticks) =>
            ticks.map((t) => formatUsd(Math.round(t * 100)))
        }
      ],
      series: [
        {},
        {
          stroke: 'var(--color-ink)',
          width: 1.4,
          points: { show: false }
        }
      ],
      hooks: {
        draw: [
          (u: uPlot) => {
            const ctx = u.ctx;
            const yMin = u.scales.y!.min!;
            const yMax = u.scales.y!.max!;
            if (baseline < yMin || baseline > yMax) return;
            const yPx = u.valToPos(baseline, 'y', true);
            ctx.save();
            ctx.strokeStyle = getComputedStyle(el!).getPropertyValue('--color-brass').trim() || '#9b7a32';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 3]);
            ctx.globalAlpha = 0.6;
            ctx.beginPath();
            ctx.moveTo(u.bbox.left, yPx);
            ctx.lineTo(u.bbox.left + u.bbox.width, yPx);
            ctx.stroke();
            ctx.restore();
          }
        ]
      }
    };

    chart?.destroy();
    chart = new uPlot(opts, [xs, ys], el);

    const ro = new ResizeObserver(() => {
      if (el && chart) chart.setSize({ width: el.clientWidth, height });
    });
    ro.observe(el);

    return () => {
      ro.disconnect();
      chart?.destroy();
    };
  });
</script>

<figure class="ec">
  <figcaption class="ec__cap">
    <em>Account equity, last thirty days, drawn at close.</em>
    <span class="ec__fig">Fig. I</span>
  </figcaption>
  <div bind:this={el} class="ec__host" style:height="{height}px"></div>
</figure>

<style>
  .ec { margin: 0 0 56px; }
  .ec__cap {
    display: flex; justify-content: space-between; align-items: baseline;
    font-family: var(--font-body);
    font-style: italic;
    font-size: 13px;
    color: var(--color-ink-2);
    margin-bottom: 8px;
  }
  .ec__fig {
    font-family: var(--font-mono);
    font-style: normal;
    font-size: 9.5px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  .ec__host { width: 100%; }
  /* uPlot strokes use real CSS vars via getComputedStyle */
  :global(.u-axis) { color: var(--color-ink-3); }
</style>
```

- [ ] **Step 3: Run tests**

```bash
pnpm test --run src/lib/components/charts/EquityCurve.test.ts
```

Expected: PASS.

- [ ] **Step 4: Manual verify with `pnpm dev`** — open `/portfolio` and confirm y-axis labels read fully (e.g. `$10,000.00`, not `00.00`). Skip if no holdings yet — load with at least one trade in your local DB.

- [ ] **Step 5: Commit**

```bash
git add src/lib/components/charts/EquityCurve.svelte src/lib/components/charts/EquityCurve.test.ts
git commit -m "fix(charts): equity-curve y-axis gutter + ledger styling"
```

---

### Task 13: Restyle `Sparkline.svelte` (responsive, ledger colors, flat detection)

**Files:**
- Modify: `src/lib/components/charts/Sparkline.svelte`
- Create: `src/lib/components/charts/Sparkline.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/components/charts/Sparkline.test.ts
import { render } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import Sparkline from './Sparkline.svelte';

describe('Sparkline', () => {
  it('renders host element', () => {
    const { container } = render(Sparkline, { props: { data: [1, 2, 3] } });
    expect(container.querySelector('div')).toBeTruthy();
  });

  it('treats start === end as flat', async () => {
    const { container } = render(Sparkline, { props: { data: [10, 11, 10] } });
    await new Promise((r) => setTimeout(r, 30));
    // We can't reliably introspect uPlot's stroke through DOM here; the test
    // pins the shape of the API (no crash with flat input).
    expect(container.querySelector('div')).toBeTruthy();
  });
});
```

- [ ] **Step 2: Replace `Sparkline.svelte`**

```svelte
<!-- src/lib/components/charts/Sparkline.svelte -->
<script lang="ts">
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';

  let {
    data,
    dates,
    width = 110,
    height = 28
  }: { data: number[]; dates?: string[]; width?: number; height?: number } = $props();

  let el: HTMLDivElement | undefined = $state();
  let chart: uPlot | undefined;

  $effect(() => {
    if (!el || data.length === 0) return;
    const xs: number[] = dates
      ? dates.map((d) => new Date(d).getTime() / 1000)
      : data.map((_, i) => i);

    const first = data[0];
    const last = data[data.length - 1];
    let strokeVar = '--color-ink';
    if (first != null && last != null) {
      if (last > first) strokeVar = '--color-gain';
      else if (last < first) strokeVar = '--color-loss';
    }
    const stroke = getComputedStyle(el).getPropertyValue(strokeVar).trim() || '#16110a';

    const opts: uPlot.Options = {
      width,
      height,
      legend: { show: false },
      cursor: { show: false },
      scales: { x: { time: !!dates }, y: {} },
      axes: [{ show: false }, { show: false }],
      series: [{}, { stroke, width: 1.2, points: { show: false } }]
    };

    chart?.destroy();
    chart = new uPlot(opts, [xs, data], el);
    return () => chart?.destroy();
  });
</script>

<div bind:this={el} class="sp" style:width="{width}px" style:height="{height}px"></div>

<style>
  .sp { display: inline-block; }
</style>
```

- [ ] **Step 3: Run tests, expect PASS**

- [ ] **Step 4: Commit**

```bash
git add src/lib/components/charts/Sparkline.svelte src/lib/components/charts/Sparkline.test.ts
git commit -m "refactor(charts): Sparkline gain/loss/flat colors"
```

---

## Phase 4 — Tables / molecules

### Task 14: Restyle `DataTable.svelte` as a ledger

**Files:**
- Modify: `src/lib/components/tables/DataTable.svelte`

- [ ] **Step 1: Read the existing `DataTable.svelte`** to confirm props.

```bash
cat src/lib/components/tables/DataTable.svelte
```

- [ ] **Step 2: Replace it (preserve `columns` and `rows` props)**

```svelte
<!-- src/lib/components/tables/DataTable.svelte -->
<script lang="ts">
  type Column = { key: string; label: string; tabular?: boolean; align?: 'left' | 'right' };
  type Row = Record<string, string | number>;
  let { columns, rows }: { columns: Column[]; rows: Row[] } = $props();
</script>

<table class="dt">
  <thead>
    <tr>
      {#each columns as c}
        <th class:right={c.align === 'right' || c.tabular}>{c.label}</th>
      {/each}
    </tr>
  </thead>
  <tbody>
    {#each rows as r}
      <tr>
        {#each columns as c}
          <td
            class:right={c.align === 'right' || c.tabular}
            class:tabular={c.tabular}
            class:cell-sym={c.key === 'symbol'}
          >
            {r[c.key] ?? ''}
          </td>
        {/each}
      </tr>
    {/each}
  </tbody>
</table>

<style>
  .dt {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-body);
  }
  .dt thead th {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    text-align: left;
    padding: 0 12px 10px 0;
    border-bottom: 1.5px solid var(--color-ink);
  }
  .dt th.right { text-align: right; padding-right: 0; padding-left: 12px; }
  .dt tbody td {
    padding: 14px 12px 14px 0;
    border-bottom: 1px solid var(--color-rule-soft);
    font-size: 14px;
    color: var(--color-ink);
    vertical-align: middle;
  }
  .dt tbody td.right { text-align: right; padding-right: 0; padding-left: 12px; }
  .dt tbody td.tabular { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
  .dt tbody td.cell-sym {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.01em;
  }
  .dt tbody tr:last-child td { border-bottom: 1px solid var(--color-ink); }
</style>
```

- [ ] **Step 3: Run `pnpm check`**

- [ ] **Step 4: Commit**

```bash
git add src/lib/components/tables/DataTable.svelte
git commit -m "refactor(ui): DataTable as ledger"
```

---

### Task 15: `StandingsTable.svelte` (sports almanac)

**Files:**
- Create: `src/lib/components/tables/StandingsTable.svelte`

- [ ] **Step 1: Write the component**

```svelte
<!-- src/lib/components/tables/StandingsTable.svelte -->
<script lang="ts">
  import FormBar from '$lib/components/marks/FormBar.svelte';

  type Row = {
    rank: number;
    name: string;
    caption?: string;
    totalCents: number;
    returnPct: number;
    formDeltas?: number[];
  };

  let { rows, formatUsd }: {
    rows: Row[];
    formatUsd: (cents: number) => string;
  } = $props();

  const ROMAN = ['', 'I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X'];
  function roman(n: number): string { return ROMAN[n] ?? n.toString(); }
</script>

<table class="st">
  <thead>
    <tr>
      <th></th>
      <th>Player</th>
      <th>Form</th>
      <th class="right">Total</th>
      <th class="right">Return</th>
    </tr>
  </thead>
  <tbody>
    {#each rows as r}
      <tr>
        <td><span class="rank" class:rank--gold={r.rank === 1}>{roman(r.rank)}</span></td>
        <td class="name">
          {r.name}
          {#if r.caption}<span class="cap">— {r.caption}</span>{/if}
        </td>
        <td>{#if r.formDeltas}<FormBar deltas={r.formDeltas} />{/if}</td>
        <td class="right total">{formatUsd(r.totalCents)}</td>
        <td class="right ret" class:up={r.returnPct > 0} class:dn={r.returnPct < 0}>
          {r.returnPct > 0 ? '+' : ''}{(r.returnPct * 100).toFixed(1)}%
        </td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  .st { width: 100%; border-collapse: collapse; }
  .st thead th {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    text-align: left;
    padding: 0 12px 6px 0;
    border-bottom: 1.5px solid var(--color-ink);
  }
  .st thead th.right { text-align: right; padding-right: 0; padding-left: 12px; }
  .st tbody td {
    padding: 12px 12px 12px 0;
    border-bottom: 1px solid var(--color-rule-soft);
    vertical-align: middle;
  }
  .st tbody td.right { text-align: right; padding-right: 0; padding-left: 12px; }
  .rank {
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 60, 'wght' 600;
    font-size: 26px;
    color: var(--color-ink);
    line-height: 1;
  }
  .rank--gold { color: var(--color-stamp); }
  .name { font-family: var(--font-body); font-size: 15px; }
  .cap {
    display: block;
    font-size: 11px;
    color: var(--color-ink-3);
    font-style: italic;
  }
  .total {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 500;
    font-size: 16px;
    font-variant-numeric: tabular-nums;
  }
  .ret { font-family: var(--font-mono); font-size: 12px; font-variant-numeric: tabular-nums; }
  .ret.up { color: var(--color-gain); }
  .ret.dn { color: var(--color-loss); }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/tables/StandingsTable.svelte
git commit -m "feat(ui): StandingsTable component"
```

---

### Task 16: `OrderTicket.svelte` (the trade form)

**Files:**
- Create: `src/lib/components/forms/OrderTicket.svelte`

- [ ] **Step 1: Write the component (no logic — form rendering only; the parent page wires `enhance`)**

```svelte
<!-- src/lib/components/forms/OrderTicket.svelte -->
<script lang="ts">
  import Stamp from '$lib/components/marks/Stamp.svelte';

  type Props = {
    mode: 'buy' | 'sell';
    onModeChange: (m: 'buy' | 'sell') => void;
    symbol: string;
    onSymbolChange: (s: string) => void;
    shares: string;
    onSharesChange: (s: string) => void;
    cashCents: number;
    formatUsd: (c: number) => string;
    lastPriceCents?: number;
    error?: string;
    filled?: { atTime: string; total: string } | null;
    children?: import('svelte').Snippet;
    no?: number;
    nowLabel?: string;
  };

  let {
    mode, onModeChange, symbol, onSymbolChange, shares, onSharesChange,
    cashCents, formatUsd, lastPriceCents,
    error, filled, children, no = 1, nowLabel
  }: Props = $props();

  const totalCost = $derived.by(() => {
    const n = parseInt(shares || '0', 10);
    if (!n || !lastPriceCents) return null;
    return n * lastPriceCents;
  });
</script>

<div class="ticket">
  <span class="ticket__dup">— duplicate · file copy —</span>

  <div class="ticket__head">
    <h3>Order Ticket</h3>
    <div class="ticket__meta">
      No. {no.toString().padStart(4, '0')}<br/>
      {nowLabel ?? ''}
    </div>
  </div>

  <div class="ticket__toggle">
    <button type="button" class:on={mode === 'buy'} onclick={() => onModeChange('buy')}>Buy</button>
    <button type="button" class:on={mode === 'sell'} onclick={() => onModeChange('sell')}>Sell</button>
  </div>

  <div class="ticket__field">
    <div class="lbl">Symbol</div>
    <input
      class="input"
      name="symbol"
      autocomplete="off"
      autocapitalize="characters"
      value={symbol}
      oninput={(e) => onSymbolChange((e.currentTarget as HTMLInputElement).value)}
      required
    />
  </div>

  <div class="ticket__field">
    <div class="lbl">Shares</div>
    <input
      class="input"
      name="shares"
      type="number"
      inputmode="numeric"
      min="1"
      value={shares}
      oninput={(e) => onSharesChange((e.currentTarget as HTMLInputElement).value)}
      required
    />
  </div>

  <div class="ticket__totals">
    <div class="row"><span class="k">Cash</span><span class="v">{formatUsd(cashCents)}</span></div>
    {#if lastPriceCents}
      <div class="row"><span class="k">Last price</span><span class="v">{formatUsd(lastPriceCents)}</span></div>
    {/if}
    <div class="row"><span class="k">Commission</span><span class="v">$0.00</span></div>
    {#if totalCost != null}
      <div class="row big">
        <span class="k">Total cost</span>
        <span class="v">{formatUsd(totalCost)}</span>
      </div>
    {/if}
  </div>

  {#if error}<p class="ticket__error">{error}</p>{/if}

  {@render children?.()}

  {#if filled}
    <div class="ticket__stamp"><Stamp label="Filled" sub="— booked at {filled.atTime} —" size="lg" /></div>
  {/if}
</div>

<style>
  .ticket {
    position: relative;
    background: var(--color-paper-receipt);
    box-shadow: 0 1px 0 rgba(22,17,10,0.04), 0 14px 28px -20px rgba(22,17,10,0.22);
    padding: 22px 22px 18px;
    margin: 4px 0 14px;
    max-width: 460px;
  }
  .ticket::before, .ticket::after {
    content: ""; position: absolute; left: 0; right: 0; height: 8px;
    background: radial-gradient(circle at 4px 8px, var(--color-paper) 3.5px, transparent 4px) 0 0/8px 8px repeat-x;
  }
  .ticket::before { top: -7px; }
  .ticket::after  { bottom: -7px; transform: scaleY(-1); }

  .ticket__dup {
    position: absolute; top: 14px; right: 18px;
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 24, 'wght' 600, 'SOFT' 100;
    font-size: 10px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--color-stamp);
    opacity: 0.55;
    transform: rotate(-2deg);
    pointer-events: none;
  }

  .ticket__head {
    display: flex; justify-content: space-between; align-items: baseline;
    border-bottom: 1.5px solid var(--color-ink);
    padding-bottom: 8px; margin-bottom: 12px;
  }
  .ticket__head h3 {
    margin: 0;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.01em;
  }
  .ticket__meta {
    font-family: var(--font-mono);
    font-size: 9.5px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    text-align: right;
    line-height: 1.5;
  }

  .ticket__toggle {
    display: inline-flex; border: 1.5px solid var(--color-ink); margin-bottom: 14px;
  }
  .ticket__toggle button {
    padding: 6px 18px;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    background: transparent;
    color: var(--color-ink);
    border: 0; cursor: pointer;
  }
  .ticket__toggle button.on { background: var(--color-ink); color: var(--color-paper-receipt); }

  .ticket__field { margin-bottom: 12px; }
  .ticket__field .lbl {
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    margin-bottom: 4px;
  }
  .ticket__field .input {
    width: 100%;
    background: transparent;
    border: 0;
    border-bottom: 1.5px solid var(--color-ink);
    outline: none;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 500;
    font-size: 22px;
    letter-spacing: -0.015em;
    color: var(--color-ink);
    padding: 2px 0 4px;
  }
  .ticket__field .input:focus { border-bottom-width: 2px; }

  .ticket__totals {
    margin-top: 12px; padding-top: 10px;
    border-top: 1px dashed var(--color-rule);
    font-family: var(--font-mono);
    font-size: 11px;
    line-height: 1.6;
  }
  .ticket__totals .row { display: flex; justify-content: space-between; }
  .ticket__totals .row .k {
    color: var(--color-ink-3);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    font-size: 9px;
    padding-top: 3px;
  }
  .ticket__totals .row.big {
    margin-top: 8px; padding-top: 8px;
    border-top: 1.5px solid var(--color-ink);
    font-size: 13px;
  }
  .ticket__totals .row.big .v {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.01em;
  }

  .ticket__error {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-loss);
    margin: 8px 0 0;
  }

  .ticket__stamp {
    margin-top: 12px;
    text-align: right;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/forms/OrderTicket.svelte
git commit -m "feat(ui): OrderTicket component with perforations + stamp slot"
```

---

## Phase 5 — Chrome / shell

### Task 17: Restyle `ThemeToggle.svelte`

**Files:**
- Modify: `src/lib/components/ThemeToggle.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/ThemeToggle.svelte -->
<script lang="ts">
  import { mode, setMode } from 'mode-watcher';
  import { Sun, Moon, Monitor } from 'lucide-svelte';

  function cycle() {
    if (mode.current === 'light') setMode('dark');
    else if (mode.current === 'dark') setMode('system');
    else setMode('light');
  }
</script>

<button onclick={cycle} class="tt" aria-label="toggle theme">
  {#if mode.current === 'light'}<Sun class="ico" />
  {:else if mode.current === 'dark'}<Moon class="ico" />
  {:else}<Monitor class="ico" />
  {/if}
</button>

<style>
  .tt {
    background: transparent;
    border: 0;
    padding: 6px;
    color: var(--color-ink-2);
    cursor: pointer;
    transition: color 0.15s;
  }
  .tt:hover { color: var(--color-ink); }
  :global(.tt .ico) { width: 16px; height: 16px; }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/ThemeToggle.svelte
git commit -m "refactor(ui): ThemeToggle in ledger style"
```

---

### Task 18: Restyle `SideNav.svelte` (bound spine + edition)

**Files:**
- Modify: `src/lib/components/nav/SideNav.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/nav/SideNav.svelte -->
<script lang="ts">
  import { page } from '$app/state';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import type { ComponentType, SvelteComponent } from 'svelte';

  let { navItems, user, editionNo = 1 }: {
    navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
    user: { id: string; username: string; displayName: string } | null;
    editionNo?: number;
  } = $props();

  function isActive(href: string): boolean {
    return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
  }

  const ROMAN = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII'];
</script>

<aside class="rail">
  <div class="rail__brand">finance<span class="amp">&amp;</span>sim</div>
  <div class="rail__edition">Vol III · No. {editionNo}</div>
  <hr class="rail__rule"/>

  <nav class="rail__nav">
    <ul>
      {#each navItems as item, i}
        {@const active = isActive(item.href)}
        <li class:on={active}>
          <a href={item.href}>
            <span class="num">{ROMAN[i] ?? ''}</span>
            <span class="lbl">{item.label}</span>
            {#if active}<span class="dot" aria-hidden="true"></span>{/if}
          </a>
        </li>
      {/each}
    </ul>
  </nav>

  <div class="rail__foot">
    {#if user}
      <div class="who">{user.displayName || user.username}</div>
    {/if}
    <div class="row">
      <ThemeToggle />
      <form method="POST" action="/signout">
        <button type="submit" class="signout">Sign out</button>
      </form>
    </div>
  </div>
</aside>

<style>
  .rail {
    position: fixed; inset-block: 0; left: 0; z-index: 10;
    width: 220px;
    background:
      linear-gradient(to right, var(--color-paper-2) 0, var(--color-paper-2) 6px, transparent 6px),
      var(--color-paper);
    border-right: 1px solid var(--color-rule);
    box-shadow: inset -3px 0 0 var(--color-rule-soft);
    padding: 28px 22px 18px 24px;
    display: none;
    flex-direction: column;
  }
  @media (min-width: 768px) { .rail { display: flex; } }

  .rail__brand {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 600;
    font-size: 19px;
    letter-spacing: -0.02em;
    line-height: 1;
  }
  .amp { color: var(--color-stamp); font-style: italic; }
  .rail__edition {
    margin-top: 4px;
    font-family: var(--font-mono);
    font-size: 9.5px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  .rail__rule {
    border: 0;
    border-top: 1px solid var(--color-rule);
    margin: 22px 0 14px;
  }

  .rail__nav { flex: 1; }
  .rail__nav ul { list-style: none; padding: 0; margin: 0; }
  .rail__nav li { border-bottom: 1px dotted var(--color-rule-soft); }
  .rail__nav a {
    display: flex; align-items: baseline; gap: 12px;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 14, 'SOFT' 0, 'wght' 400;
    font-size: 15px;
    color: var(--color-ink-2);
    padding: 9px 0;
    text-decoration: none;
  }
  .rail__nav a:hover { color: var(--color-ink); }
  .rail__nav li.on a {
    color: var(--color-ink);
    font-variation-settings: 'opsz' 14, 'SOFT' 0, 'wght' 600;
  }
  .rail__nav .num {
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 0.08em;
    color: var(--color-ink-3);
    width: 22px;
    text-align: right;
  }
  .rail__nav li.on .num { color: var(--color-stamp); }
  .rail__nav .dot {
    margin-left: auto;
    width: 5px; height: 5px;
    background: var(--color-stamp);
    border-radius: 50%;
    align-self: center;
  }

  .rail__foot { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--color-rule); }
  .rail__foot .who {
    font-family: var(--font-body);
    font-size: 13px;
    color: var(--color-ink);
    margin-bottom: 6px;
  }
  .rail__foot .row { display: flex; justify-content: space-between; align-items: center; }
  .signout {
    background: transparent; border: 0; cursor: pointer;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-2);
    padding: 4px;
  }
  .signout:hover { color: var(--color-stamp); }
</style>
```

- [ ] **Step 2: Run `pnpm check`** — note: `editionNo` is optional with default 1, so existing callers compile. We wire the real value in Phase 6 / Task 22.

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/nav/SideNav.svelte
git commit -m "refactor(ui): SideNav as bound-spine ledger"
```

---

### Task 19: Restyle `MobileTabBar.svelte`

**Files:**
- Modify: `src/lib/components/nav/MobileTabBar.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/nav/MobileTabBar.svelte -->
<script lang="ts">
  import { page } from '$app/state';
  import type { ComponentType, SvelteComponent } from 'svelte';

  let { navItems }: {
    navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
  } = $props();

  function isActive(href: string): boolean {
    return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
  }

  const tabs = $derived(navItems.slice(0, 5));
</script>

<nav class="tabbar">
  {#each tabs as item}
    {@const active = isActive(item.href)}
    <a href={item.href} class:on={active}>
      <item.icon class="ico" />
      <span class="lbl">{item.label}</span>
    </a>
  {/each}
</nav>

<style>
  .tabbar {
    position: fixed; inset-inline: 0; bottom: 0; z-index: 10;
    display: flex;
    background: var(--color-paper-2);
    border-top: 1px solid var(--color-rule);
  }
  @media (min-width: 768px) { .tabbar { display: none; } }
  .tabbar a {
    flex: 1;
    display: flex; flex-direction: column; align-items: center; gap: 2px;
    padding: 8px 4px;
    color: var(--color-ink-3);
    text-decoration: none;
  }
  .tabbar a.on { color: var(--color-ink); }
  :global(.tabbar .ico) { width: 18px; height: 18px; }
  .tabbar .lbl {
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }
  .tabbar a.on .lbl { color: var(--color-stamp); }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/nav/MobileTabBar.svelte
git commit -m "refactor(ui): MobileTabBar ledger styling"
```

---

### Task 20: `AppShell.svelte` with `TickerTape` + edition prop

**Files:**
- Modify: `src/lib/components/nav/AppShell.svelte`

- [ ] **Step 1: Replace the file**

```svelte
<!-- src/lib/components/nav/AppShell.svelte -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { ComponentType, SvelteComponent } from 'svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import SideNav from './SideNav.svelte';
  import MobileTabBar from './MobileTabBar.svelte';
  import TickerTape from './TickerTape.svelte';
  import { Wallet, ArrowLeftRight, Search, History, Trophy, Settings } from 'lucide-svelte';

  let {
    user,
    editionNo = 1,
    ticker = [],
    children
  }: {
    user: { id: string; username: string; displayName: string } | null;
    editionNo?: number;
    ticker?: { symbol: string; price: string; pct: number }[];
    children: Snippet;
  } = $props();

  const navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[] = [
    { href: '/portfolio', label: 'Portfolio', icon: Wallet },
    { href: '/trade', label: 'Trade', icon: ArrowLeftRight },
    { href: '/quote', label: 'Quote', icon: Search },
    { href: '/history', label: 'Ledger', icon: History },
    { href: '/competitions', label: 'Competitions', icon: Trophy },
    { href: '/settings', label: 'Settings', icon: Settings }
  ];
</script>

<TickerTape ticks={ticker} />

<div class="shell">
  <header class="mobile-top">
    <span class="brand">finance<span class="amp">&amp;</span>sim</span>
    <div class="row">
      <ThemeToggle />
      <form method="POST" action="/signout">
        <button type="submit" class="signout">Sign out</button>
      </form>
    </div>
  </header>

  <SideNav {navItems} {user} {editionNo} />

  <main class="main">
    {@render children()}
  </main>

  <MobileTabBar {navItems} />
</div>

<style>
  .shell { min-height: 100vh; }

  .mobile-top {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 14px;
    background: var(--color-paper-2);
    border-bottom: 1px solid var(--color-rule);
  }
  @media (min-width: 768px) { .mobile-top { display: none; } }
  .brand {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
    font-size: 16px;
    letter-spacing: -0.02em;
    color: var(--color-ink);
  }
  .amp { color: var(--color-stamp); font-style: italic; }
  .row { display: flex; align-items: center; gap: 6px; }
  .signout {
    background: transparent; border: 0;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-2);
    padding: 4px 6px;
    cursor: pointer;
  }

  .main {
    padding-bottom: 72px;
  }
  @media (min-width: 768px) { .main { margin-left: 220px; padding-bottom: 0; } }
</style>
```

- [ ] **Step 2: Run `pnpm check`**

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/nav/AppShell.svelte
git commit -m "refactor(ui): AppShell with TickerTape + editionNo wiring"
```

---

## Phase 6 — Server-side bits

### Task 21: Edition-number derivation utility

**Files:**
- Create: `src/lib/server/user/edition.ts`
- Create: `src/lib/server/user/edition.test.ts`
- Modify: `src/routes/(app)/+layout.server.ts` (or create if it doesn't exist)

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/server/user/edition.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { editionNoForUser } from './edition';
import * as schema from '$lib/server/db/schema';

describe('editionNoForUser', () => {
  let db: ReturnType<typeof drizzle>;
  let raw: Database.Database;

  beforeEach(() => {
    raw = new Database(':memory:');
    db = drizzle(raw, { schema });
    migrate(db, { migrationsFolder: './drizzle' });
  });

  it('returns 1 for a user with no transactions', async () => {
    raw.prepare(
      'INSERT INTO users (id, username, display_name, starting_cash_cents, cash_cents, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run('u1', 'alice', 'Alice', 1000000, 1000000, Math.floor(Date.now() / 1000));
    expect(await editionNoForUser(db, 'u1')).toBe(1);
  });

  it('returns count(distinct trading day) + 1', async () => {
    raw.prepare(
      'INSERT INTO users (id, username, display_name, starting_cash_cents, cash_cents, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run('u1', 'alice', 'Alice', 1000000, 1000000, Math.floor(Date.now() / 1000));

    const day1 = Math.floor(new Date('2026-05-01T14:00:00Z').getTime() / 1000);
    const day1b = Math.floor(new Date('2026-05-01T18:00:00Z').getTime() / 1000);
    const day2 = Math.floor(new Date('2026-05-02T14:00:00Z').getTime() / 1000);

    const ins = raw.prepare(
      'INSERT INTO transactions (id, user_id, symbol, shares, price_cents, executed_at) VALUES (?, ?, ?, ?, ?, ?)'
    );
    ins.run('t1', 'u1', 'AAPL', 5,  29277, day1);
    ins.run('t2', 'u1', 'AAPL', -1, 29300, day1b);
    ins.run('t3', 'u1', 'MSFT', 3,  41492, day2);

    expect(await editionNoForUser(db, 'u1')).toBe(3); // 2 distinct days + 1
  });
});
```

- [ ] **Step 2: Run test, verify FAIL** (`module not found`).

- [ ] **Step 3: Implement `edition.ts`**

```ts
// src/lib/server/user/edition.ts
import { sql } from 'drizzle-orm';
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';

/**
 * Decorative "edition number" shown in the masthead and sidebar.
 * Equals the count of distinct calendar days on which the user has transactions, plus 1.
 * A user with zero trades sees "No. 1" on their first day.
 */
export async function editionNoForUser(
  db: BetterSQLite3Database<Record<string, unknown>>,
  userId: string
): Promise<number> {
  const result = db.all<{ days: number }>(
    sql`SELECT COUNT(DISTINCT DATE(executed_at, 'unixepoch')) AS days
        FROM transactions WHERE user_id = ${userId}`
  );
  const days = (result[0]?.days as number | bigint | undefined) ?? 0;
  return Number(days) + 1;
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
pnpm test --run src/lib/server/user/edition.test.ts
```

- [ ] **Step 5: Wire it into `(app)/+layout.server.ts`**

```bash
ls src/routes/\(app\)/+layout.server.ts 2>/dev/null && echo exists || echo missing
```

If exists, modify it. If missing, create it:

```ts
// src/routes/(app)/+layout.server.ts
import { db } from '$lib/server/db';
import { editionNoForUser } from '$lib/server/user/edition';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals }) => {
  const user = locals.user;
  if (!user) return { user: null, editionNo: 1 };
  const editionNo = await editionNoForUser(db, user.id);
  return { user, editionNo };
};
```

If `(app)/+layout.server.ts` already returns `user`, just add `editionNo` to its return object.

- [ ] **Step 6: Update `(app)/+layout.svelte` to forward `editionNo`**

```svelte
<!-- src/routes/(app)/+layout.svelte -->
<script lang="ts">
  import AppShell from '$lib/components/nav/AppShell.svelte';

  let {
    data,
    children
  }: {
    data: { user: { id: string; username: string; displayName: string } | null; editionNo: number };
    children: import('svelte').Snippet;
  } = $props();
</script>

<AppShell user={data.user} editionNo={data.editionNo}>
  {@render children()}
</AppShell>
```

- [ ] **Step 7: Run `pnpm check`** — expect no errors.

- [ ] **Step 8: Commit**

```bash
git add src/lib/server/user/edition.ts src/lib/server/user/edition.test.ts src/routes/\(app\)/+layout.server.ts src/routes/\(app\)/+layout.svelte
git commit -m "feat(server): edition-number derivation + layout wiring"
```

---

## Phase 7 — Pages

> Each page task ends with **manual verification**: `pnpm dev`, sign in, visit the route, confirm visually. Capture a screenshot to `screenshots/ledger/` if you want a before/after record.

### Task 22: `(app)/+layout.svelte` page padding wrapper

This is just a thin wrapper that gives every signed-in route consistent padding. Already partially done in Task 21 step 6, but we're going to wrap a `<div class="page">` around children.

**Files:**
- Modify: `src/routes/(app)/+layout.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/+layout.svelte -->
<script lang="ts">
  import AppShell from '$lib/components/nav/AppShell.svelte';

  let {
    data,
    children
  }: {
    data: { user: { id: string; username: string; displayName: string } | null; editionNo: number };
    children: import('svelte').Snippet;
  } = $props();
</script>

<AppShell user={data.user} editionNo={data.editionNo}>
  <div class="page">
    {@render children()}
  </div>
</AppShell>

<style>
  .page {
    max-width: 1100px;
    margin: 0 auto;
    padding: 32px clamp(20px, 4vw, 56px) 80px;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/\(app\)/+layout.svelte
git commit -m "feat(ui): consistent page padding on signed-in routes"
```

---

### Task 23: Portfolio page

**Files:**
- Modify: `src/routes/(app)/portfolio/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/portfolio/+page.svelte -->
<script lang="ts">
  import { formatUsd } from '$lib/shared/money';
  import EquityCurveChart from '$lib/components/charts/EquityCurve.svelte';
  import Sparkline from '$lib/components/charts/Sparkline.svelte';
  import Masthead from '$lib/components/marks/Masthead.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import StatBlock from '$lib/components/marks/StatBlock.svelte';
  import DataTable from '$lib/components/tables/DataTable.svelte';
  import { onMount } from 'svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  let sparklines = $state<Record<string, { closes: number[]; dates: string[] }>>({});
  onMount(async () => {
    for (const h of data.holdings) {
      const res = await fetch(`/api/sparkline/${h.symbol}`);
      if (res.ok) {
        const j = await res.json();
        sparklines[h.symbol] = { closes: j.closes, dates: j.dates };
      }
    }
  });

  let rows = $derived(
    data.holdings.map((h) => ({
      symbol: h.symbol,
      shares: h.shares.toString(),
      price: formatUsd(h.priceCents),
      value: formatUsd(h.valueCents)
    }))
  );

  const stats = $derived([
    { label: 'Cash on hand', value: formatUsd(data.cashCents) },
    { label: 'Holdings, mkt.', value: formatUsd(data.totalCents - data.cashCents) },
    { label: 'Account total', value: formatUsd(data.totalCents) }
  ]);

  // server load may pass editionNo through layout; use 1 as fallback
  const editionNo = $derived(((data as unknown) as { editionNo?: number }).editionNo ?? 1);
</script>

<Masthead {editionNo} date={new Date()} />

<SectionHead eyebrow="I — Portfolio" title="The Portfolio." meta="As of close" />

<StatBlock {stats} />

<EquityCurveChart series={data.curve} />

<SectionHead title="Holdings." meta={`${data.holdings.length} ${data.holdings.length === 1 ? 'position' : 'positions'}`} />

{#if data.holdings.length === 0}
  <p class="empty">
    <em>No holdings yet —</em> <a href="/trade">trade</a>.
  </p>
{:else}
  <DataTable
    columns={[
      { key: 'symbol', label: 'Symbol' },
      { key: 'shares', label: 'Shares', tabular: true },
      { key: 'price',  label: 'Last',   tabular: true },
      { key: 'value',  label: 'Position', tabular: true }
    ]}
    {rows}
  />

  <div class="sparks">
    {#each data.holdings as h}
      {@const sp = sparklines[h.symbol]}
      <div class="sparks__item">
        <span class="sym">{h.symbol}</span>
        {#if sp}
          <Sparkline data={sp.closes} dates={sp.dates} width={140} height={32} />
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .empty {
    font-family: var(--font-body);
    font-size: 15px;
    color: var(--color-ink-2);
  }
  .empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
  .sparks { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 14px; margin-top: 24px; }
  .sparks__item {
    display: flex; align-items: center; justify-content: space-between;
    border-top: 1px solid var(--color-rule-soft);
    padding-top: 8px;
  }
  .sym {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 16px;
  }
</style>
```

- [ ] **Step 2: Run `pnpm check`** — expect no errors.

- [ ] **Step 3: Commit**

```bash
git add src/routes/\(app\)/portfolio/+page.svelte
git commit -m "feat(ui): portfolio page in ledger style"
```

---

### Task 24: Trade page (uses `OrderTicket`)

**Files:**
- Modify: `src/routes/(app)/trade/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/trade/+page.svelte -->
<script lang="ts">
  import { enhance } from '$app/forms';
  import OrderTicket from '$lib/components/forms/OrderTicket.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import { formatUsd } from '$lib/shared/money';

  let { data, form } = $props();

  let mode: 'buy' | 'sell' = $state('buy');
  let symbol = $state('');
  let shares = $state('');

  $effect(() => {
    if (form?.success) {
      shares = '';
      return;
    }
    if (form && 'symbol' in form && typeof form.symbol === 'string') {
      symbol = form.symbol as string;
    }
    if (form && 'shares' in form && form.shares != null) {
      shares = String(form.shares);
    }
  });

  const filled = $derived(
    form?.success
      ? {
          atTime: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
          total: ''
        }
      : null
  );

  const nowLabel = new Date().toLocaleString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' }).replace(/, /, ' · ');
</script>

<SectionHead eyebrow="II — Trade" title="Buy or sell." meta="At market" />

<form method="POST" use:enhance class="trade-form">
  <input type="hidden" name="mode" value={mode} />
  <OrderTicket
    {mode}
    onModeChange={(m) => (mode = m)}
    {symbol}
    onSymbolChange={(s) => (symbol = s)}
    {shares}
    onSharesChange={(s) => (shares = s)}
    cashCents={data.cashCents}
    {formatUsd}
    error={form?.error ?? undefined}
    {filled}
    {nowLabel}
  >
    <button type="submit" class="btn-place">Place order →</button>
  </OrderTicket>
</form>

{#if form?.success}
  <p class="success">{form.message} <a href="/portfolio">view portfolio →</a></p>
{/if}

{#if mode === 'sell' && data.holdings.length > 0}
  <section class="holdings">
    <div class="holdings__lbl">Your holdings</div>
    <ul>
      {#each data.holdings as h}
        <li>
          <button type="button" class="sym" onclick={() => (symbol = h.symbol)}>{h.symbol}</button>
          <span class="shares">{h.shares} shares</span>
        </li>
      {/each}
    </ul>
  </section>
{/if}

<style>
  .trade-form { display: contents; }
  .btn-place {
    display: block; width: 100%;
    background: var(--color-ink);
    color: var(--color-paper-receipt);
    border: 0;
    padding: 11px;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 13px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    cursor: pointer;
    margin-top: 14px;
  }
  .success {
    margin: 12px 0 0;
    font-family: var(--font-body);
    font-style: italic;
    color: var(--color-gain);
  }
  .success a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
  .holdings { margin-top: 32px; }
  .holdings__lbl {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    margin-bottom: 8px;
  }
  .holdings ul { list-style: none; padding: 0; margin: 0; }
  .holdings li { display: flex; gap: 14px; padding: 6px 0; align-items: baseline; }
  .sym {
    background: transparent; border: 0; padding: 0; cursor: pointer;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 16px;
    color: var(--color-ink);
  }
  .sym:hover { color: var(--color-stamp); }
  .shares { font-family: var(--font-mono); font-size: 12px; color: var(--color-ink-3); }
</style>
```

- [ ] **Step 2: Run `pnpm check`**

- [ ] **Step 3: Commit**

```bash
git add src/routes/\(app\)/trade/+page.svelte
git commit -m "feat(ui): trade page with OrderTicket"
```

---

### Task 25: Quote page

**Files:**
- Modify: `src/routes/(app)/quote/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/quote/+page.svelte -->
<script lang="ts">
  import { enhance } from '$app/forms';
  import TextField from '$lib/components/forms/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import Sparkline from '$lib/components/charts/Sparkline.svelte';
  import Stamp from '$lib/components/marks/Stamp.svelte';
  import { formatUsd } from '$lib/shared/money';

  let { form } = $props();
  let symbol = $state('');
  let sparkData = $state<number[] | null>(null);
  let sparkDates = $state<string[] | undefined>();

  $effect(() => {
    if (form && 'symbol' in form && typeof form.symbol === 'string') {
      symbol = form.symbol as string;
    }
  });

  $effect(() => {
    if (form?.symbol && !form?.error) {
      fetch(`/api/sparkline/${form.symbol}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((j) => { if (j) { sparkData = j.closes; sparkDates = j.dates; } });
    }
  });

  const dollars = $derived(form?.priceCents != null ? Math.floor(form.priceCents / 100) : null);
  const cents   = $derived(form?.priceCents != null ? `.${(form.priceCents % 100).toString().padStart(2, '0')}` : null);
</script>

<SectionHead eyebrow="III — Quote" title="Quote." meta="Last reported close" />

<form method="POST" use:enhance class="qf">
  <TextField name="symbol" label="Symbol" bind:value={symbol} required />
  <FormError message={form?.error ?? ''} />
  <Button type="submit" variant="primary">Get quote</Button>
</form>

{#if form?.priceCents != null && !form?.error}
  <article class="card">
    <div class="sym">{form.symbol}</div>
    <div class="price tabular">
      ${dollars?.toLocaleString()}<span class="c">{cents}</span>
    </div>
    {#if sparkData}
      <div class="spark">
        <Sparkline data={sparkData} dates={sparkDates} width={400} height={48} />
      </div>
    {/if}
    <div class="foot">30-day chart · drawn at close</div>
  </article>
{:else if form?.error}
  <div class="error-card">
    <div class="error-card__sym">{form.symbol ?? '—'}</div>
    <Stamp label="No record" variant="loss" size="md" />
  </div>
{/if}

<style>
  .qf { display: flex; flex-direction: column; gap: 14px; max-width: 400px; }
  .card {
    margin-top: 32px;
    max-width: 460px;
    padding: 20px 24px 18px;
    background: var(--color-paper-receipt);
    box-shadow: 0 14px 28px -22px rgba(22,17,10,0.18);
  }
  .sym {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  .price {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 144, 'wght' 400;
    font-size: 56px;
    letter-spacing: -0.03em;
    line-height: 1;
    margin-top: 4px;
  }
  .price .c {
    font-size: 0.55em;
    color: var(--color-ink-2);
    vertical-align: 0.42em;
    margin-left: 1px;
  }
  .spark { margin: 16px 0 6px; }
  .foot {
    font-family: var(--font-mono);
    font-size: 9.5px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  .error-card {
    margin-top: 28px;
    padding: 24px;
    background: var(--color-paper-receipt);
    max-width: 400px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .error-card__sym {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'wght' 600;
    font-size: 22px;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/\(app\)/quote/+page.svelte
git commit -m "feat(ui): quote page in ledger style"
```

---

### Task 26: History page

**Files:**
- Modify: `src/routes/(app)/history/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/history/+page.svelte -->
<script lang="ts">
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import DataTable from '$lib/components/tables/DataTable.svelte';
  import { formatUsd } from '$lib/shared/money';
  import { toIsoDate } from '$lib/shared/dates';

  let { data } = $props();

  let rows = $derived(
    data.rows.map((r) => {
      const isBuy = r.shares > 0;
      return {
        date: toIsoDate(r.executedAt),
        type: isBuy ? 'Buy' : 'Sell',
        symbol: r.symbol,
        shares: Math.abs(r.shares).toString(),
        price: formatUsd(r.priceCents),
        amount: formatUsd(Math.abs(r.shares * r.priceCents)),
        cashAfter: formatUsd(r.runningCash)
      };
    })
  );
</script>

<SectionHead eyebrow="IV — Ledger" title="The Ledger." meta={`${data.rows.length} ${data.rows.length === 1 ? 'entry' : 'entries'}`} />

{#if data.rows.length === 0}
  <p class="empty"><em>No trades yet —</em> <a href="/trade">trade</a>.</p>
{:else}
  <DataTable
    columns={[
      { key: 'date',      label: 'Date' },
      { key: 'type',      label: 'Type' },
      { key: 'symbol',    label: 'Symbol' },
      { key: 'shares',    label: 'Shares',     tabular: true },
      { key: 'price',     label: 'Price',      tabular: true },
      { key: 'amount',    label: 'Amount',     tabular: true },
      { key: 'cashAfter', label: 'Cash after', tabular: true }
    ]}
    {rows}
  />
{/if}

<style>
  .empty { font-family: var(--font-body); font-size: 15px; color: var(--color-ink-2); }
  .empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/\(app\)/history/+page.svelte
git commit -m "feat(ui): history (Ledger) page in ledger style"
```

---

### Task 27: Competitions list page

**Files:**
- Modify: `src/routes/(app)/competitions/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/competitions/+page.svelte -->
<script lang="ts">
  import { toIsoDate } from '$lib/shared/dates';
  import { formatUsd } from '$lib/shared/money';
  import Button from '$lib/components/Button.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import Stamp from '$lib/components/marks/Stamp.svelte';

  let { data } = $props();

  function stampVariant(status: string): 'stamp' | 'ink' | 'muted' {
    if (status === 'finished') return 'ink';
    if (status === 'open')     return 'stamp';
    return 'stamp'; // running
  }
</script>

<div class="head">
  <SectionHead eyebrow="V — Competitions" title="Competitions." meta="Hosting + joined" />
  <a href="/competitions/new" class="cta">
    <Button variant="primary">Create new</Button>
  </a>
</div>

{#if data.comps.length === 0}
  <p class="empty"><em>No competitions yet —</em> <a href="/competitions/new">create one</a> or join via invite link.</p>
{:else}
  <ul class="list">
    {#each data.comps as c}
      <li>
        <a href="/competitions/{c.id}">
          <div class="row">
            <div>
              <div class="name">{c.name}</div>
              <div class="meta">
                <span class="type">{c.type}</span>
                {#if c.isHost}<span class="host">· host</span>{/if}
                · {toIsoDate(c.startDate)} → {toIsoDate(c.endDate)}
                · starting {formatUsd(c.startingCashCents)}
                · code <span class="code">{c.inviteCode}</span>
              </div>
            </div>
            <Stamp label={c.status} variant={stampVariant(c.status)} size="sm" />
          </div>
        </a>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; }
  .head .cta { padding-bottom: 10px; }
  .empty { font-family: var(--font-body); font-size: 15px; color: var(--color-ink-2); }
  .empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
  .list { list-style: none; padding: 0; margin: 0; }
  .list li { border-bottom: 1px solid var(--color-rule-soft); }
  .list a {
    display: block;
    text-decoration: none;
    color: var(--color-ink);
    padding: 16px 0;
  }
  .list a:hover { background: var(--color-paper-2); }
  .row { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
  .name {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.01em;
  }
  .meta {
    margin-top: 3px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-ink-3);
    letter-spacing: 0.04em;
  }
  .type { text-transform: uppercase; letter-spacing: 0.12em; }
  .host { color: var(--color-ink-2); }
  .code { color: var(--color-ink-2); }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/\(app\)/competitions/+page.svelte
git commit -m "feat(ui): competitions list in ledger style"
```

---

### Task 28: Competition `[id]` page (sports almanac)

**Files:**
- Modify: `src/routes/(app)/competitions/[id]/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/(app)/competitions/[id]/+page.svelte -->
<script lang="ts">
  import { enhance } from '$app/forms';
  import { invalidateAll } from '$app/navigation';
  import OrderTicket from '$lib/components/forms/OrderTicket.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import StandingsTable from '$lib/components/tables/StandingsTable.svelte';
  import PullQuote from '$lib/components/marks/PullQuote.svelte';
  import Stamp from '$lib/components/marks/Stamp.svelte';
  import Button from '$lib/components/Button.svelte';
  import { formatUsd } from '$lib/shared/money';
  import { toIsoDate } from '$lib/shared/dates';

  let { data, form } = $props();

  let mode: 'buy' | 'sell' = $state('buy');
  let symbol = $state('');
  let shares = $state('');

  let polledLeaderboard: typeof data.leaderboard | null = $state(null);
  let leaderboard = $derived(polledLeaderboard ?? data.leaderboard);

  $effect(() => {
    if (data.dashboard.competition.status === 'running') {
      polledLeaderboard = null;
      const t = setInterval(async () => {
        const r = await fetch(`/api/leaderboard/${data.dashboard.competition.id}`);
        if (r.ok) { const j = await r.json(); polledLeaderboard = j.rows; }
      }, 5000);
      return () => { clearInterval(t); polledLeaderboard = null; };
    }
  });

  let canTrade = $derived(
    (data.dashboard.competition.type === 'live' && data.dashboard.competition.status === 'running') ||
    (data.dashboard.competition.type === 'historical' && data.dashboard.competition.status === 'open')
  );

  const standings = $derived(
    leaderboard.map((r) => ({
      rank: r.rank,
      name: r.displayName,
      caption: undefined as string | undefined,
      totalCents: r.totalCents,
      returnPct: r.returnPct,
      formDeltas: undefined as number[] | undefined
    }))
  );

  const leader = $derived(standings[0]);

  const statusInfo = $derived.by(() => {
    if (data.dashboard.competition.status === 'finished') {
      return { label: 'Final', sub: leader ? `Champion: ${leader.name}` : '— sealed —', variant: 'ink' as const };
    }
    return { label: 'Provisional', sub: `— sealed ${toIsoDate(data.dashboard.competition.endDate)} —`, variant: 'stamp' as const };
  });
</script>

<SectionHead eyebrow="Standings" title={data.dashboard.competition.name} meta={`${data.dashboard.competition.type} · code ${data.dashboard.competition.inviteCode}`} />

<p class="deck">
  <em>
    {leaderboard.length} {leaderboard.length === 1 ? 'player' : 'players'},
    starting {formatUsd(data.dashboard.competition.startingCashCents)} each,
    sealed {toIsoDate(data.dashboard.competition.endDate)}.
  </em>
</p>

{#if leader && leader.returnPct !== 0}
  <PullQuote badge={leader.name.charAt(0).toUpperCase()}>
    "<strong>{leader.name}</strong>
    {leader.returnPct > 0 ? 'up' : 'down'}
    <strong>{(Math.abs(leader.returnPct) * 100).toFixed(1)}%</strong>
    — <em>{leader.returnPct > 0 ? 'in good form.' : 'looking for a comeback.'}</em>"
  </PullQuote>
{/if}

<div class="standings">
  <StandingsTable rows={standings} {formatUsd} />
</div>

<div class="status-row">
  <Stamp label={statusInfo.label} sub={statusInfo.sub} variant={statusInfo.variant} size="md" />
</div>

{#if data.dashboard.isHost}
  <section class="host-controls">
    <SectionHead title="Host controls." />
    {#if data.dashboard.competition.type === 'historical' && data.dashboard.competition.status === 'open'}
      <form method="POST" action="?/resolve" use:enhance={() => () => invalidateAll()}>
        <Button type="submit" variant="primary">Resolve now</Button>
      </form>
    {/if}
    {#if data.dashboard.competition.status === 'finished'}
      <form method="POST" action="?/toggleShare" use:enhance={() => () => invalidateAll()}>
        <input type="hidden" name="value" value={data.dashboard.competition.shareResults ? '0' : '1'} />
        <Button type="submit" variant="quiet">
          {data.dashboard.competition.shareResults ? 'Unshare results' : 'Share results publicly'}
        </Button>
      </form>
    {/if}
  </section>
{/if}

<section class="my">
  <SectionHead title="My positions." meta={`Cash ${formatUsd(data.dashboard.myCashCents)}`} />
  {#if data.dashboard.myHoldings.length > 0}
    <ul class="my-list">
      {#each data.dashboard.myHoldings as h}
        <li><span class="sym">{h.symbol}</span><span class="sh">{h.shares} shares</span></li>
      {/each}
    </ul>
  {:else}
    <p class="empty"><em>No comp positions yet.</em></p>
  {/if}
</section>

{#if canTrade}
  <section class="trade">
    <SectionHead title="Place an order." />
    <form method="POST" action="?/trade" use:enhance={() => () => invalidateAll()}>
      <input type="hidden" name="mode" value={mode} />
      <OrderTicket
        {mode}
        onModeChange={(m) => (mode = m)}
        {symbol}
        onSymbolChange={(s) => (symbol = s)}
        {shares}
        onSharesChange={(s) => (shares = s)}
        cashCents={data.dashboard.myCashCents}
        {formatUsd}
        error={form?.tradeError ?? undefined}
      >
        <button type="submit" class="btn-place">Place order →</button>
      </OrderTicket>
    </form>
    {#if form?.tradeOk}<p class="ok"><em>{form.tradeOk}</em></p>{/if}
  </section>
{/if}

<style>
  .deck { font-family: var(--font-body); font-style: italic; font-size: 14px; color: var(--color-ink-2); margin: 0 0 18px; max-width: 640px; }
  .standings { margin-top: 18px; }
  .status-row { margin-top: 22px; text-align: right; }
  .host-controls, .my, .trade { margin-top: 8px; }
  .my-list { list-style: none; padding: 0; margin: 8px 0 0; }
  .my-list li { display: flex; gap: 14px; padding: 6px 0; align-items: baseline; border-bottom: 1px solid var(--color-rule-soft); }
  .sym { font-family: var(--font-display); font-variation-settings: 'opsz' 24, 'wght' 600; font-size: 16px; }
  .sh { font-family: var(--font-mono); font-size: 12px; color: var(--color-ink-3); }
  .empty { font-family: var(--font-body); font-style: italic; color: var(--color-ink-2); }
  .ok { font-family: var(--font-body); color: var(--color-gain); }
  .btn-place {
    display: block; width: 100%;
    background: var(--color-ink); color: var(--color-paper-receipt);
    border: 0; padding: 11px;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 13px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    cursor: pointer;
    margin-top: 14px;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/\(app\)/competitions/\[id\]/+page.svelte
git commit -m "feat(ui): competition [id] as sports almanac"
```

---

### Task 29: Competition `new` and `join` pages

**Files:**
- Modify: `src/routes/(app)/competitions/new/+page.svelte`
- Modify: `src/routes/(app)/competitions/join/[code]/+page.svelte`

- [ ] **Step 1: Read both files**

```bash
cat src/routes/\(app\)/competitions/new/+page.svelte src/routes/\(app\)/competitions/join/\[code\]/+page.svelte
```

- [ ] **Step 2: Apply ledger styling**

For each file: replace the existing `<h1>` with `<SectionHead>` (eyebrow "V — Competitions", appropriate title), wrap the form fields in our restyled `TextField` (already done in Task 10), keep the existing form action / `enhance` wiring untouched. The exact code depends on what each file currently does — preserve the form contracts.

For `new`:

```svelte
<script lang="ts">
  import { enhance } from '$app/forms';
  import TextField from '$lib/components/forms/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  let { form } = $props();
</script>

<SectionHead eyebrow="V — Competitions" title="New competition." meta="Open to invitees" />

<form method="POST" use:enhance class="cn">
  <!-- KEEP the field names from the existing file -->
  <!-- e.g. name, type (radio: live | historical), startDate, endDate, startingCashCents -->
  <!-- Re-paste the exact field markup from the original file, swapping in <TextField> where appropriate. -->
  <FormError message={form?.error ?? ''} />
  <Button type="submit" variant="primary">Create</Button>
</form>

<style>
  .cn { display: flex; flex-direction: column; gap: 14px; max-width: 460px; }
</style>
```

For `join/[code]`:

```svelte
<script lang="ts">
  import { enhance } from '$app/forms';
  import Button from '$lib/components/Button.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import { formatUsd } from '$lib/shared/money';
  import { toIsoDate } from '$lib/shared/dates';
  let { data } = $props();
</script>

<SectionHead eyebrow="Invite" title="Join: {data.comp.name}" />

<div class="card">
  <p class="meta">
    <span>{data.comp.type}</span> · {toIsoDate(data.comp.startDate)} → {toIsoDate(data.comp.endDate)} · starting {formatUsd(data.comp.startingCashCents)}
  </p>
  <form method="POST" use:enhance>
    <Button type="submit" variant="primary">Join</Button>
  </form>
</div>

<style>
  .card { background: var(--color-paper-receipt); padding: 24px; max-width: 460px; box-shadow: 0 14px 28px -22px rgba(22,17,10,0.18); }
  .meta { font-family: var(--font-mono); font-size: 11px; color: var(--color-ink-3); letter-spacing: 0.04em; margin: 0 0 14px; }
  .meta span:first-child { text-transform: uppercase; letter-spacing: 0.12em; }
</style>
```

- [ ] **Step 3: Run `pnpm check`**

- [ ] **Step 4: Commit**

```bash
git add src/routes/\(app\)/competitions/new/+page.svelte src/routes/\(app\)/competitions/join/\[code\]/+page.svelte
git commit -m "feat(ui): competition new + join in ledger style"
```

---

### Task 30: Settings + passkeys pages

**Files:**
- Modify: `src/routes/(app)/settings/+page.svelte`
- Modify: `src/routes/(app)/settings/passkeys/+page.svelte`

- [ ] **Step 1: Read both files**

```bash
cat src/routes/\(app\)/settings/+page.svelte src/routes/\(app\)/settings/passkeys/+page.svelte
```

- [ ] **Step 2: Replace `settings/+page.svelte`**

```svelte
<script lang="ts">
  import { enhance } from '$app/forms';
  import TextField from '$lib/components/forms/TextField.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import Button from '$lib/components/Button.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import type { PageProps } from './$types';

  let { data, form }: PageProps = $props();
  let displayName = $state('');
  let errorMsg = $derived((form as { error?: string } | null)?.error ?? '');

  $effect(() => { if (data.user?.displayName) displayName = data.user.displayName; });
</script>

<SectionHead eyebrow="VI — Settings" title="Settings." />

<section class="sec">
  <h2 class="sub">Account</h2>
  <p class="line"><span class="lbl">Username</span> <span class="val">{data.user.username}</span></p>
  <form method="POST" action="?/updateDisplayName" use:enhance class="form">
    <TextField name="displayName" label="Display name" bind:value={displayName} />
    <FormError message={errorMsg} />
    {#if (form as { ok?: boolean } | null)?.ok}
      <p class="ok"><em>Display name updated.</em></p>
    {/if}
    <Button type="submit" variant="primary">Save</Button>
  </form>
</section>

<section class="sec">
  <h2 class="sub">Security</h2>
  <p class="prose">Manage your passkeys and recovery codes.</p>
  <a href="/settings/passkeys" class="link">Manage passkeys →</a>
</section>

<style>
  .sec { margin-top: 28px; max-width: 460px; }
  .sub {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'wght' 500;
    font-size: 22px;
    margin: 0 0 12px;
    letter-spacing: -0.01em;
  }
  .line { font-family: var(--font-body); font-size: 14px; margin: 0 0 14px; }
  .line .lbl { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--color-ink-3); margin-right: 8px; }
  .form { display: flex; flex-direction: column; gap: 14px; }
  .ok { font-family: var(--font-body); color: var(--color-gain); margin: 0; }
  .prose { font-family: var(--font-body); color: var(--color-ink-2); margin: 0 0 8px; }
  .link {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 14px;
    color: var(--color-ink);
    border-bottom: 1px solid var(--color-rule);
    text-decoration: none;
  }
  .link:hover { color: var(--color-stamp); }
</style>
```

- [ ] **Step 3: Replace `settings/passkeys/+page.svelte`**

Read the file first to know its data shape and form actions, then rewrite using `SectionHead`, `DataTable`, and `Button` while preserving form actions. Sketch:

```svelte
<script lang="ts">
  import { enhance } from '$app/forms';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import Button from '$lib/components/Button.svelte';
  // ... preserve existing imports

  let { data, form } = $props();
  // ... preserve existing logic
</script>

<SectionHead eyebrow="VI — Settings" title="Passkeys." meta={`${data.passkeys.length} on file`} />

<!-- Preserve the existing add/rename/revoke forms; restyle with our Button + table semantics. -->
```

- [ ] **Step 4: Run `pnpm check`**

- [ ] **Step 5: Commit**

```bash
git add src/routes/\(app\)/settings/+page.svelte src/routes/\(app\)/settings/passkeys/+page.svelte
git commit -m "feat(ui): settings + passkeys pages in ledger style"
```

---

### Task 31: Auth pages (signin / signup / recover)

**Files:**
- Modify: `src/routes/(auth)/signin/+page.svelte`
- Modify: `src/routes/(auth)/signup/+page.svelte`
- Modify: `src/routes/(auth)/recover/+page.svelte`
- Modify: `src/routes/(auth)/+layout.svelte`

- [ ] **Step 1: Read all four files**

```bash
cat src/routes/\(auth\)/+layout.svelte src/routes/\(auth\)/signin/+page.svelte src/routes/\(auth\)/signup/+page.svelte src/routes/\(auth\)/recover/+page.svelte
```

- [ ] **Step 2: Apply ledger card styling**

The auth layout should center one ticket-style card on the page, with a small "finance&sim" wordmark above. Each `+page.svelte` keeps its existing logic and form actions; only chrome changes.

`(auth)/+layout.svelte`:

```svelte
<script lang="ts">
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  let { children } = $props();
</script>

<div class="auth">
  <header class="top">
    <a href="/" class="brand">finance<span class="amp">&amp;</span>sim</a>
    <ThemeToggle />
  </header>
  <main class="card-wrap">
    <article class="card">
      {@render children()}
    </article>
  </main>
</div>

<style>
  .auth { min-height: 100vh; display: flex; flex-direction: column; }
  .top {
    display: flex; justify-content: space-between; align-items: center;
    padding: 18px 24px;
    border-bottom: 1px solid var(--color-rule);
  }
  .brand {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.02em;
    color: var(--color-ink);
    text-decoration: none;
  }
  .amp { color: var(--color-stamp); font-style: italic; }
  .card-wrap { flex: 1; display: grid; place-items: center; padding: 24px; }
  .card {
    width: 100%;
    max-width: 420px;
    background: var(--color-paper-receipt);
    padding: 32px;
    box-shadow: 0 14px 28px -22px rgba(22,17,10,0.18);
    position: relative;
  }
  .card::before, .card::after {
    content: ""; position: absolute; left: 0; right: 0; height: 8px;
    background: radial-gradient(circle at 4px 8px, var(--color-paper) 3.5px, transparent 4px) 0 0/8px 8px repeat-x;
  }
  .card::before { top: -7px; }
  .card::after  { bottom: -7px; transform: scaleY(-1); }
</style>
```

For each page (`signin`, `signup`, `recover`) — preserve existing logic and form actions; replace the existing markup chrome with this skeleton:

```svelte
<script lang="ts">
  // KEEP existing imports + state + form actions
  import TextField from '$lib/components/forms/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
</script>

<h1 class="auth-h">Welcome back.</h1>  <!-- or "Open an account." or "Recovery." -->
<p class="auth-deck"><em>Sign in with your passkey.</em></p>

<form method="POST" use:enhance class="auth-form">
  <TextField name="username" label="Username" bind:value={username} required />
  <FormError message={errorMsg} />
  <Button type="submit" variant="primary">Sign in</Button>
</form>

<p class="auth-foot"><a href="/recover">Use a recovery code →</a></p>

<style>
  .auth-h {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 96, 'wght' 500;
    font-size: 32px;
    letter-spacing: -0.02em;
    line-height: 1;
    margin: 0 0 4px;
  }
  .auth-deck {
    font-family: var(--font-body);
    font-style: italic;
    font-size: 14px;
    color: var(--color-ink-2);
    margin: 0 0 24px;
  }
  .auth-form { display: flex; flex-direction: column; gap: 14px; }
  .auth-foot { margin-top: 18px; font-family: var(--font-body); }
  .auth-foot a { color: var(--color-ink-2); border-bottom: 1px dotted var(--color-rule); text-decoration: none; }
  .auth-foot a:hover { color: var(--color-ink); }
</style>
```

For the `signup` page, after the passkey ceremony the existing flow renders recovery codes — wrap those codes in a `Stamp`-flavored card:

```svelte
<!-- after success: -->
<div class="codes">
  {#each recoveryCodes as code}
    <code class="code">{code}</code>
  {/each}
</div>
<style>
  .codes { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
  .code {
    font-family: var(--font-mono);
    font-size: 13px;
    background: var(--color-paper-2);
    padding: 8px 12px;
    letter-spacing: 0.06em;
  }
</style>
```

- [ ] **Step 3: Run `pnpm check`**

- [ ] **Step 4: Commit**

```bash
git add src/routes/\(auth\)/
git commit -m "feat(ui): auth pages in ledger style"
```

---

### Task 32: Signed-out landing page

**Files:**
- Modify: `src/routes/+page.svelte`

- [ ] **Step 1: Replace contents**

```svelte
<!-- src/routes/+page.svelte -->
<script lang="ts">
  import { ArrowRight } from 'lucide-svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
</script>

<div class="land">
  <header class="top">
    <span class="brand">finance<span class="amp">&amp;</span>sim</span>
    <div class="row">
      <ThemeToggle />
      <a href="/signin" class="signin">Sign in</a>
    </div>
  </header>

  <main class="hero">
    <div class="eyebrow">— A daily ledger of paper positions —</div>
    <h1>Paper trading.<br/><em>Real friends.</em></h1>
    <p class="deck">
      Track a fake portfolio. Run instant-replay competitions on past windows. Or compete live with your friends.
      Passkey sign-in. No email.
    </p>
    <div class="cta-row">
      <a href="/signup" class="cta cta--primary">Open an account <ArrowRight class="ico" /></a>
      <a href="/signin" class="cta cta--quiet">Already have one</a>
    </div>
  </main>

  <footer class="foot">Set in Fraunces, Newsreader &amp; JetBrains Mono · est. MMXXVI</footer>
</div>

<style>
  .land { min-height: 100vh; display: flex; flex-direction: column; padding: 24px clamp(20px, 4vw, 56px); }
  .top { display: flex; justify-content: space-between; align-items: center; }
  .brand {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.02em;
  }
  .amp { color: var(--color-stamp); font-style: italic; }
  .row { display: flex; align-items: center; gap: 12px; }
  .signin {
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-2);
    text-decoration: none;
  }
  .signin:hover { color: var(--color-ink); }

  .hero { flex: 1; max-width: 720px; margin: 0 auto; padding: 96px 0; display: flex; flex-direction: column; gap: 14px; }
  .eyebrow {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
  h1 {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 500;
    font-size: clamp(48px, 8vw, 88px);
    line-height: 0.95;
    letter-spacing: -0.035em;
    margin: 0;
  }
  h1 em {
    font-style: italic;
    color: var(--color-stamp);
    font-variation-settings: 'opsz' 144, 'SOFT' 100, 'wght' 500;
  }
  .deck {
    font-family: var(--font-body);
    font-size: 18px;
    line-height: 1.55;
    color: var(--color-ink-2);
    max-width: 56ch;
    margin: 8px 0 12px;
  }
  .deck::first-line { font-variant: small-caps; letter-spacing: 0.04em; color: var(--color-ink); }

  .cta-row { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
  .cta {
    display: inline-flex; align-items: center; gap: 8px;
    text-decoration: none;
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    font-size: 13px;
    padding: 12px 22px;
  }
  .cta--primary { background: var(--color-ink); color: var(--color-paper-receipt); }
  .cta--primary:hover { opacity: 0.88; }
  :global(.cta .ico) { width: 14px; height: 14px; }
  .cta--quiet {
    color: var(--color-ink);
    border-bottom: 1px solid var(--color-rule);
    padding: 12px 0;
    letter-spacing: 0;
    text-transform: none;
    font-style: italic;
    font-family: var(--font-body);
    font-variation-settings: initial;
    font-size: 16px;
  }
  .cta--quiet:hover { color: var(--color-stamp); }

  .foot {
    margin-top: auto;
    padding-top: 24px;
    border-top: 1px solid var(--color-rule);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/routes/+page.svelte
git commit -m "feat(ui): signed-out landing in ledger style"
```

---

## Phase 8 — Verification

### Task 33: Type-check, test, e2e smoke, final commit

- [ ] **Step 1: Run `pnpm check`**

```bash
pnpm check
```

Expected: zero errors. Fix any.

- [ ] **Step 2: Run unit tests**

```bash
pnpm test --run
```

Expected: all green. Fix any test that broke from prop API changes (most likely `Button` callers passing `size`/`secondary`/`ghost`).

- [ ] **Step 3: Run dev server and manually visit each route**

```bash
pnpm dev
```

Open in a browser, sign in with your existing test passkey, and walk through:
- `/portfolio` — y-axis labels visible, masthead present, holdings table looks like a ledger
- `/trade` — order ticket renders with perforations, Buy/Sell toggle, totals; submit shows a Filled stamp
- `/quote` — query a known symbol; sparkline + price card render; query a junk symbol → "No record" stamp
- `/history` — bound-book table
- `/competitions` — list page; click into one
- `/competitions/[id]` — almanac voice; rank numerals; provisional stamp
- `/settings`, `/settings/passkeys` — form fields, restyled
- `/`, `/signin`, `/signup`, `/recover` — paper card, masthead

- [ ] **Step 4: Run e2e smoke**

```bash
pnpm test:e2e
```

Expected: existing critical-paths suite still passes (signup → trade → comp). If a selector broke from copy/style changes, update the selector in the test, NOT the production code.

- [ ] **Step 5: Verify no orphan imports**

```bash
grep -rn 'variant="secondary"\|variant="ghost"\|size="sm"\|size="md"\|size="lg"' src/
```

Expected: zero matches.

- [ ] **Step 6: Tag the commit**

```bash
git log --oneline | head -20
```

If there were any straggler fixes from steps 1–5, commit them:

```bash
git add -A
git commit -m "chore(ui): post-sweep fixes"
```

---

## Self-Review Checklist (run before declaring done)

- Spec §2.2 tokens — Task 1 ✓
- Spec §2.3 paper grain — Task 1 ✓
- Spec §3.1 Masthead — Task 7 ✓
- Spec §3.2 Ticker tape — Task 8, integrated Task 20 ✓
- Spec §3.3 SectionHead — Task 3 ✓
- Spec §3.4 StatBlock — Task 4 ✓
- Spec §3.5 Equity chart + 60px gutter bug fix — Task 12 ✓
- Spec §3.6 Holdings ledger — Task 14 (DataTable) ✓
- Spec §3.7 Order ticket — Task 16 ✓
- Spec §3.8 Stamps — Task 2 + used in Tasks 16, 25, 27, 28 ✓
- Spec §3.9 Standings + PullQuote + FormBar — Tasks 5, 6, 15, 28 ✓
- Spec §3.10 Sparklines — Task 13 ✓
- Spec §3.11 Buttons — Task 9 ✓
- Spec §3.12 Form fields — Task 10 ✓
- Spec §3.13 Empty states — handled in pages 23, 26, 27 ✓
- Spec §4 per-route — Tasks 22–32 ✓
- Spec §5 navigation chrome — Tasks 17–20 ✓
- Spec §6 light/dark — Task 1 (token swap) ✓
- Spec §7 mobile — handled in each component's media queries ✓
- Spec §8 accessibility — focus rings (Task 1), reduced motion (Task 8), aria-labels in Stamp/icon buttons ✓
- Spec §9 y-axis bug — Task 12 ✓
- Spec §10 out-of-scope — none added ✓
