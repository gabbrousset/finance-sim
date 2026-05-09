# finance-sim v3 — UI Aesthetic: Ledger

**Status:** active
**Date:** 2026-05-08
**Supersedes:** [v3 design spec](2026-05-05-finance-sim-v3-design.md) §9.1 (Aesthetic) and §9.2 (Navigation chrome). All other v3 sections stand.
**Scope:** visual sweep only. No new finance affordances (day change %, per-holding P&L, allocation %, etc.) are introduced here — those land in a later phase.

## 1. The direction

A printed-ledger aesthetic. The app reads as a daily almanac of paper positions, not a fintech dashboard. The pun is the point: it's *paper* trading, so the UI is paper.

The voice flexes across three moods, all in one visual language:

- **Formal** — portfolio, history, settings. Editorial type, hairline rules, hand-set Fraunces numerals. The ledger book.
- **Warm-game** — competitions and friend-facing pages. Bold rank numerals, leader pull-quotes, "form bars," a champion stamp at resolution. The sports almanac inside the same paper.
- **Tactile-delight** — trade tickets, receipts, confirmations. Perforated edges, "Filled" stamps, duplicate watermarks. The stuff your hands touch.

Rejected directions documented for posterity: Linear/Vercel, Stripe, Editorial-serif (too quiet), Swiss/brutalist, Playful-color, Riso zine (great for one weekend, fatigues across six daily-use routes), Civic Plex form (good but anonymous), CRT terminal (great aesthetic for a dev-tools project — wrong here because friends should feel welcome).

## 2. Design tokens

### 2.1 Typography

Three families. All free, served via Google Fonts (preconnect + variable axes).

| Role | Family | Notes |
|---|---|---|
| Display (page titles, big numerals) | **Fraunces** (variable) | `opsz` 96–144, `SOFT` 0–100, `wght` 400–700. SOFT 30 for masthead, SOFT 0 for body display, SOFT 100 italic for stamps and amp accents. |
| Body, editorial copy | **Newsreader** (variable) | `opsz` 6–72, italic available. Body at `opsz` 16, decks at `opsz` 14 italic. |
| Tabular, labels, captions, code | **JetBrains Mono** | wght 400/500. Used for KPI labels, dates, edition numbers, sparkline foot-notes, form labels, ticker tape. |

`font-variant-numeric: tabular-nums lining-nums` on every numeric value. `font-feature-settings: "tnum"` as a backup. Money is set in Fraunces with the cents rendered at `0.55em`, raised `0.42em`, in `--ink-2` — the cents are deliberately quiet.

### 2.2 Color

Light is the canonical mode. Dark is "logbook by lamplight" — warm cream ink on near-black warm paper, not cool grey.

```css
:root {
  --paper:         #f1e9d4;  /* warm cream, primary surface */
  --paper-2:       #ebe2c8;  /* sidebar, alt surface */
  --paper-receipt: #fbf6e6;  /* receipts, order tickets */
  --ink:           #16110a;  /* primary text */
  --ink-2:         #4d4232;  /* secondary text */
  --ink-3:         #8a7e66;  /* JBM labels, captions */
  --rule:          #b9ad8e;  /* hairline rules */
  --rule-soft:     #d4c8a8;  /* dotted/soft dividers */
  --gain:          #305e3f;  /* forest-green ink */
  --loss:          #8a2a2a;  /* oxblood */
  --brass:         #9b7a32;  /* rare accent — pull-quote edge, baselines */
  --stamp:         #973128;  /* rotated stamps, amp accents */
}

.dark {
  --paper:         #14110b;
  --paper-2:       #1c1810;
  --paper-receipt: #1f1c14;
  --ink:           #ede4c8;
  --ink-2:         #b8ad8f;
  --ink-3:         #7a6f55;
  --rule:          #3a3324;
  --rule-soft:     #2a2519;
  --gain:          #87c19a;
  --loss:          #d49693;
  --brass:         #c9a25b;
  --stamp:         #d49693;
}
```

Color rules:
- Buttons are `--ink` on `--paper-receipt` (or inverse on submit). Never green or red.
- `--gain` and `--loss` are reserved for signed values and form bars. Never for chrome.
- `--stamp` is reserved for status stamps, the `&` accent in the wordmark, and the "rank I" highlight in standings. Never for body text.
- `--brass` is decorative only — pull-quote borders, dashed equity baseline.

### 2.3 Texture

The body has a subtle paper grain — an inline SVG turbulence noise at ~6% opacity, fixed-attachment so it doesn't tile-jump on scroll. **Receipts and tickets are clean** — no grain — so the contained type stays readable. Sidebar gets a `linear-gradient` to suggest a bound spine on its right edge.

```css
body {
  background:
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240'>...</svg>"),
    var(--paper);
  background-attachment: fixed;
}
```

Full SVG kept in `src/lib/assets/paper-grain.css` for reuse.

### 2.4 Spacing and rhythm

8px base, 4px sub-grid. Body line-height 1.55 → 24.8px → use 24px or 32px section gaps. Page max-width: 1100px main + 200px rail. Reading measure for editorial copy capped at ~64ch.

## 3. Component vocabulary

These are the named pieces. Each one has one obvious place to live in code.

### 3.1 Masthead (page-level, not app-level)

A masthead appears once per top-level page. Three columns:

```
[ vol/edition · est. ]   [ FINANCE&SIM ]   [ weekday · date · status ]
                         A daily ledger…
─────────────────────────────────────────  (3px double rule)
```

- `&` is set in italic Fraunces with `SOFT 100` and `--stamp` color. It's the brand mark.
- Mobile: side blocks stack below the wordmark or hide entirely.

### 3.2 Ticker tape

A sticky band at the very top of the app shell (above the masthead, replaces the existing mobile top header). Slim, ink background, JetBrains Mono small, slow horizontal marquee. Content: the user's holdings + a short watchlist (S&P, QQQ, the symbols they recently quoted). 60s loop, paused on `prefers-reduced-motion`.

### 3.3 Section header

```
[ small TAB · stamp color ]  [ Section title ]   [ as-of · meta · ink-3 ]
─────────────────────────────────────────────  (1px solid --rule)
```

Title is Fraunces 28–38px, `opsz` 96, `wght` 500. The TAB is JBM 9px caps in `--paper` on `--stamp` background, used to tag the section ("STANDINGS", "ORDER TICKET", "QUOTE", etc).

### 3.4 Stat block (KPIs)

Three-up grid, no boxes. Fields are separated by a vertical 1px `--rule`. Label in JBM 10px caps. Value in Fraunces 28–40px tabular. Optional delta line below in JBM 11px with `.pos`/`.neg` colors. **No card surfaces — the page itself is the surface.**

### 3.5 Equity chart (uPlot)

uPlot configured to look hand-drawn:

- Line: `--ink`, 1.4px, `linejoin: round`. No fill.
- Baseline at start value: dashed, `--brass`, 0.6 opacity.
- Y-axis labels: JBM 10px, `--ink-3`, right-aligned, prefixed `$`. **Reserve a 60px-wide axis gutter** so labels never clip (this fixes the "00.00" bug from screenshot 9).
- X-axis: JBM 10px caps, dates like "Apr 8" / "May 6". A "May 8 / 2026" terminal stamp at the right edge.
- Grid: dotted `--rule-soft`, 4 horizontal lines max. No vertical grid.
- Terminal point: 3.5px `--stamp` filled circle on the latest value, with the value annotated above it in italic Fraunces 11px.
- Caption above the chart, italic Newsreader: *"Account equity, last thirty days, drawn at close."* with a "Fig. I" tag right-aligned in JBM caps.

### 3.6 Holdings ledger (table)

Header row: JBM 10px caps `--ink-3`, bottom border 1.5px solid `--ink`. Body rows: 16px vertical padding, hairline `--rule-soft` between rows. Final row has a 1px solid `--ink` border-bottom. Symbol cell uses Fraunces 20px wght 600. Numeric cells right-aligned, JBM 14px tabular. Position (final money column) in Fraunces 18px tabular wght 500.

A `Last 30d` column holds a per-row sparkline (see 3.10).

A totals row at the bottom: JBM caps label "Total at market" + Fraunces 18px wght 600 number.

### 3.7 Order ticket

The flagship skeuomorphic component.

- Surface: `--paper-receipt`, with a soft drop-shadow `0 14px 28px -20px rgba(22,17,10,0.22)` and a hairline highlight on top.
- Perforated edges: top and bottom, via a `radial-gradient` `8px×8px` repeating pattern that paints `--paper`-color circles into the ticket edge.
- Optional `dup` watermark: italic Fraunces 10px, `--stamp` at 0.55 opacity, rotated -2°, top-right corner. Reads "— duplicate · file copy —".
- Header: ticket title left ("Order Ticket"), meta right (no., date, time in JBM caps).
- Buy/Sell toggle: 1.5px solid `--ink` border, JBM caps, active segment inverted to `--ink` background with `--paper-receipt` text.
- Fields: JBM caps label above; value typeset in Fraunces 22px wght 500 with a 1.5px solid `--ink` underline. Hint text in italic Newsreader 11px right-aligned.
- Totals block: dashed top rule, JBM caps labels left, JBM tabular values right. Final "Total cost" row gets a solid 1.5px top rule and Fraunces 18px wght 600 value.
- "Place order" button: full-width, `--ink` background, `--paper-receipt` text, Fraunces caps, `letter-spacing 0.18em`. The button sits just inside the ticket — it's part of the ticket.

On submit success:
- A "Filled" stamp animates rotated -6° into the bottom-right of the ticket: hollow `--stamp` border 3.5px, italic Fraunces 22px caps with 0.22em tracking, "— booked at HH:MM —" subline 8.5px JBM caps. The animation is a 280ms spring (CSS `cubic-bezier(0.34, 1.56, 0.64, 1)`) on `transform: scale(0.6) rotate(-6deg) → scale(1) rotate(-6deg)` plus opacity. `prefers-reduced-motion`: skip the animation, just appear.
- The form fields lock (read-only). A "Trade again" link appears below the ticket.

### 3.8 Stamps (status indicators)

A reusable `<Stamp>` component. Variants:

| Variant | Where | Color |
|---|---|---|
| `Filled` | trade success | `--stamp` |
| `Booked` | smaller variant of Filled, used inline in receipts | `--stamp` |
| `Provisional` | open competition status | `--stamp` |
| `Final` | resolved competition | `--ink` |
| `Champion: <name>` | resolved comp leader card | `--stamp` |
| `Closed` / `Delisted` | history rows for sold-out positions | `--ink-2` |
| `No record` | quote error state | `--loss` |

All stamps share: hollow border 2–3.5px, italic Fraunces (`opsz` matched to size, `SOFT 100`, `wght` 700), uppercase, 0.16–0.22em tracking, rotation between -6° and -3°, optional 8px caps subline.

### 3.9 Standings / sports almanac block

For `/competitions/[id]`:

- A leader pull-quote at the top: 44px circular `--ink` badge with the leader's initial, paired with an italic Fraunces 17px line: *"Marie up 14.2% with two weeks to go — in good form."* Border-left 3px `--stamp` on the surrounding container.
- Standings table: `rank` cell uses italic Fraunces 26px wght 600, Roman numerals "I, II, III, IV". Rank I is in `--stamp`. `name` cell uses Newsreader 15px with an italic 11px caption underneath (e.g. *"— in good form"*, *"— TSLA holdout"*, *"— testing his luck"*). The captions are derived heuristically from each player's recent activity (see plan).
- Form bar: a 6-segment row of 6×8px swatches showing each of the player's last six trading days within the comp. Each swatch's color is the sign of that day's net P&L delta on the player's *comp* portfolio: `--gain` if up, `--loss` if down, `--rule-soft` if flat (no change or no activity). Days with no holdings movement still count as flat — the bar is dense, not sparse.
- "From the desk" editorial note: Newsreader 13px, `--ink-2`, with a JBM caps subhead in `--stamp`. Auto-generated from stand spread + recent moves; falls back to nothing if no notable changes.
- Status stamp at the bottom-right: `Provisional — sealed [date]` while open, `Final — Champion: [name]` once resolved.

### 3.10 Sparklines

uPlot mini-charts: 1.2px stroke, `--gain` if up over the window, `--loss` if down, `--ink` if flat. No axes, no fill. 28px tall in tables, 38px on the quote card.

### 3.11 Buttons

Two flavors:

- **Primary** (sparingly): `--ink` background, `--paper-receipt` text, Fraunces caps with 0.18em tracking, 11px-13px depending on context. No border-radius beyond 2px. Used for "Place order", "Save", "Sign in".
- **Quiet** (default): underlined Newsreader, no chrome. "view portfolio", "trade", "manage passkeys".

No green or red on buttons — even destructive actions ("Revoke passkey", "Delete account") use `--ink` chrome and rely on the modal's copy to convey weight. The single allowed exception is the Delete-Account confirmation, which gets a small `--loss` text indicator next to its button.

### 3.12 Form fields

JBM caps label, value typeset in Fraunces 20px wght 500 with a 1.5px solid `--ink` underline. No box. Errors render below the underline in JBM 11px `--loss`. Focus state thickens the underline to 2px.

### 3.13 Empty states

Newsreader italic 14px in `--ink-2`, with a Newsreader-underlined CTA link inline. e.g. *"No competitions yet — create one or join via invite link."* No illustrations.

## 4. Per-route specification

| Route | Eyebrow tab | Title | Notes |
|---|---|---|---|
| `/` (signed-out) | — | "Paper trading.<br>Real friends." | Full masthead at scale. Two CTAs (Sign in / Create account). One sample standings card below the fold for social proof. |
| `/signin` | `Account` | "Welcome back." | Single ticket-style card. Username field + Sign in button. "Use a recovery code →" link. |
| `/signup` | `Account` | "Open an account." | Username field, Create-account button. After passkey ceremony: a recovery-codes ticket renders, with a "Note these down" stamp. |
| `/recover` | `Account` | "Recovery." | Recovery code field + Continue button. |
| `/portfolio` | `I — Portfolio` | "The Portfolio." | Stat block (Cash / Holdings / Total), equity Fig. I, holdings ledger. Optional "From the desk" pull-quote summarizing the day's net move. |
| `/trade` | `II — Trade` | "Buy or sell." | Order Ticket card on the left. Right column on desktop: a small ledger of current holdings (read-only). Mobile: holdings stack below the ticket. |
| `/quote` | `III — Quote` | "Quote." | Symbol field + Get-quote button. Result renders as a research card (eyebrow symbol, italic company name, big Fraunces price, gain line, sparkline, "30-day · drawn at close" footnote). Errors render as a "No record" stamp inside the card. |
| `/history` | `IV — Ledger` | "The Ledger." | Bound-book table: Date · Type · Symbol · Shares · Price · Amount · Cash after. Year separators as small-caps centered rules ("MMXXVI"). Filter chips: This year / All time. |
| `/competitions` | `V — Competitions` | "Competitions." | Two sections: "Hosting" and "Joined". Each item is a small card with comp name, status stamp, member count, your standing. "Create new" → goes to `/competitions/new`. |
| `/competitions/new` | `V — Competitions` | "New competition." | Form-style: Name field, Type radio (Live / Historical), Start/End date pickers, Initial cash, Members invite. |
| `/competitions/[id]` | `Standings` | "<Comp name> '26" | Sports-almanac voice. Comp masthead, leader pull-quote, standings table with form bars, "From the desk" note, Provisional/Final stamp. Trade button visible only while open or live. |
| `/competitions/join/[code]` | `Invite` | "Join: <comp name>" | Single card with comp meta and a Join button. |
| `/settings` | `VI — Settings` | "Settings." | Sub-sections: Account (display name + Save), Security (link to passkeys page), Danger (delete-account). |
| `/settings/passkeys` | `VI — Settings` | "Passkeys." | Bound-book ledger: Date added · Device · Last used · Status. Per-row rename / revoke. "Add passkey" CTA top-right. |

## 5. Navigation chrome

The existing AppShell (sidebar on `md+`, bottom tab bar below) stays — sharpen, don't re-architect.

### 5.1 Sidebar (desktop)

- Surface: `--paper-2` with an inset `box-shadow: inset -3px 0 0 var(--rule-soft)` mimicking a bound-book spine.
- Brand wordmark: "finance&sim" in Fraunces 19px wght 600 with `&` in `--stamp` italic SOFT 100.
- Edition line below brand: "Vol III · No. 128" in JBM 9.5px caps `--ink-3`. Decorative. `No. NNN` = `count(distinct date(transactions.executed_at)) where user_id = ?` + 1 (clamped to ≥ 1, so a brand-new user sees "No. 1" on signup day).
- Nav items: Fraunces 15px wght 400 (active wght 600). Roman numeral prefix in JBM 9px caps `--ink-3` (active: `--stamp`). Dotted `--rule-soft` separator between items. Active item gets a 4px filled `--stamp` dot at the right edge.
- Bottom: user display name in Newsreader 13px, theme toggle + Sign-out link in JBM caps.

### 5.2 Bottom tab bar (mobile)

- Surface: `--paper-2`, top border 1px solid `--rule`.
- Item: lucide icon (current) at 20px + JBM 9px caps label.
- Active item: `--ink` color, the others `--ink-3`. No background fill on active — the typography weight does the work.

### 5.3 Mobile top header

Shrinks to just the brand wordmark (Fraunces 16px) + theme toggle + sign-out link. Ticker tape sits *above* this header.

## 6. Light / dark mode

Toggle remains in the sidebar (desktop) and mobile top header. `mode-watcher` (per v3 §UI) drives a `.dark` class on `<html>`. Tokens swap as defined in §2.2.

Things that change beyond color in dark mode:
- The body's noise SVG gets re-tinted with darker stops (separate data-URI for dark — kept in the same `paper-grain.css`).
- The ticker tape's ink/paper inverts correspondingly (the band is `--paper` on `--ink` in light → `--ink-2` on `--paper` in dark; i.e., it always feels "different" from the rest of the page).
- Stamps in dark use `--stamp` (a desaturated red) which has been tuned to stay legible on the dark warm-paper background.

## 7. Mobile

- Masthead: side blocks stack below the wordmark on `<800px`, or hide if space is tight. Wordmark scales down (Fraunces clamp 28–36px).
- Ticker tape: stays at the top.
- Stat block: 1-column stack instead of 3-up; each stat keeps its label/value relationship.
- Tables (holdings, history, standings): collapse to a row-per-card layout on `<640px`. Symbol/name + sparkline + value top-line, secondary fields below in JBM caps + values.
- Order ticket: full-width, perforations stay.
- Standings on mobile: pull-quote stays; form bars and italic captions stay; rank numerals remain large.

## 8. Accessibility

- All `--ink` / `--paper` and `--gain` / `--loss` combinations meet WCAG AA on body text. The stamp red on paper is fine for non-text decorative use only.
- Stamp animations and ticker marquee respect `prefers-reduced-motion`.
- All icon-only controls have `aria-label`.
- Focus rings: 2px solid `--ink` (light) / 2px solid `--ink-2` (dark), 2px offset. Never removed.

## 9. Bug fix bundled with this sweep

**Equity-curve y-axis labels clip to "00.00".** Visible in screenshot 9. Root cause: insufficient axis-label gutter in the uPlot config. Fix as part of §3.5: reserve a 60px-wide y-axis gutter and right-align labels within it. Verify against the largest legitimate value the user could plausibly hold (≥ `$100,000.00` in case of a bull comp).

## 10. Out of scope

Explicitly **not** in this sweep, deferred to later phases:

- Day change %, day change $
- Per-holding P&L (absolute and %)
- Allocation % per holding
- Last-updated timestamps on prices
- Company-name lookup beyond what's already returned by the existing market-data adapter (if symbol-only data is what we have, the holdings table renders symbol-only and the design tolerates it; the company name in mockups is decorative)
- Search/typeahead on the symbol input
- Charting beyond the existing 30-day window (no 1Y, 5Y, etc.)
- Real-time price ticking / WebSocket updates
- Notifications (in-app or email)

Any of these will be re-spec'd individually if/when added.

## 11. Implementation hand-off

A separate implementation plan covers phasing, file-level changes, and the TDD steps. See `docs/superpowers/plans/2026-05-08-ui-ledger-aesthetic.md` (to be written next).

## 12. Open questions

None. All decisions above are intentional. If something needs to change during implementation, update this spec — don't drift silently.
