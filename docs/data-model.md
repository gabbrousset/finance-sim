# data model

SQLite. All tables live in `finance.db`.

**ID format:** `cuid2` — collision-resistant, URL-safe, no UUID hyphen noise.  
**Timestamps:** UTC unix seconds (INTEGER). No timezone columns, no strings.  
**Dates (trading):** `YYYY-MM-DD` TEXT for NYSE calendar dates where time doesn't matter.  
**Money:** integer cents throughout. See [invariant 1](#money-is-integer-cents) and [tech-choices.md](./tech-choices.md#money-representation).

## schema

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

## invariants

### money is integer cents

`1000000` means `$10,000.00`. Floating-point arithmetic is never used for money — no rounding errors, no `0.1 + 0.2` surprises. The display layer (`lib/shared/money.ts`) converts to dollars for rendering. Nothing else touches floats.

See [tech-choices.md](./tech-choices.md#money-representation) for why this was a deliberate stack-level decision.

### append-only ledgers

`transactions` and `competition_trades` are immutable history. Rows are inserted; never updated or deleted. The current state of a portfolio — how many shares you hold — is always derivable by replaying the ledger.

`holdings` and `competition_holdings` are denormalized snapshots kept in sync to avoid replaying the ledger on every page load. If they ever diverge from the ledger, the ledger is the source of truth.

### personal and competition state are fully separated

Joining a competition does not touch personal `cash_cents` or personal `holdings`. Competition state lives in `competition_holdings` and `competition_cash`. A user can run a real portfolio and a competition portfolio independently.

### holdings rows deleted at 0 shares

A row in `holdings` (or `competition_holdings`) means you own a positive number of shares. When a sell brings shares to zero, the row is deleted. The `CHECK (shares > 0)` constraint enforces this at the DB level — an accidental upsert to 0 is an error.

This keeps portfolio queries simple: `SELECT * FROM holdings WHERE user_id = ?` returns only positions you actually hold.

### single source of truth for sessions

The `sessions` table is the authority. Cookies are opaque random values; the cookie value is hashed before lookup (`sessions.id` stores the hash). Revoking a session is a DELETE — no JWT invalidation list needed.

`auth_challenges` follow the same pattern: the challenge cookie value is hashed and stored in `id`.

## design notes

**Why SQLite?** Friend-group scale, single process, no infrastructure to operate. WAL mode handles concurrent reads from multiple browser tabs. See [tech-choices.md](./tech-choices.md#better-sqlite3).

**Why not store portfolio value?** Computed, not stored. Portfolio value depends on current market price, which changes constantly. The service layer computes it on request from holdings + live quote. Historical equity curves are computed from the ledger + cached EOD closes.

**Cache tables are not authoritative.** `quote_cache_live` and `quote_cache_eod` hold fetched prices for performance. If a cache row is missing, the system falls through to the real adapter. Stale live quotes (outside NYSE hours) are intentional — see [`market-data/`](./market-data/caching-strategy.md) for TTL policy.
