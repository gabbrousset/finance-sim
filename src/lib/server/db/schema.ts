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
