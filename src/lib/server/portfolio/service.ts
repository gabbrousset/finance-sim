import { eq, and, desc } from 'drizzle-orm';
import { createId } from '@paralleldrive/cuid2';
import type { Db } from '$lib/server/db/client';
import { schema } from '$lib/server/db/client';
import { normalizeSymbol, isValidSymbol } from '$lib/shared/symbols';

export interface Holding {
  symbol: string;
  shares: number;
  priceCents: number;
  valueCents: number;
}

export interface Valuation {
  cashCents: number;
  holdings: Holding[];
  totalCents: number;
}

export interface Transaction {
  id: string;
  symbol: string;
  shares: number;
  priceCents: number;
  executedAt: number;
}

export class PortfolioService {
  private now: () => number;

  constructor(
    private db: Db,
    now?: () => number
  ) {
    this.now = now ?? (() => Math.floor(Date.now() / 1000));
  }

  buy(userId: string, symbol: string, shares: number, priceCents: number): void {
    const sym = normalizeSymbol(symbol);
    if (!isValidSymbol(sym)) throw new Error(`Invalid symbol: ${symbol}`);
    if (shares <= 0) throw new Error('shares must be > 0');

    this.db.transaction((tx) => {
      const user = tx
        .select({ cashCents: schema.users.cashCents })
        .from(schema.users)
        .where(eq(schema.users.id, userId))
        .get();

      if (!user) throw new Error(`User not found: ${userId}`);

      const cost = shares * priceCents;
      if (user.cashCents < cost) {
        throw new Error(`Insufficient cash: need ${cost}, have ${user.cashCents}`);
      }

      const newCash = user.cashCents - cost;

      // Check existing holding
      const existing = tx
        .select({ shares: schema.holdings.shares })
        .from(schema.holdings)
        .where(
          and(eq(schema.holdings.userId, userId), eq(schema.holdings.symbol, sym))
        )
        .get();

      if (existing) {
        tx.update(schema.holdings)
          .set({ shares: existing.shares + shares })
          .where(
            and(eq(schema.holdings.userId, userId), eq(schema.holdings.symbol, sym))
          )
          .run();
      } else {
        tx.insert(schema.holdings)
          .values({ userId, symbol: sym, shares })
          .run();
      }

      tx.update(schema.users)
        .set({ cashCents: newCash })
        .where(eq(schema.users.id, userId))
        .run();

      tx.insert(schema.transactions)
        .values({
          id: createId(),
          userId,
          symbol: sym,
          shares,
          priceCents,
          executedAt: this.now()
        })
        .run();
    });
  }

  sell(userId: string, symbol: string, shares: number, priceCents: number): void {
    const sym = normalizeSymbol(symbol);
    if (!isValidSymbol(sym)) throw new Error(`Invalid symbol: ${symbol}`);
    if (shares <= 0) throw new Error('shares must be > 0');

    this.db.transaction((tx) => {
      const user = tx
        .select({ cashCents: schema.users.cashCents })
        .from(schema.users)
        .where(eq(schema.users.id, userId))
        .get();

      if (!user) throw new Error(`User not found: ${userId}`);

      const existing = tx
        .select({ shares: schema.holdings.shares })
        .from(schema.holdings)
        .where(
          and(eq(schema.holdings.userId, userId), eq(schema.holdings.symbol, sym))
        )
        .get();

      if (!existing) throw new Error(`No holding for symbol: ${sym}`);
      if (existing.shares < shares) {
        throw new Error(`Insufficient shares: own ${existing.shares}, tried to sell ${shares}`);
      }

      const newShares = existing.shares - shares;
      const proceeds = shares * priceCents;

      if (newShares === 0) {
        tx.delete(schema.holdings)
          .where(
            and(eq(schema.holdings.userId, userId), eq(schema.holdings.symbol, sym))
          )
          .run();
      } else {
        tx.update(schema.holdings)
          .set({ shares: newShares })
          .where(
            and(eq(schema.holdings.userId, userId), eq(schema.holdings.symbol, sym))
          )
          .run();
      }

      tx.update(schema.users)
        .set({ cashCents: user.cashCents + proceeds })
        .where(eq(schema.users.id, userId))
        .run();

      tx.insert(schema.transactions)
        .values({
          id: createId(),
          userId,
          symbol: sym,
          shares: -shares,
          priceCents,
          executedAt: this.now()
        })
        .run();
    });
  }

  valuate(userId: string, quotes: Map<string, number>): Valuation {
    const user = this.db
      .select({ cashCents: schema.users.cashCents })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .get();

    const cashCents = user?.cashCents ?? 0;

    const rows = this.db
      .select({ symbol: schema.holdings.symbol, shares: schema.holdings.shares })
      .from(schema.holdings)
      .where(eq(schema.holdings.userId, userId))
      .all();

    const holdings: Holding[] = rows.map((row) => {
      const priceCents = quotes.get(row.symbol) ?? 0;
      const valueCents = row.shares * priceCents;
      return { symbol: row.symbol, shares: row.shares, priceCents, valueCents };
    });

    const totalCents = cashCents + holdings.reduce((sum, h) => sum + h.valueCents, 0);

    return { cashCents, holdings, totalCents };
  }

  transactionLedger(userId: string): Transaction[] {
    return this.db
      .select({
        id: schema.transactions.id,
        symbol: schema.transactions.symbol,
        shares: schema.transactions.shares,
        priceCents: schema.transactions.priceCents,
        executedAt: schema.transactions.executedAt
      })
      .from(schema.transactions)
      .where(eq(schema.transactions.userId, userId))
      .orderBy(desc(schema.transactions.executedAt), desc(schema.transactions.id))
      .all();
  }
}
