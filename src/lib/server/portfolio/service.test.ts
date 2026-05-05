import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { eq } from 'drizzle-orm';
import { PortfolioService } from './service';

describe('PortfolioService', () => {
  let db: Db;
  let svc: PortfolioService;
  const userId = 'u1';

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users).values({
      id: userId,
      username: 'alice',
      displayName: 'Alice',
      cashCents: 1_000_000,
      createdAt: 0
    }).run();
    svc = new PortfolioService(db);
  });

  describe('buy', () => {
    it('adds holdings and debits cash', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      const u = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
      expect(u?.cashCents).toBe(1_000_000 - 5 * 19000);
      const holdings = db.select().from(schema.holdings).all();
      expect(holdings).toHaveLength(1);
      expect(holdings[0]?.shares).toBe(5);
      expect(holdings[0]?.symbol).toBe('AAPL');
    });

    it('rejects when insufficient cash', () => {
      expect(() => svc.buy(userId, 'AAPL', 100, 19000)).toThrow(/cash/i);
    });

    it('rejects zero shares', () => {
      expect(() => svc.buy(userId, 'AAPL', 0, 19000)).toThrow();
    });

    it('rejects negative shares', () => {
      expect(() => svc.buy(userId, 'AAPL', -5, 19000)).toThrow();
    });

    it('rejects invalid symbol', () => {
      expect(() => svc.buy(userId, '123!', 1, 19000)).toThrow(/symbol/i);
    });

    it('normalizes symbol (lowercase input)', () => {
      svc.buy(userId, 'aapl', 5, 19000);
      const holdings = db.select().from(schema.holdings).all();
      expect(holdings[0]?.symbol).toBe('AAPL');
    });

    it('accumulates shares when buying more of existing symbol', () => {
      svc.buy(userId, 'AAPL', 3, 19000);
      svc.buy(userId, 'AAPL', 2, 19500);
      const holdings = db.select().from(schema.holdings).all();
      expect(holdings).toHaveLength(1);
      expect(holdings[0]?.shares).toBe(5);
    });

    it('inserts a transaction record', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      const txns = db.select().from(schema.transactions).all();
      expect(txns).toHaveLength(1);
      expect(txns[0]?.symbol).toBe('AAPL');
      expect(txns[0]?.shares).toBe(5);
      expect(txns[0]?.priceCents).toBe(19000);
    });
  });

  describe('sell', () => {
    it('decrements shares and credits cash', () => {
      svc.buy(userId, 'AAPL', 10, 19000);
      const cashAfterBuy = 1_000_000 - 10 * 19000;
      svc.sell(userId, 'AAPL', 4, 20000);
      const u = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
      expect(u?.cashCents).toBe(cashAfterBuy + 4 * 20000);
      const holdings = db.select().from(schema.holdings).all();
      expect(holdings[0]?.shares).toBe(6);
    });

    it('deletes holdings row when shares hit zero', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      svc.sell(userId, 'AAPL', 5, 19500);
      expect(db.select().from(schema.holdings).all()).toHaveLength(0);
    });

    it('rejects selling more shares than owned', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      expect(() => svc.sell(userId, 'AAPL', 6, 19500)).toThrow();
    });

    it('rejects selling unowned symbol', () => {
      expect(() => svc.sell(userId, 'AAPL', 1, 19500)).toThrow();
    });

    it('rejects zero shares', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      expect(() => svc.sell(userId, 'AAPL', 0, 19000)).toThrow();
    });

    it('rejects negative shares', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      expect(() => svc.sell(userId, 'AAPL', -1, 19000)).toThrow();
    });

    it('inserts a transaction record with negative shares', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      svc.sell(userId, 'AAPL', 3, 20000);
      const txns = db
        .select()
        .from(schema.transactions)
        .orderBy(schema.transactions.executedAt)
        .all();
      expect(txns).toHaveLength(2);
      expect(txns[1]?.shares).toBe(-3);
      expect(txns[1]?.priceCents).toBe(20000);
    });
  });

  describe('valuate', () => {
    it('combines cash with holdings priced by caller', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      svc.buy(userId, 'MSFT', 2, 38000);
      const quotes = new Map([
        ['AAPL', 20000],
        ['MSFT', 39000]
      ]);
      const v = svc.valuate(userId, quotes);
      expect(v.cashCents).toBe(1_000_000 - 5 * 19000 - 2 * 38000);
      expect(v.holdings).toHaveLength(2);
      expect(v.totalCents).toBe(v.cashCents + 5 * 20000 + 2 * 39000);
    });

    it('returns empty holdings and full cash for user with no positions', () => {
      const v = svc.valuate(userId, new Map());
      expect(v.cashCents).toBe(1_000_000);
      expect(v.holdings).toHaveLength(0);
      expect(v.totalCents).toBe(1_000_000);
    });

    it('falls back to priceCents=0 when quote is missing', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      const v = svc.valuate(userId, new Map());
      expect(v.holdings[0]?.priceCents).toBe(0);
      expect(v.holdings[0]?.valueCents).toBe(0);
    });

    it('valueCents equals shares * priceCents for each holding', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      const quotes = new Map([['AAPL', 20000]]);
      const v = svc.valuate(userId, quotes);
      expect(v.holdings[0]?.valueCents).toBe(5 * 20000);
    });
  });

  describe('transactionLedger', () => {
    it('returns empty array for user with no transactions', () => {
      expect(svc.transactionLedger(userId)).toHaveLength(0);
    });

    it('returns newest first', () => {
      // Use now injection to give distinct timestamps
      let t = 1_000_000;
      const svcWithClock = new PortfolioService(db, () => t);

      svcWithClock.buy(userId, 'AAPL', 5, 19000);
      t += 1;
      svcWithClock.buy(userId, 'MSFT', 2, 38000);
      t += 1;
      svcWithClock.sell(userId, 'AAPL', 1, 19500);

      const ledger = svcWithClock.transactionLedger(userId);
      expect(ledger).toHaveLength(3);
      // newest is the sell
      expect(ledger[0]?.symbol).toBe('AAPL');
      expect(ledger[0]?.shares).toBe(-1);
      // second is MSFT buy
      expect(ledger[1]?.symbol).toBe('MSFT');
      // oldest is first AAPL buy
      expect(ledger[2]?.symbol).toBe('AAPL');
      expect(ledger[2]?.shares).toBe(5);
    });

    it('includes correct transaction fields', () => {
      svc.buy(userId, 'AAPL', 5, 19000);
      const ledger = svc.transactionLedger(userId);
      expect(ledger[0]?.id).toBeTruthy();
      expect(ledger[0]?.symbol).toBe('AAPL');
      expect(ledger[0]?.shares).toBe(5);
      expect(ledger[0]?.priceCents).toBe(19000);
      expect(typeof ledger[0]?.executedAt).toBe('number');
    });
  });
});
