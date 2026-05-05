import { describe, it, expect, beforeEach } from 'vitest';
import { createDb, applyMigrations, schema } from '$lib/server/db/client';
import type { Db } from '$lib/server/db/client';
import { MockMarketData } from '$lib/server/market/mock';
import { CompetitionService } from './service';
import { toIsoDate } from '$lib/shared/dates';
import { eq, and } from 'drizzle-orm';

describe('CompetitionService', () => {
  let db: Db;
  let mkt: MockMarketData;
  let svc: CompetitionService;
  let nowSec = 1_700_000_000; // 2023-11-14ish

  beforeEach(() => {
    db = createDb(':memory:');
    applyMigrations(db);
    db.insert(schema.users)
      .values([
        { id: 'host', username: 'host', displayName: 'Host', cashCents: 0, createdAt: 0 },
        { id: 'guest', username: 'guest', displayName: 'Guest', cashCents: 0, createdAt: 0 }
      ])
      .run();
    mkt = new MockMarketData();
    svc = new CompetitionService(db, mkt, () => nowSec);
  });

  // ---- create ----

  describe('create', () => {
    it('stores comp, mints invite code, joins host with starting cash', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test Comp',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });

      expect(comp.id).toBeTruthy();
      expect(comp.name).toBe('Test Comp');
      expect(comp.hostId).toBe('host');
      expect(comp.type).toBe('live');
      expect(comp.status).toBe('open');
      expect(comp.inviteCode).toMatch(/^[A-Z2-9]{8}$/);
      expect(comp.startingCashCents).toBe(1_000_000);

      // host should be a member
      const members = db.select().from(schema.competitionMembers).all();
      expect(members).toHaveLength(1);
      expect(members[0]?.userId).toBe('host');

      // host should have cash
      const cash = db.select().from(schema.competitionCash).all();
      expect(cash).toHaveLength(1);
      expect(cash[0]?.cashCents).toBe(1_000_000);
    });

    it('invite code contains only valid base32 chars (no I, O, 0, 1)', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 500_000
      });
      expect(comp.inviteCode).toHaveLength(8);
      expect(comp.inviteCode).toMatch(/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/);
    });

    it('rejects empty name', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: '',
          type: 'live',
          startDateUnix: nowSec + 3600,
          endDateUnix: nowSec + 7200,
          startingCashCents: 1_000_000
        })
      ).toThrow(/name/i);
    });

    it('rejects name longer than 60 chars', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: 'a'.repeat(61),
          type: 'live',
          startDateUnix: nowSec + 3600,
          endDateUnix: nowSec + 7200,
          startingCashCents: 1_000_000
        })
      ).toThrow(/name/i);
    });

    it('rejects zero startingCashCents', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: 'Test',
          type: 'live',
          startDateUnix: nowSec + 3600,
          endDateUnix: nowSec + 7200,
          startingCashCents: 0
        })
      ).toThrow(/cash/i);
    });

    it('rejects startDate >= endDate', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: 'Test',
          type: 'live',
          startDateUnix: nowSec + 7200,
          endDateUnix: nowSec + 3600,
          startingCashCents: 1_000_000
        })
      ).toThrow(/start.*end|date/i);
    });

    it('rejects live comp with past startDate', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: 'Test',
          type: 'live',
          startDateUnix: nowSec - 3600, // past
          endDateUnix: nowSec + 3600,
          startingCashCents: 1_000_000
        })
      ).toThrow(/start/i);
    });

    it('rejects historical comp with future endDate', () => {
      expect(() =>
        svc.create({
          hostId: 'host',
          name: 'Test',
          type: 'historical',
          startDateUnix: nowSec - 7200,
          endDateUnix: nowSec + 3600, // future
          startingCashCents: 1_000_000
        })
      ).toThrow(/end/i);
    });

    it('accepts historical comp with past endDate', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Historical Test',
        type: 'historical',
        startDateUnix: nowSec - 7200,
        endDateUnix: nowSec - 3600,
        startingCashCents: 500_000
      });
      expect(comp.type).toBe('historical');
      expect(comp.status).toBe('open');
    });
  });

  // ---- findByInviteCode / findById ----

  describe('findByInviteCode and findById', () => {
    it('findByInviteCode returns the competition', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      const found = svc.findByInviteCode(comp.inviteCode);
      expect(found?.id).toBe(comp.id);
    });

    it('findByInviteCode returns null for unknown code', () => {
      expect(svc.findByInviteCode('XXXXXXXX')).toBeNull();
    });

    it('findById returns the competition', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      const found = svc.findById(comp.id);
      expect(found?.inviteCode).toBe(comp.inviteCode);
    });

    it('findById returns null for unknown id', () => {
      expect(svc.findById('nonexistent')).toBeNull();
    });
  });

  // ---- join ----

  describe('join', () => {
    let compId: string;

    beforeEach(() => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      compId = comp.id;
    });

    it('adds guest with starting cash', () => {
      svc.join(compId, 'guest');
      const members = db.select().from(schema.competitionMembers).all();
      expect(members).toHaveLength(2);
      const guestCash = db
        .select()
        .from(schema.competitionCash)
        .where(
          and(
            eq(schema.competitionCash.competitionId, compId),
            eq(schema.competitionCash.userId, 'guest')
          )
        )
        .get();
      expect(guestCash?.cashCents).toBe(1_000_000);
    });

    it('is idempotent — joining twice does not duplicate row', () => {
      svc.join(compId, 'guest');
      svc.join(compId, 'guest');
      const members = db
        .select()
        .from(schema.competitionMembers)
        .where(eq(schema.competitionMembers.competitionId, compId))
        .all();
      expect(members).toHaveLength(2);
    });

    it('refuses to join a finished comp', () => {
      // Force status to finished
      db.update(schema.competitions)
        .set({ status: 'finished' })
        .where(eq(schema.competitions.id, compId))
        .run();
      expect(() => svc.join(compId, 'guest')).toThrow(/finished|status/i);
    });

    it('refuses to join a running comp', () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();
      expect(() => svc.join(compId, 'guest')).toThrow(/open|status/i);
    });

    it('throws for nonexistent comp', () => {
      expect(() => svc.join('bad-id', 'guest')).toThrow();
    });
  });

  // ---- tradeInComp (live) ----

  describe('tradeInComp - live', () => {
    let compId: string;

    beforeEach(() => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Live Comp',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      compId = comp.id;
    });

    it('requires running status for live comp', async () => {
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 1, priceCents: 15000 })
      ).rejects.toThrow(/running|status/i);
    });

    it('buys shares, debits cash, records trade', async () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();

      await svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 3, priceCents: 19000 });

      const cash = db
        .select()
        .from(schema.competitionCash)
        .where(
          and(
            eq(schema.competitionCash.competitionId, compId),
            eq(schema.competitionCash.userId, 'host')
          )
        )
        .get();
      expect(cash?.cashCents).toBe(1_000_000 - 3 * 19000);

      const holdings = db.select().from(schema.competitionHoldings).all();
      expect(holdings).toHaveLength(1);
      expect(holdings[0]?.symbol).toBe('AAPL');
      expect(holdings[0]?.shares).toBe(3);

      const trades = db.select().from(schema.competitionTrades).all();
      expect(trades).toHaveLength(1);
      expect(trades[0]?.priceCents).toBe(19000);
      expect(trades[0]?.shares).toBe(3);
    });

    it('sells shares, credits cash, removes holding at zero', async () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();

      await svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 5, priceCents: 19000 });
      await svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: -5, priceCents: 20000 });

      const cash = db
        .select()
        .from(schema.competitionCash)
        .where(
          and(
            eq(schema.competitionCash.competitionId, compId),
            eq(schema.competitionCash.userId, 'host')
          )
        )
        .get();
      expect(cash?.cashCents).toBe(1_000_000 - 5 * 19000 + 5 * 20000);

      const holdings = db.select().from(schema.competitionHoldings).all();
      expect(holdings).toHaveLength(0);
    });

    it('throws on insufficient cash', async () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 100, priceCents: 19000 })
      ).rejects.toThrow(/cash/i);
    });

    it('throws on insufficient shares when selling', async () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: -5, priceCents: 20000 })
      ).rejects.toThrow(/shares|holding/i);
    });

    it('throws on invalid symbol', async () => {
      db.update(schema.competitions)
        .set({ status: 'running' })
        .where(eq(schema.competitions.id, compId))
        .run();
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: '123!', shares: 1, priceCents: 15000 })
      ).rejects.toThrow(/symbol/i);
    });
  });

  // ---- tradeInComp (historical) ----

  describe('tradeInComp - historical', () => {
    const startUnix = 1_700_000_000 - 86400 * 30; // 30 days ago
    const endUnix = 1_700_000_000 - 86400 * 1;   // yesterday
    let compId: string;

    beforeEach(() => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Historical Comp',
        type: 'historical',
        startDateUnix: startUnix,
        endDateUnix: endUnix,
        startingCashCents: 1_000_000
      });
      compId = comp.id;
    });

    it('pulls price from startDate close and ignores priceCents arg', async () => {
      const startIso = toIsoDate(startUnix);
      mkt.setHistorical('AAPL', startIso, 19000);

      await svc.tradeInComp({
        competitionId: compId,
        userId: 'host',
        symbol: 'AAPL',
        shares: 5,
        priceCents: 99999 // should be ignored
      });

      const cash = db
        .select()
        .from(schema.competitionCash)
        .where(
          and(
            eq(schema.competitionCash.competitionId, compId),
            eq(schema.competitionCash.userId, 'host')
          )
        )
        .get();
      expect(cash?.cashCents).toBe(1_000_000 - 5 * 19000);

      const trades = db.select().from(schema.competitionTrades).all();
      expect(trades[0]?.priceCents).toBe(19000);
    });

    it('throws when no price available for startDate', async () => {
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 1 })
      ).rejects.toThrow(/price/i);
    });

    it('requires open status for historical comp', async () => {
      // Force to finished
      db.update(schema.competitions)
        .set({ status: 'finished', finishedAt: nowSec - 1 })
        .where(eq(schema.competitions.id, compId))
        .run();
      const startIso = toIsoDate(startUnix);
      mkt.setHistorical('AAPL', startIso, 19000);
      await expect(
        svc.tradeInComp({ competitionId: compId, userId: 'host', symbol: 'AAPL', shares: 1 })
      ).rejects.toThrow(/open|status|finished/i);
    });
  });

  // ---- resolveHistorical ----

  describe('resolveHistorical', () => {
    let compId: string;

    beforeEach(() => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Historical',
        type: 'historical',
        startDateUnix: nowSec - 7200,
        endDateUnix: nowSec - 3600,
        startingCashCents: 500_000
      });
      compId = comp.id;
    });

    it('flips status to finished and sets finishedAt', () => {
      svc.resolveHistorical(compId);
      const comp = db.select().from(schema.competitions).where(eq(schema.competitions.id, compId)).get();
      expect(comp?.status).toBe('finished');
      expect(comp?.finishedAt).toBe(nowSec);
    });

    it('refuses if comp is not historical', () => {
      const liveComp = svc.create({
        hostId: 'host',
        name: 'Live',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      expect(() => svc.resolveHistorical(liveComp.id)).toThrow(/historical/i);
    });

    it('refuses if comp is already finished', () => {
      svc.resolveHistorical(compId);
      expect(() => svc.resolveHistorical(compId)).toThrow(/finished/i);
    });

    it('throws for nonexistent comp', () => {
      expect(() => svc.resolveHistorical('bad-id')).toThrow();
    });
  });

  // ---- tickStatuses ----

  describe('tickStatuses', () => {
    it('flips open live comp to running at startDate', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Live',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });

      // advance past startDate
      nowSec += 4000;
      svc.tickStatuses();

      const updated = db.select().from(schema.competitions).where(eq(schema.competitions.id, comp.id)).get();
      expect(updated?.status).toBe('running');
    });

    it('flips running live comp to finished at endDate and sets finishedAt', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Live',
        type: 'live',
        startDateUnix: nowSec + 100,
        endDateUnix: nowSec + 200,
        startingCashCents: 1_000_000
      });

      // advance past endDate
      nowSec += 300;
      svc.tickStatuses();

      const updated = db.select().from(schema.competitions).where(eq(schema.competitions.id, comp.id)).get();
      expect(updated?.status).toBe('finished');
      expect(updated?.finishedAt).toBe(nowSec);
    });

    it('leaves historical comps alone', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Historical',
        type: 'historical',
        startDateUnix: nowSec - 7200,
        endDateUnix: nowSec - 3600,
        startingCashCents: 500_000
      });

      svc.tickStatuses();

      const updated = db.select().from(schema.competitions).where(eq(schema.competitions.id, comp.id)).get();
      expect(updated?.status).toBe('open'); // unchanged
    });
  });

  // ---- getDashboard ----

  describe('getDashboard', () => {
    let compId: string;

    beforeEach(() => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Dash Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      compId = comp.id;
      svc.join(compId, 'guest');
    });

    it('returns null for nonexistent comp', () => {
      expect(svc.getDashboard('bad-id', 'host')).toBeNull();
    });

    it('returns full dashboard for host', () => {
      const dash = svc.getDashboard(compId, 'host');
      expect(dash).not.toBeNull();
      expect(dash!.competition.id).toBe(compId);
      expect(dash!.isHost).toBe(true);
      expect(dash!.isMember).toBe(true);
      expect(dash!.myCashCents).toBe(1_000_000);
      expect(dash!.myHoldings).toHaveLength(0);
      expect(dash!.members).toHaveLength(2);
    });

    it('returns correct data for guest', () => {
      const dash = svc.getDashboard(compId, 'guest');
      expect(dash!.isHost).toBe(false);
      expect(dash!.isMember).toBe(true);
      expect(dash!.myCashCents).toBe(1_000_000);
    });

    it('returns isMember=false for non-member user', () => {
      // Add a third user
      db.insert(schema.users)
        .values({ id: 'outsider', username: 'outsider', displayName: 'Outsider', cashCents: 0, createdAt: 0 })
        .run();
      const dash = svc.getDashboard(compId, 'outsider');
      expect(dash!.isMember).toBe(false);
      expect(dash!.myCashCents).toBe(0);
      expect(dash!.myHoldings).toHaveLength(0);
    });

    it('returns members with displayName', () => {
      const dash = svc.getDashboard(compId, 'host');
      const hostMember = dash!.members.find((m) => m.userId === 'host');
      expect(hostMember?.displayName).toBe('Host');
    });
  });

  // ---- setShareResults ----

  describe('setShareResults', () => {
    it('updates shareResults to true (1)', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      svc.setShareResults(comp.id, true);
      const updated = db.select().from(schema.competitions).where(eq(schema.competitions.id, comp.id)).get();
      expect(updated?.shareResults).toBe(1);
    });

    it('updates shareResults to false (0)', () => {
      const comp = svc.create({
        hostId: 'host',
        name: 'Test',
        type: 'live',
        startDateUnix: nowSec + 3600,
        endDateUnix: nowSec + 7200,
        startingCashCents: 1_000_000
      });
      svc.setShareResults(comp.id, true);
      svc.setShareResults(comp.id, false);
      const updated = db.select().from(schema.competitions).where(eq(schema.competitions.id, comp.id)).get();
      expect(updated?.shareResults).toBe(0);
    });
  });
});
