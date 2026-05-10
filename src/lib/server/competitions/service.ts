import { eq, and, or } from 'drizzle-orm';
import { createId } from '@paralleldrive/cuid2';
import type { Db } from '$lib/server/db/client';
import { schema } from '$lib/server/db/client';
import type { MarketData } from '$lib/server/market/types';
import { normalizeSymbol, isValidSymbol } from '$lib/shared/symbols';
import { toIsoDate } from '$lib/shared/dates';

// Base32 alphabet: no I, O, 0, 1
const INVITE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateInviteCode(): string {
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += INVITE_ALPHABET[Math.floor(Math.random() * INVITE_ALPHABET.length)];
  }
  return code;
}

export interface CompetitionInput {
  hostId: string;
  name: string;
  type: 'live' | 'historical';
  startDateUnix: number;
  endDateUnix: number;
  startingCashCents: number;
}

export interface CompetitionRow {
  id: string;
  hostId: string;
  name: string;
  type: 'live' | 'historical';
  status: 'open' | 'running' | 'finished';
  inviteCode: string;
  startingCashCents: number;
  startDate: number;
  endDate: number;
  shareResults: number;
  createdAt: number;
  finishedAt: number | null;
}

export interface CompetitionDashboard {
  competition: CompetitionRow;
  isMember: boolean;
  isHost: boolean;
  myCashCents: number;
  myHoldings: { symbol: string; shares: number }[];
  members: { userId: string; displayName: string; joinedAt: number }[];
}

export class CompetitionService {
  constructor(
    private db: Db,
    private market: MarketData,
    private now: () => number = () => Math.floor(Date.now() / 1000)
  ) {}

  create(input: CompetitionInput): CompetitionRow {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 60) {
      throw new Error('name must be 1–60 characters');
    }
    if (input.startingCashCents <= 0) {
      throw new Error('startingCashCents must be > 0');
    }
    if (input.startDateUnix >= input.endDateUnix) {
      throw new Error('startDate must be before endDate');
    }

    const now = this.now();

    if (input.type === 'live') {
      if (input.startDateUnix < now - 60) {
        throw new Error('live comp startDate must be in the future');
      }
    } else {
      // historical
      if (input.endDateUnix > now) {
        throw new Error('historical comp endDate must be in the past');
      }
    }

    // Mint invite code with retry on collision
    let inviteCode = '';
    let comp: CompetitionRow | undefined;
    for (let attempt = 0; attempt < 10; attempt++) {
      inviteCode = generateInviteCode();
      const id = createId();
      try {
        this.db.transaction((tx) => {
          tx.insert(schema.competitions)
            .values({
              id,
              hostId: input.hostId,
              name,
              type: input.type,
              status: 'open',
              inviteCode,
              startingCashCents: input.startingCashCents,
              startDate: input.startDateUnix,
              endDate: input.endDateUnix,
              shareResults: 0,
              createdAt: now,
              finishedAt: null
            })
            .run();

          // Auto-join host
          tx.insert(schema.competitionMembers)
            .values({ competitionId: id, userId: input.hostId, joinedAt: now })
            .run();

          tx.insert(schema.competitionCash)
            .values({ competitionId: id, userId: input.hostId, cashCents: input.startingCashCents })
            .run();
        });

        comp = {
          id,
          hostId: input.hostId,
          name,
          type: input.type,
          status: 'open',
          inviteCode,
          startingCashCents: input.startingCashCents,
          startDate: input.startDateUnix,
          endDate: input.endDateUnix,
          shareResults: 0,
          createdAt: now,
          finishedAt: null
        };
        break;
      } catch (err: unknown) {
        const isUnique =
          err instanceof Error &&
          'code' in err &&
          (err as { code: string }).code === 'SQLITE_CONSTRAINT_UNIQUE';
        if (!isUnique) throw err;
        // retry on collision
      }
    }

    if (!comp) throw new Error('failed to generate unique invite code after 10 attempts');
    return comp;
  }

  findByInviteCode(code: string): CompetitionRow | null {
    const row = this.db
      .select()
      .from(schema.competitions)
      .where(eq(schema.competitions.inviteCode, code))
      .get();
    return row ?? null;
  }

  findById(id: string): CompetitionRow | null {
    const row = this.db
      .select()
      .from(schema.competitions)
      .where(eq(schema.competitions.id, id))
      .get();
    return row ?? null;
  }

  join(competitionId: string, userId: string): void {
    const comp = this.findById(competitionId);
    if (!comp) throw new Error(`Competition not found: ${competitionId}`);
    if (comp.status !== 'open') {
      throw new Error(`Cannot join competition with status '${comp.status}'. Must be 'open'.`);
    }

    // Check if already a member (idempotent)
    const existing = this.db
      .select()
      .from(schema.competitionMembers)
      .where(
        and(
          eq(schema.competitionMembers.competitionId, competitionId),
          eq(schema.competitionMembers.userId, userId)
        )
      )
      .get();

    if (existing) return;

    const now = this.now();
    this.db.transaction((tx) => {
      tx.insert(schema.competitionMembers)
        .values({ competitionId, userId, joinedAt: now })
        .run();
      tx.insert(schema.competitionCash)
        .values({ competitionId, userId, cashCents: comp.startingCashCents })
        .run();
    });
  }

  async tradeInComp(args: {
    competitionId: string;
    userId: string;
    symbol: string;
    shares: number;
    priceCents?: number;
  }): Promise<void> {
    const sym = normalizeSymbol(args.symbol);
    if (!isValidSymbol(sym)) throw new Error(`Invalid symbol: ${args.symbol}`);

    const comp = this.findById(args.competitionId);
    if (!comp) throw new Error(`Competition not found: ${args.competitionId}`);

    let priceCents: number;

    if (comp.type === 'live') {
      if (comp.status !== 'running') {
        throw new Error(`Live comp requires status 'running', got '${comp.status}'`);
      }
      if (args.priceCents == null) {
        throw new Error('priceCents is required for live competition trades');
      }
      priceCents = args.priceCents;
    } else {
      // historical
      if (comp.status !== 'open') {
        throw new Error(`Historical comp requires status 'open', got '${comp.status}'`);
      }
      const startIso = toIsoDate(comp.startDate);
      const price = await this.market.getCloseAt(sym, startIso);
      if (price == null) {
        throw new Error(`No price available for ${sym} at window start (${startIso})`);
      }
      priceCents = price;
    }

    const now = this.now();

    if (args.shares > 0) {
      // Buy
      const shares = args.shares;
      this.db.transaction((tx) => {
        const cashRow = tx
          .select()
          .from(schema.competitionCash)
          .where(
            and(
              eq(schema.competitionCash.competitionId, args.competitionId),
              eq(schema.competitionCash.userId, args.userId)
            )
          )
          .get();

        const currentCash = cashRow?.cashCents ?? 0;
        const cost = shares * priceCents;
        if (currentCash < cost) {
          throw new Error(`Insufficient cash: need ${cost}, have ${currentCash}`);
        }

        const existing = tx
          .select()
          .from(schema.competitionHoldings)
          .where(
            and(
              eq(schema.competitionHoldings.competitionId, args.competitionId),
              eq(schema.competitionHoldings.userId, args.userId),
              eq(schema.competitionHoldings.symbol, sym)
            )
          )
          .get();

        if (existing) {
          tx.update(schema.competitionHoldings)
            .set({ shares: existing.shares + shares })
            .where(
              and(
                eq(schema.competitionHoldings.competitionId, args.competitionId),
                eq(schema.competitionHoldings.userId, args.userId),
                eq(schema.competitionHoldings.symbol, sym)
              )
            )
            .run();
        } else {
          tx.insert(schema.competitionHoldings)
            .values({ competitionId: args.competitionId, userId: args.userId, symbol: sym, shares })
            .run();
        }

        tx.update(schema.competitionCash)
          .set({ cashCents: currentCash - cost })
          .where(
            and(
              eq(schema.competitionCash.competitionId, args.competitionId),
              eq(schema.competitionCash.userId, args.userId)
            )
          )
          .run();

        tx.insert(schema.competitionTrades)
          .values({
            id: createId(),
            competitionId: args.competitionId,
            userId: args.userId,
            symbol: sym,
            shares,
            priceCents,
            executedAt: now
          })
          .run();
      });
    } else if (args.shares < 0) {
      // Sell
      const sharesToSell = -args.shares;
      this.db.transaction((tx) => {
        const cashRow = tx
          .select()
          .from(schema.competitionCash)
          .where(
            and(
              eq(schema.competitionCash.competitionId, args.competitionId),
              eq(schema.competitionCash.userId, args.userId)
            )
          )
          .get();

        const existing = tx
          .select()
          .from(schema.competitionHoldings)
          .where(
            and(
              eq(schema.competitionHoldings.competitionId, args.competitionId),
              eq(schema.competitionHoldings.userId, args.userId),
              eq(schema.competitionHoldings.symbol, sym)
            )
          )
          .get();

        if (!existing) throw new Error(`No holding for symbol: ${sym}`);
        if (existing.shares < sharesToSell) {
          throw new Error(`Insufficient shares: own ${existing.shares}, tried to sell ${sharesToSell}`);
        }

        const newShares = existing.shares - sharesToSell;
        const proceeds = sharesToSell * priceCents;
        const currentCash = cashRow?.cashCents ?? 0;

        if (newShares === 0) {
          tx.delete(schema.competitionHoldings)
            .where(
              and(
                eq(schema.competitionHoldings.competitionId, args.competitionId),
                eq(schema.competitionHoldings.userId, args.userId),
                eq(schema.competitionHoldings.symbol, sym)
              )
            )
            .run();
        } else {
          tx.update(schema.competitionHoldings)
            .set({ shares: newShares })
            .where(
              and(
                eq(schema.competitionHoldings.competitionId, args.competitionId),
                eq(schema.competitionHoldings.userId, args.userId),
                eq(schema.competitionHoldings.symbol, sym)
              )
            )
            .run();
        }

        tx.update(schema.competitionCash)
          .set({ cashCents: currentCash + proceeds })
          .where(
            and(
              eq(schema.competitionCash.competitionId, args.competitionId),
              eq(schema.competitionCash.userId, args.userId)
            )
          )
          .run();

        tx.insert(schema.competitionTrades)
          .values({
            id: createId(),
            competitionId: args.competitionId,
            userId: args.userId,
            symbol: sym,
            shares: -sharesToSell,
            priceCents,
            executedAt: now
          })
          .run();
      });
    } else {
      throw new Error('shares must be non-zero');
    }
  }

  resolveHistorical(competitionId: string): void {
    const comp = this.findById(competitionId);
    if (!comp) throw new Error(`Competition not found: ${competitionId}`);
    if (comp.type !== 'historical') {
      throw new Error(`resolveHistorical only applies to historical competitions`);
    }
    if (comp.status === 'finished') {
      throw new Error(`Competition is already finished`);
    }

    this.db
      .update(schema.competitions)
      .set({ status: 'finished', finishedAt: this.now() })
      .where(eq(schema.competitions.id, competitionId))
      .run();
  }

  tickStatuses(): void {
    const now = this.now();

    const toTick = this.db
      .select()
      .from(schema.competitions)
      .where(
        or(
          and(
            eq(schema.competitions.status, 'open'),
            eq(schema.competitions.type, 'live')
          ),
          eq(schema.competitions.status, 'running')
        )
      )
      .all();

    for (const comp of toTick) {
      if (comp.type !== 'live') continue;

      // A live comp that has passed endDate goes directly to finished,
      // regardless of whether it passed through 'running' in a prior tick.
      if (comp.endDate <= now) {
        this.db
          .update(schema.competitions)
          .set({ status: 'finished', finishedAt: now })
          .where(eq(schema.competitions.id, comp.id))
          .run();
      } else if (comp.status === 'open' && comp.startDate <= now) {
        this.db
          .update(schema.competitions)
          .set({ status: 'running' })
          .where(eq(schema.competitions.id, comp.id))
          .run();
      }
    }
  }

  getDashboard(competitionId: string, userId: string): CompetitionDashboard | null {
    const comp = this.findById(competitionId);
    if (!comp) return null;

    const members = this.db
      .select({
        userId: schema.competitionMembers.userId,
        joinedAt: schema.competitionMembers.joinedAt,
        displayName: schema.users.displayName
      })
      .from(schema.competitionMembers)
      .innerJoin(schema.users, eq(schema.competitionMembers.userId, schema.users.id))
      .where(eq(schema.competitionMembers.competitionId, competitionId))
      .all();

    const cashRow = this.db
      .select()
      .from(schema.competitionCash)
      .where(
        and(
          eq(schema.competitionCash.competitionId, competitionId),
          eq(schema.competitionCash.userId, userId)
        )
      )
      .get();

    const holdingsRows = this.db
      .select({ symbol: schema.competitionHoldings.symbol, shares: schema.competitionHoldings.shares })
      .from(schema.competitionHoldings)
      .where(
        and(
          eq(schema.competitionHoldings.competitionId, competitionId),
          eq(schema.competitionHoldings.userId, userId)
        )
      )
      .all();

    const isMember = members.some((m) => m.userId === userId);
    const isHost = comp.hostId === userId;

    return {
      competition: comp,
      isMember,
      isHost,
      myCashCents: cashRow?.cashCents ?? 0,
      myHoldings: holdingsRows,
      members: members.map((m) => ({ userId: m.userId, displayName: m.displayName, joinedAt: m.joinedAt }))
    };
  }

  setShareResults(competitionId: string, value: boolean): void {
    this.db
      .update(schema.competitions)
      .set({ shareResults: value ? 1 : 0 })
      .where(eq(schema.competitions.id, competitionId))
      .run();
  }
}
