import { fail, redirect, error } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';
import { computeLeaderboard } from '$lib/server/competitions/leaderboard';
import { isValidSymbol, normalizeSymbol } from '$lib/shared/symbols';

export const load: PageServerLoad = async ({ params, locals }) => {
  if (!locals.user) throw redirect(302, '/signin');
  const db = getDb();
  const market = getMarketData();
  const svc = new CompetitionService(db, market);
  svc.tickStatuses();

  const dashboard = svc.getDashboard(params.id, locals.user.id);
  if (!dashboard) throw error(404, 'competition not found');
  if (!dashboard.isMember && !dashboard.isHost) throw error(403, 'not a member of this competition');

  const leaderboard = await computeLeaderboard(db, market, params.id);

  return {
    dashboard,
    leaderboard
  };
};

export const actions: Actions = {
  trade: async ({ request, params, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const form = await request.formData();
    const mode = String(form.get('mode') ?? '');
    const rawSymbol = String(form.get('symbol') ?? '').trim();
    const sharesStr = String(form.get('shares') ?? '').trim();

    if (mode !== 'buy' && mode !== 'sell') return fail(400, { tradeError: 'invalid mode' });
    const symbol = normalizeSymbol(rawSymbol);
    if (!isValidSymbol(symbol)) return fail(400, { tradeError: 'invalid symbol' });
    const shares = Number.parseInt(sharesStr, 10);
    if (!Number.isFinite(shares) || shares <= 0) return fail(400, { tradeError: 'shares must be positive' });

    const db = getDb();
    const market = getMarketData();
    const svc = new CompetitionService(db, market);
    const comp = svc.findById(params.id);
    if (!comp) return fail(404, { tradeError: 'competition not found' });

    let priceCents: number | undefined;
    if (comp.type === 'live') {
      const q = await market.getLiveQuote(symbol);
      if (!q) return fail(400, { tradeError: `no quote for ${symbol}` });
      priceCents = q.priceCents;
    }
    // historical: tradeInComp pulls from market.getCloseAt internally

    try {
      await svc.tradeInComp({
        competitionId: params.id,
        userId: locals.user.id,
        symbol,
        shares: mode === 'buy' ? shares : -shares,
        priceCents
      });
      return { tradeOk: `${mode === 'buy' ? 'bought' : 'sold'} ${shares} ${symbol}` };
    } catch (e) {
      return fail(400, { tradeError: e instanceof Error ? e.message : 'trade failed' });
    }
  },

  resolve: async ({ params, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const db = getDb();
    const market = getMarketData();
    const svc = new CompetitionService(db, market);
    const comp = svc.findById(params.id);
    if (!comp) return fail(404, { error: 'not found' });
    if (comp.hostId !== locals.user.id) return fail(403, { error: 'host only' });
    try {
      svc.resolveHistorical(params.id);
      return { resolveOk: true };
    } catch (e) {
      return fail(400, { error: e instanceof Error ? e.message : 'failed' });
    }
  },

  toggleShare: async ({ request, params, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const form = await request.formData();
    const value = form.get('value') === '1';
    const db = getDb();
    const market = getMarketData();
    const svc = new CompetitionService(db, market);
    const comp = svc.findById(params.id);
    if (!comp) return fail(404, { error: 'not found' });
    if (comp.hostId !== locals.user.id) return fail(403, { error: 'host only' });
    svc.setShareResults(params.id, value);
    return { shareToggled: value };
  }
};
