import type { RequestHandler } from './$types';
import { json, error } from '@sveltejs/kit';
import { getDb } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { computeLeaderboard } from '$lib/server/competitions/leaderboard';
import { CompetitionService } from '$lib/server/competitions/service';

export const GET: RequestHandler = async ({ params, locals }) => {
  if (!locals.user) throw error(401, 'unauthorized');
  const db = getDb();
  const market = getMarketData();
  const svc = new CompetitionService(db, market);
  svc.tickStatuses();
  const comp = svc.findById(params.id);
  if (!comp) throw error(404, 'not found');
  // Membership check: only members + host can see leaderboard.
  // (Public share endpoint will be a separate route, Phase 3.6.)
  const dashboard = svc.getDashboard(params.id, locals.user.id);
  if (!dashboard?.isMember && !dashboard?.isHost) throw error(403, 'forbidden');
  const rows = await computeLeaderboard(db, market, params.id);
  return json({
    rows,
    status: comp.status,
    fetchedAt: Math.floor(Date.now() / 1000)
  });
};
