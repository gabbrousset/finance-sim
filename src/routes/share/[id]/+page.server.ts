import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';
import { computeLeaderboard } from '$lib/server/competitions/leaderboard';

export const load: PageServerLoad = async ({ params, url }) => {
  const code = url.searchParams.get('code');
  if (!code) throw error(404, 'not found');

  const db = getDb();
  const market = getMarketData();
  const svc = new CompetitionService(db, market);

  const comp = svc.findById(params.id);
  if (!comp) throw error(404, 'not found');
  if (comp.inviteCode !== code) throw error(404, 'not found');
  if (comp.status !== 'finished') throw error(404, 'not found');
  if (comp.shareResults !== 1) throw error(404, 'not found');

  const leaderboard = await computeLeaderboard(db, market, params.id);

  return {
    competition: {
      name: comp.name,
      type: comp.type,
      startDate: comp.startDate,
      endDate: comp.endDate,
      startingCashCents: comp.startingCashCents,
      finishedAt: comp.finishedAt
    },
    leaderboard
  };
};
