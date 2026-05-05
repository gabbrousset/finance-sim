import { redirect } from '@sveltejs/kit';
import { eq, inArray } from 'drizzle-orm';
import type { PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(302, '/signin');
	const db = getDb();
	const market = getMarketData();
	const svc = new CompetitionService(db, market);

	const userId = locals.user.id;

	const memberRows = db
		.select({ competitionId: schema.competitionMembers.competitionId })
		.from(schema.competitionMembers)
		.where(eq(schema.competitionMembers.userId, userId))
		.all();
	const compIds = memberRows.map((r) => r.competitionId);

	if (compIds.length === 0) return { comps: [] };

	const comps = db
		.select()
		.from(schema.competitions)
		.where(inArray(schema.competitions.id, compIds))
		.all();

	const statusOrder: Record<string, number> = { open: 0, running: 1, finished: 2 };
	comps.sort((a, b) => {
		if (statusOrder[a.status] !== statusOrder[b.status]) {
			return (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99);
		}
		return b.startDate - a.startDate;
	});

	return {
		comps: comps.map((c) => ({
			id: c.id,
			name: c.name,
			type: c.type,
			status: c.status,
			inviteCode: c.inviteCode,
			isHost: c.hostId === userId,
			startDate: c.startDate,
			endDate: c.endDate,
			startingCashCents: c.startingCashCents
		}))
	};
};
