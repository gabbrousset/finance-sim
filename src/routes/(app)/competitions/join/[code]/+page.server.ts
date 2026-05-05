import { fail, redirect, error } from '@sveltejs/kit';
import { eq, and } from 'drizzle-orm';
import type { Actions, PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';

export const load: PageServerLoad = async ({ params, locals }) => {
	if (!locals.user) throw redirect(302, `/signin?next=/competitions/join/${params.code}`);
	const db = getDb();
	const market = getMarketData();
	const svc = new CompetitionService(db, market);
	svc.tickStatuses();

	const comp = svc.findByInviteCode(params.code);
	if (!comp) throw error(404, 'invite code not recognized');

	// If already a member, just redirect to the dashboard.
	const member = db
		.select()
		.from(schema.competitionMembers)
		.where(
			and(
				eq(schema.competitionMembers.competitionId, comp.id),
				eq(schema.competitionMembers.userId, locals.user.id)
			)
		)
		.get();
	if (member) throw redirect(303, `/competitions/${comp.id}`);

	return {
		competition: {
			id: comp.id,
			name: comp.name,
			type: comp.type,
			status: comp.status,
			startDate: comp.startDate,
			endDate: comp.endDate,
			startingCashCents: comp.startingCashCents,
			hostId: comp.hostId
		},
		canJoin: comp.status === 'open',
		hostDisplayName:
			db
				.select({ displayName: schema.users.displayName })
				.from(schema.users)
				.where(eq(schema.users.id, comp.hostId))
				.get()?.displayName ?? 'unknown'
	};
};

export const actions: Actions = {
	default: async ({ params, locals }) => {
		if (!locals.user) return fail(401, { error: 'unauthorized' });
		const db = getDb();
		const market = getMarketData();
		const svc = new CompetitionService(db, market);
		const comp = svc.findByInviteCode(params.code);
		if (!comp) return fail(404, { error: 'invite code not recognized' });
		try {
			svc.join(comp.id, locals.user.id);
		} catch (e) {
			return fail(400, { error: e instanceof Error ? e.message : 'join failed' });
		}
		throw redirect(303, `/competitions/${comp.id}`);
	}
};
