import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getDb } from '$lib/server/db/client';
import { getMarketData } from '$lib/server/market/factory';
import { CompetitionService } from '$lib/server/competitions/service';
import { parseIsoDate } from '$lib/shared/dates';
import { dollarsToCents } from '$lib/shared/money';

export const load: PageServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(302, '/signin');
	return {};
};

export const actions: Actions = {
	default: async ({ request, locals }) => {
		if (!locals.user)
			return fail(401, {
				error: 'unauthorized',
				name: '',
				type: '',
				startDate: '',
				endDate: '',
				startingCash: ''
			});
		const form = await request.formData();
		const name = String(form.get('name') ?? '').trim();
		const type = String(form.get('type') ?? '');
		const startDateIso = String(form.get('startDate') ?? '');
		const endDateIso = String(form.get('endDate') ?? '');
		const startingCashStr = String(form.get('startingCash') ?? '10000');

		const echo = {
			name,
			type,
			startDate: startDateIso,
			endDate: endDateIso,
			startingCash: startingCashStr
		};

		if (name.length < 1 || name.length > 60)
			return fail(400, { ...echo, error: 'name must be 1-60 chars' });
		if (type !== 'live' && type !== 'historical')
			return fail(400, { ...echo, error: 'type required' });
		if (
			!/^\d{4}-\d{2}-\d{2}$/.test(startDateIso) ||
			!/^\d{4}-\d{2}-\d{2}$/.test(endDateIso)
		) {
			return fail(400, { ...echo, error: 'dates required' });
		}
		const startUnix = parseIsoDate(startDateIso);
		const endUnix = parseIsoDate(endDateIso);
		if (startUnix >= endUnix) return fail(400, { ...echo, error: 'start must be before end' });

		let startingCashCents: number;
		try {
			startingCashCents = dollarsToCents(Number.parseFloat(startingCashStr));
		} catch {
			return fail(400, { ...echo, error: 'starting cash must be a number' });
		}
		if (startingCashCents <= 0)
			return fail(400, { ...echo, error: 'starting cash must be positive' });

		const db = getDb();
		const market = getMarketData();
		const svc = new CompetitionService(db, market);

		let comp;
		try {
			comp = svc.create({
				hostId: locals.user.id,
				name,
				type: type as 'live' | 'historical',
				startDateUnix: startUnix,
				endDateUnix: endUnix,
				startingCashCents
			});
		} catch (e) {
			const msg = e instanceof Error ? e.message : 'failed';
			return fail(400, { ...echo, error: msg });
		}
		throw redirect(303, `/competitions/${comp.id}`);
	}
};
