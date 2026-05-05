import { fail, redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import type { Actions, PageServerLoad } from './$types';
import { getDb, schema } from '$lib/server/db/client';

export const load: PageServerLoad = async ({ locals }) => {
  if (!locals.user) throw redirect(302, '/signin');
  return { user: locals.user };
};

export const actions: Actions = {
  updateDisplayName: async ({ request, locals }) => {
    if (!locals.user) return fail(401, { error: 'unauthorized' });
    const form = await request.formData();
    const displayName = String(form.get('displayName') ?? '').trim();
    if (displayName.length < 1 || displayName.length > 40) {
      return fail(400, { error: 'display name must be 1-40 chars' });
    }
    const db = getDb();
    db.update(schema.users)
      .set({ displayName })
      .where(eq(schema.users.id, locals.user.id))
      .run();
    return { ok: true };
  }
};
