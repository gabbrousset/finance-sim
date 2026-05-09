import { redirect } from '@sveltejs/kit';
import { getDb } from '$lib/server/db/client';
import { editionNoForUser } from '$lib/server/user/edition';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals }) => {
  if (!locals.user) throw redirect(302, '/signin');
  const editionNo = editionNoForUser(getDb(), locals.user.id);
  return { user: locals.user, editionNo };
};
