import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { getDb } from '$lib/server/db/client';
import { revokeSession } from '$lib/server/auth/sessions';

export const POST: RequestHandler = async ({ cookies }) => {
  const session = cookies.get('session');
  if (session) {
    const db = getDb();
    await revokeSession(db, session);
  }
  cookies.delete('session', { path: '/' });
  cookies.delete('force_passkey_setup', { path: '/' });
  throw redirect(303, '/');
};
